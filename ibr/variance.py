"""Measuring the probabilistic layer instead of asserting things about it.

The project claims the security audit is probabilistic. So far that claim has
rested on having watched one payload draw `high_risk` three times and
`suspicious` once — enough to know the verdict moves, not enough to say how
much. This module samples the audit repeatedly on fixed inputs and reports
rates with confidence intervals, which is the difference between "it varies"
and "it lets 1 in 8 through, 95% CI [3%, 32%]".

Two rates matter, and only measuring one of them would be misleading:

  * **Pass-through rate** on malicious input — how often a payload draws a
    verdict other than `high_risk`. Per PROJECT_SPEC.md §3.1, `safe` and
    `suspicious` both continue to the Reader, so this is the false-negative
    rate in the only sense that changes behaviour.
  * **False-positive rate** on benign input — how often an ordinary bug report
    draws `high_risk` and gets dropped. A screening layer tuned until it never
    misses an attack, at the cost of blocking real issues, has not been made
    good; it has been made useless in a different direction.

Intervals are Wilson score intervals rather than the normal approximation.
That matters here specifically: the interesting results sit at or near 0 and 1,
where the normal approximation produces intervals extending past the ends of
the probability scale and understates uncertainty at small n.
"""

from __future__ import annotations

import math
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import openai

from .config import AUDIT_MODEL
from .issues import Issue
from .pipeline import audit_only
from .schemas import RISK_LEVELS

# Verdicts that let the content continue to the Reader (PROJECT_SPEC.md §3.1).
PASSES_THROUGH = ("safe", "suspicious")

DEFAULT_SAMPLES = 20
DEFAULT_CONCURRENCY = 5


def wilson_interval(
    successes: int, trials: int, *, z: float = 1.959963985
) -> tuple[float, float]:
    """95% Wilson score interval for a binomial proportion.

    Chosen over the normal approximation because the results that matter here
    are extreme: for 0 successes in 20 trials the normal interval is [0, 0],
    which would assert certainty from an absence of observations. Wilson gives
    [0, 0.161] — an honest statement that 20 clean samples are consistent with
    a real rate as high as 16%.
    """
    if trials <= 0:
        return (0.0, 1.0)
    p = successes / trials
    z2 = z * z
    denominator = 1.0 + z2 / trials
    centre = (p + z2 / (2 * trials)) / denominator
    margin = (z / denominator) * math.sqrt(
        p * (1.0 - p) / trials + z2 / (4.0 * trials * trials)
    )
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def newcombe_difference_interval(
    successes_a: int,
    trials_a: int,
    successes_b: int,
    trials_b: int,
    *,
    z: float = 1.959963985,
) -> tuple[float, float]:
    """95% interval for (rate_a - rate_b), Newcombe's square-and-add method.

    The companion to `wilson_interval` for the question "did switching models
    change anything". Built from the two Wilson intervals rather than a normal
    approximation to the difference, for the same reason: the rates being
    compared here sit near zero, where the normal interval misbehaves.

    An interval spanning 0 means the data cannot distinguish the two rates. At
    the sample sizes this project can afford that is the likely answer, and
    saying so is the point — "the newer model looks better" is not a finding
    when a handful of samples couldn't have shown otherwise.
    """
    if trials_a <= 0 or trials_b <= 0:
        return (-1.0, 1.0)

    p_a = successes_a / trials_a
    p_b = successes_b / trials_b
    lo_a, hi_a = wilson_interval(successes_a, trials_a, z=z)
    lo_b, hi_b = wilson_interval(successes_b, trials_b, z=z)

    difference = p_a - p_b
    lower = difference - math.sqrt((p_a - lo_a) ** 2 + (hi_b - p_b) ** 2)
    upper = difference + math.sqrt((hi_a - p_a) ** 2 + (p_b - lo_b) ** 2)
    return (max(-1.0, lower), min(1.0, upper))


def required_samples_per_group(
    rate_a: float,
    rate_b: float,
    *,
    z_alpha: float = 1.959963985,  # two-sided alpha = 0.05
    z_power: float = 0.8416212336,  # power = 0.80
) -> int | None:
    """Roughly how many samples per model it would take to tell two rates apart.

    Exists to put a number on why "the newer model seems better" is usually not
    a finding. Detecting a halving of a ~1% rate needs samples in the
    thousands per model; a few hundred cannot resolve it, so a clean run on a
    newer model is compatible with no improvement at all.

    Normal-approximation sample size, which is crude at rates this small —
    treat the result as an order of magnitude, not a target. Returns None when
    the two rates are equal, since no sample size distinguishes them.
    """
    delta = abs(rate_a - rate_b)
    if delta < 1e-12:
        return None
    variance = rate_a * (1.0 - rate_a) + rate_b * (1.0 - rate_b)
    if variance <= 0.0:
        return None
    return math.ceil(((z_alpha + z_power) ** 2) * variance / (delta * delta))


@dataclass
class SubjectVariance:
    """Sampled audit behaviour for one fixed input."""

    key: str
    name: str
    is_malicious: bool
    verdicts: list[str] = field(default_factory=list)
    errors: int = 0

    @property
    def trials(self) -> int:
        return len(self.verdicts)

    @property
    def counts(self) -> dict[str, int]:
        tally = Counter(self.verdicts)
        return {level: tally.get(level, 0) for level in RISK_LEVELS}

    @property
    def high_risk(self) -> int:
        return self.counts["high_risk"]

    @property
    def passed_through(self) -> int:
        """Samples where the content would have reached the Reader."""
        return sum(self.counts[level] for level in PASSES_THROUGH)

    @property
    def adverse(self) -> int:
        """Outcomes that count against the audit for this subject.

        For malicious input that's passing through; for benign input it's
        being blocked. Keeping the sign consistent lets both be read from one
        column without a reader having to invert anything mentally.
        """
        return self.passed_through if self.is_malicious else self.high_risk

    @property
    def adverse_rate(self) -> float:
        return self.adverse / self.trials if self.trials else 0.0

    @property
    def interval(self) -> tuple[float, float]:
        return wilson_interval(self.adverse, self.trials)

    @property
    def unanimous(self) -> bool:
        return len(set(self.verdicts)) <= 1

    @property
    def spread(self) -> str:
        return " ".join(
            f"{level}×{n}" for level, n in self.counts.items() if n
        )


@dataclass
class CorpusVariance:
    subjects: list[SubjectVariance] = field(default_factory=list)
    samples_requested: int = 0

    @property
    def malicious(self) -> list[SubjectVariance]:
        return [s for s in self.subjects if s.is_malicious]

    @property
    def benign(self) -> list[SubjectVariance]:
        return [s for s in self.subjects if not s.is_malicious]

    def pooled(self, subjects: list[SubjectVariance]) -> tuple[int, int, tuple[float, float]]:
        """Adverse outcomes, trials, and the interval across several subjects.

        Pooling assumes the subjects share a rate, which they plainly don't —
        different payloads are differently persuasive. It's reported as a
        headline because a single number is what people quote, and the
        per-subject rows immediately below it are what qualify it.
        """
        adverse = sum(s.adverse for s in subjects)
        trials = sum(s.trials for s in subjects)
        return adverse, trials, wilson_interval(adverse, trials)

    @property
    def disagreed_with_itself(self) -> list[SubjectVariance]:
        return [s for s in self.subjects if s.trials > 1 and not s.unanimous]


def measure_subject(
    key: str,
    name: str,
    issue: Issue,
    *,
    is_malicious: bool,
    samples: int = DEFAULT_SAMPLES,
    concurrency: int = DEFAULT_CONCURRENCY,
    client: openai.OpenAI | None = None,
    audit_model: str = AUDIT_MODEL,
) -> SubjectVariance:
    """Call the audit `samples` times on one fixed input.

    Concurrent because the calls are independent and sequential sampling makes
    a 20-sample run take long enough that people reach for a smaller n — which
    is the wrong thing to economise on when the whole point is the interval
    width.
    """
    result = SubjectVariance(key=key, name=name, is_malicious=is_malicious)

    def one(_index: int) -> str | None:
        try:
            return audit_only(
                issue, client=client, audit_model=audit_model
            ).risk_level
        except openai.APIError:
            return None

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        for verdict in pool.map(one, range(samples)):
            if verdict is None:
                result.errors += 1
            else:
                result.verdicts.append(verdict)

    return result
