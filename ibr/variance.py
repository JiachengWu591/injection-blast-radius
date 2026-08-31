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

import json
import math
import os
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from collections.abc import Callable
from pathlib import Path
from threading import Lock

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
    treat the result as an order of magnitude, not a target. Returns None only
    when the two rates are equal, since no sample size distinguishes those.
    """
    delta = abs(rate_a - rate_b)
    if delta < 1e-12:
        return None

    variance = rate_a * (1.0 - rate_a) + rate_b * (1.0 - rate_b)
    if variance <= 0.0:
        # Zero variance with a non-zero difference means both rates sit exactly
        # at 0 or 1 — the *most* separable pair there is. Returning None here
        # would have the report say "no sample size would separate them" about
        # 0% versus 100%, which is precisely backwards. One observation per
        # group settles it, so report that rather than an impossibility.
        return 1

    return math.ceil(((z_alpha + z_power) ** 2) * variance / (delta * delta))


@dataclass
class SubjectVariance:
    """Sampled audit behaviour for one fixed input."""

    key: str
    name: str
    is_malicious: bool
    verdicts: list[str] = field(default_factory=list)
    errors: int = 0
    reused: int = 0
    """How many verdicts came from the sample store rather than fresh calls."""

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


class SampleStore:
    """Append-only JSONL record of every audit sample ever taken.

    Narrowing an interval means multiplying n, and at n=200 across a dozen
    subjects a run is thousands of calls and tens of minutes. Losing that to a
    dropped connection halfway through is not an acceptable failure mode, and
    neither is being unable to add samples later without starting over. Every
    verdict is written as it arrives, so a run is resumable and n accumulates
    across sessions.

    Verdicts are keyed by (model, subject) and nothing else. That is a real
    assumption worth stating: it treats samples taken on different days as
    exchangeable, which they are not if the provider changes the model behind a
    stable id. The alternative — discarding history on any doubt — would make
    large n unreachable, so the trade is deliberate and the report notes it.

    **Writes are sharded per process.** An earlier version had every process
    append to one file, which measured as losing 32% of records and tearing
    lines in half under four concurrent writers ('sk"}', 'ous"}'). Worse, the
    fail-closed loader then refused to open the damaged file, so one accidental
    double-run permanently bricked a store holding thousands of paid-for
    samples. `open(..., "a")` is not atomic across processes.

    Sharding removes the shared resource instead of guarding it: each process
    writes only `<base>.<pid>.jsonl` and reads every shard. No locks, no
    platform-specific code, and no interleaving to get wrong. Two concurrent
    runs now merely over-collect — each tops up to n independently — which is
    wasteful and self-correcting rather than destructive.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.shard_path = path.with_suffix(f".{os.getpid()}{path.suffix}")
        self._lock = Lock()
        self._samples: dict[tuple[str, str], list[str]] = {}
        self.partial_lines_skipped = 0
        self._load()

    def _shards(self) -> list[Path]:
        """Every file holding samples: this process's, others', and the
        pre-sharding single file if one is left over."""
        parent = self.path.parent
        if not parent.is_dir():
            return []
        stem, suffix = self.path.stem, self.path.suffix
        found = sorted(parent.glob(f"{stem}.*{suffix}"))
        if self.path.exists():
            found.insert(0, self.path)
        return found

    def _load(self) -> None:
        for shard in self._shards():
            text = shard.read_text(encoding="utf-8")
            lines = text.splitlines()
            # `record` writes one complete `json + "\n"` per call, so a file
            # ending in a newline contains only whole records. If it doesn't,
            # the final line is a write another process is still in the middle
            # of. That makes the distinction exact rather than a guess: a
            # malformed line is tolerated only when it is both last *and*
            # unterminated, and stays fatal everywhere else.
            may_be_mid_write = bool(text) and not text.endswith("\n")
            for number, raw in enumerate(lines, 1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    key = (record["model"], record["subject"])
                    verdict = record["verdict"]
                except (json.JSONDecodeError, KeyError) as exc:
                    if may_be_mid_write and number == len(lines):
                        self.partial_lines_skipped += 1
                        continue
                    raise ValueError(
                        f"{shard}: line {number} is not a valid sample: {exc}"
                    ) from exc
                if verdict not in RISK_LEVELS:
                    raise ValueError(
                        f"{shard}: line {number} has unknown verdict {verdict!r}"
                    )
                self._samples.setdefault(key, []).append(verdict)

    def existing(self, model: str, subject: str) -> list[str]:
        return list(self._samples.get((model, subject), []))

    def record(self, model: str, subject: str, verdict: str) -> None:
        with self._lock:
            self._samples.setdefault((model, subject), []).append(verdict)
            self.shard_path.parent.mkdir(parents=True, exist_ok=True)
            with self.shard_path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(
                    json.dumps(
                        {"model": model, "subject": subject, "verdict": verdict},
                        ensure_ascii=False,
                    )
                    + "\n"
                )

    def total(self) -> int:
        return sum(len(v) for v in self._samples.values())


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
    store: SampleStore | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> SubjectVariance:
    """Sample the audit on one fixed input until it has `samples` verdicts.

    Concurrent because the calls are independent and sequential sampling makes
    a large run slow enough that people reach for a smaller n — which is the
    wrong thing to economise on when interval width is the whole point.

    With a `store`, already-recorded verdicts count toward the target and only
    the shortfall is requested.
    """
    result = SubjectVariance(key=key, name=name, is_malicious=is_malicious)

    if store is not None:
        result.verdicts.extend(store.existing(audit_model, key)[:samples])
    result.reused = len(result.verdicts)

    shortfall = max(0, samples - len(result.verdicts))
    if progress:
        progress(result.reused, shortfall)
    if shortfall == 0:
        return result

    def one(_index: int) -> str | None:
        # audit_only never raises — it fails closed to high_risk so the
        # pipeline refuses to act. That default must not be counted here as a
        # detection, or every timeout quietly improves the measured hit rate
        # and the reported miss rate comes out optimistic. `completed` is the
        # only thing that separates "the model said high_risk" from "we could
        # not reach the model".
        verdict = audit_only(issue, client=client, audit_model=audit_model)
        if not verdict.completed:
            return None
        if store is not None:
            store.record(audit_model, key, verdict.risk_level)
        return verdict.risk_level

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        for verdict in pool.map(one, range(shortfall)):
            if verdict is None:
                result.errors += 1
            else:
                result.verdicts.append(verdict)

    return result
