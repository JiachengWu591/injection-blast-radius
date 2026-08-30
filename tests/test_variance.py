"""Assertions for the audit-variance measurement.

The statistics are the point of this module, so they get checked against
published values rather than against themselves. The reporting is checked for a
specific failure mode: a run in which nothing adverse was observed must not
read as a run in which nothing adverse can happen.

Run standalone:
    python tests/test_variance.py
    python tests/test_variance.py --offline
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit_variance import render_markdown, render_terminal  # noqa: E402
from ibr.bootstrap import ensure_sandbox  # noqa: E402
from ibr.variance import (  # noqa: E402
    PASSES_THROUGH,
    CorpusVariance,
    SubjectVariance,
    wilson_interval,
)

ensure_sandbox()


# =========================================================================
# Statistics.
# =========================================================================


def test_wilson_matches_published_values() -> None:
    """Spot values from the standard Wilson score interval, to 3dp."""
    expected = {
        (0, 20): (0.000, 0.161),
        (20, 20): (0.839, 1.000),
        (10, 20): (0.299, 0.701),
        (1, 20): (0.009, 0.236),
        (5, 100): (0.022, 0.112),
        (0, 140): (0.000, 0.027),
    }
    for (successes, trials), (want_lo, want_hi) in expected.items():
        lo, hi = wilson_interval(successes, trials)
        assert abs(lo - want_lo) < 0.001, f"{successes}/{trials} lo={lo}"
        assert abs(hi - want_hi) < 0.001, f"{successes}/{trials} hi={hi}"


def test_wilson_never_leaves_the_probability_scale() -> None:
    """The reason for choosing Wilson over the normal approximation."""
    for trials in (1, 2, 5, 20, 200):
        for successes in range(trials + 1):
            lo, hi = wilson_interval(successes, trials)
            assert 0.0 <= lo <= hi <= 1.0, f"{successes}/{trials} -> [{lo}, {hi}]"


def test_wilson_does_not_claim_certainty_from_zero_observations() -> None:
    """0/n must have a non-trivial upper bound, tightening as n grows."""
    _, hi_small = wilson_interval(0, 5)
    _, hi_medium = wilson_interval(0, 25)
    _, hi_large = wilson_interval(0, 500)
    assert hi_small > hi_medium > hi_large > 0.0
    assert hi_medium > 0.10, "25 clean samples should not imply a rate under 10%"


def test_wilson_handles_no_trials() -> None:
    assert wilson_interval(0, 0) == (0.0, 1.0)


# =========================================================================
# Bookkeeping.
# =========================================================================


def _subject(verdicts: list[str], *, malicious: bool = True) -> SubjectVariance:
    return SubjectVariance(
        key="k", name="Subject", is_malicious=malicious, verdicts=list(verdicts)
    )


def test_pass_through_matches_the_specs_short_circuit_rule() -> None:
    """Only high_risk short-circuits (PROJECT_SPEC.md §3.1)."""
    assert set(PASSES_THROUGH) == {"safe", "suspicious"}
    subject = _subject(["high_risk"] * 8 + ["suspicious", "safe"])
    assert subject.trials == 10
    assert subject.passed_through == 2
    assert subject.high_risk == 8


def test_adverse_outcome_flips_with_the_kind_of_input() -> None:
    """For an attack, passing through is bad; for benign input, blocking is."""
    attack = _subject(["high_risk"] * 9 + ["suspicious"], malicious=True)
    assert attack.adverse == 1
    assert abs(attack.adverse_rate - 0.1) < 1e-9

    benign = _subject(["safe"] * 9 + ["high_risk"], malicious=False)
    assert benign.adverse == 1, "a blocked benign report is the adverse outcome"
    assert benign.passed_through == 9


def test_spread_and_unanimity() -> None:
    unanimous = _subject(["high_risk"] * 5)
    assert unanimous.unanimous is True
    assert unanimous.spread == "high_risk×5"

    mixed = _subject(["high_risk"] * 4 + ["suspicious"])
    assert mixed.unanimous is False
    assert "suspicious×1" in mixed.spread
    assert "high_risk×4" in mixed.spread


def test_pooling_and_disagreement_detection() -> None:
    corpus = CorpusVariance(
        subjects=[
            _subject(["high_risk"] * 25),
            _subject(["high_risk"] * 24 + ["suspicious"]),
            _subject(["safe"] * 25, malicious=False),
        ],
        samples_requested=25,
    )
    assert len(corpus.malicious) == 2
    assert len(corpus.benign) == 1

    adverse, trials, (lo, hi) = corpus.pooled(corpus.malicious)
    assert (adverse, trials) == (1, 50)
    assert lo < 0.02 < hi

    disagreed = corpus.disagreed_with_itself
    assert len(disagreed) == 1
    assert disagreed[0].spread.count("×") == 2


def test_a_single_sample_is_not_treated_as_disagreement() -> None:
    corpus = CorpusVariance(subjects=[_subject(["high_risk"])], samples_requested=1)
    assert corpus.disagreed_with_itself == []


# =========================================================================
# Reporting honesty.
# =========================================================================


def _corpus(*, with_disagreement: bool) -> CorpusVariance:
    attack = SubjectVariance(
        key="fake_convention",
        name="Fabricated repository convention",
        is_malicious=True,
        verdicts=(
            ["high_risk"] * 24 + ["suspicious"]
            if with_disagreement
            else ["high_risk"] * 25
        ),
    )
    benign = SubjectVariance(
        key="benign_control",
        name="Benign bug report (control)",
        is_malicious=False,
        verdicts=["safe"] * 25,
    )
    return CorpusVariance(subjects=[attack, benign], samples_requested=25)


def test_report_never_reads_a_clean_run_as_a_guarantee() -> None:
    """The failure mode this measurement exists to avoid."""
    markdown = render_markdown(_corpus(with_disagreement=False))
    assert "not evidence of determinism" in markdown
    assert "95% CI" in markdown

    terminal = render_terminal(_corpus(with_disagreement=False))
    assert "consistent with a real" in terminal
    assert "absence of an observation" in terminal


def test_report_surfaces_disagreement_when_it_happens() -> None:
    markdown = render_markdown(_corpus(with_disagreement=True))
    assert "contradict itself" in markdown.lower()
    assert "suspicious×1" in markdown
    assert "cannot be reasoned about as a guarantee" in markdown


def test_report_always_includes_the_benign_control() -> None:
    """Measuring only misses would let the audit look arbitrarily good."""
    markdown = render_markdown(_corpus(with_disagreement=True))
    assert "benign control" in markdown.lower()
    assert "false positive" in markdown.lower()
    assert "rates everything `high_risk` has a perfect miss rate" in markdown


def test_report_separates_measured_from_proven() -> None:
    """The central distinction: a rate with error bars is not a proof."""
    markdown = render_markdown(_corpus(with_disagreement=True))
    assert "Nothing above measures the structural boundary" in markdown
    assert "without making a single API call" in markdown
    assert "two materials" in markdown


def test_terminal_table_reports_intervals_for_every_subject() -> None:
    terminal = render_terminal(_corpus(with_disagreement=True))
    assert terminal.count("[") >= 2, "every row needs an interval"
    for subject in _corpus(with_disagreement=True).subjects:
        assert subject.name in terminal


# =========================================================================
# Live.
# =========================================================================


def live_test_sampling_the_audit_produces_valid_verdicts() -> None:
    from ibr.issues import load_issue
    from ibr.schemas import RISK_LEVELS
    from ibr.variance import measure_subject

    subject = measure_subject(
        "benign_control",
        "Benign bug report (control)",
        load_issue("benign"),
        is_malicious=False,
        samples=3,
        concurrency=3,
    )
    assert subject.trials + subject.errors == 3
    assert subject.trials > 0, "every audit call failed"
    for verdict in subject.verdicts:
        assert verdict in RISK_LEVELS
    lo, hi = subject.interval
    assert 0.0 <= lo <= hi <= 1.0


# =========================================================================


def main() -> int:
    offline = "--offline" in sys.argv
    prefixes = ("test_",) if offline else ("test_", "live_test_")
    tests = [
        (name, fn)
        for name, fn in sorted(globals().items())
        if name.startswith(prefixes) and callable(fn)
    ]

    failures = 0
    for name, fn in tests:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - the runner reports, never hides
            failures += 1
            print(f"FAIL  {name}\n        {type(exc).__name__}: {exc}")
        else:
            print(f"pass  {name}")

    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
