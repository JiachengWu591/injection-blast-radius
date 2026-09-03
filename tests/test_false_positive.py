"""The estimand, tested. This script produces a number that goes in the README.

The measurement itself needs an API key, but the part that can be wrong without
anything looking wrong is the arithmetic between the verdicts and the headline.
An off-by-one in the majority rule, or a `>=` where a `>` belongs, silently
changes the published rate and no assertion elsewhere would notice.

The one that matters most: an issue whose every call failed must be excluded
from the denominator, not counted as having passed. Counting it as a pass would
let a bad afternoon on the provider's side improve the reported false-positive
rate — the same class of mistake as counting a failed audit as a detection, one
level up.

Run standalone:
    python tests/test_false_positive.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from false_positive_rate import IssueVerdicts, Measurement, render  # noqa: E402


def _issue(
    issue_id: str,
    verdicts: tuple[str, ...],
    *,
    stratum: str = "plain",
    errors: int = 0,
) -> IssueVerdicts:
    return IssueVerdicts(
        issue_id=issue_id,
        stratum=stratum,
        why_benign="an ordinary report, for the purposes of this test",
        verdicts=verdicts,
        errors=errors,
    )


def test_the_majority_rule_needs_more_than_half() -> None:
    """Two of three is blocked; one of three is not; and with an even number of
    calls a tie is NOT a majority, because a coin flip is not a decision."""
    assert _issue("a", ("high_risk", "high_risk", "safe")).blocked_majority
    assert not _issue("b", ("high_risk", "safe", "safe")).blocked_majority
    assert _issue("c", ("high_risk",)).blocked_majority
    assert not _issue("d", ("safe",)).blocked_majority
    assert not _issue("e", ("high_risk", "safe")).blocked_majority
    assert _issue("f", ("high_risk", "high_risk")).blocked_majority


def test_suspicious_is_not_blocked() -> None:
    """`high_risk` short-circuits the pipeline; `suspicious` passes through.

    Adding them together would report a system that refuses issues it actually
    forwards, and the two costs are nowhere near equal.
    """
    issue = _issue("a", ("suspicious", "suspicious", "safe"))
    assert not issue.blocked_majority
    assert not issue.blocked_any
    assert issue.flagged_any


def test_an_unmeasurable_issue_is_excluded_not_counted_as_passing() -> None:
    """The load-bearing one."""
    result = Measurement(
        issues=[
            _issue("ok-1", ("safe", "safe", "safe")),
            _issue("ok-2", ("high_risk", "high_risk", "safe")),
            _issue("all-calls-failed", (), errors=3),
        ],
        samples_requested=3,
    )

    assert [i.issue_id for i in result.unmeasured] == ["all-calls-failed"]
    hits, n, _ = result.rate("blocked_majority")
    assert (hits, n) == (1, 2), (
        f"expected 1/2 over the measured issues, got {hits}/{n}. An issue that "
        "could not be measured must not sit in the denominator as a pass."
    )


def test_the_per_call_rate_pools_only_measured_calls() -> None:
    result = Measurement(
        issues=[
            _issue("a", ("high_risk", "safe", "safe")),
            _issue("b", ("safe", "safe")),
            _issue("c", (), errors=3),
        ],
        samples_requested=3,
    )
    hits, trials, _ = result.per_call()
    assert (hits, trials) == (1, 5)


def test_a_zero_result_reports_an_interval_not_certainty() -> None:
    """0/165 is not "no false positives"; it is a rate with an upper bound.

    This is the assertion that keeps the report from claiming what a null
    result cannot support — the same distinction the project makes everywhere
    else between "we did not observe X" and "X does not happen".
    """
    result = Measurement(
        issues=[_issue(f"i-{n}", ("safe", "safe", "safe")) for n in range(50)],
        samples_requested=3,
    )
    hits, n, (lo, hi) = result.rate("blocked_majority")
    assert (hits, n) == (0, 50)
    assert lo == 0.0
    assert hi > 0.0, "a zero count must still carry a non-zero upper bound"

    text = render(result, audit_model="test-model")
    assert "the upper bound of the interval above is the claim, not zero" in text


def test_the_report_lists_every_blocked_issue_with_its_reason() -> None:
    """A blocked issue is either a false positive or a corpus error, and the
    only way to tell is to read the issue and the label together."""
    result = Measurement(
        issues=[
            _issue("clean", ("safe", "safe", "safe")),
            _issue(
                "refused",
                ("high_risk", "high_risk", "safe"),
                stratum="quotes_secret_shaped",
            ),
        ],
        samples_requested=3,
    )
    text = render(result, audit_model="test-model")
    assert "refused" in text
    assert "an ordinary report, for the purposes of this test" in text
    assert "corpus error" in text, (
        "the report must say that a block can mean the label was wrong, not "
        "only that the audit was"
    )


def test_the_report_names_the_clustering_problem() -> None:
    """The per-call rate must never be presented as the headline."""
    result = Measurement(
        issues=[_issue(f"i-{n}", ("safe", "safe", "safe")) for n in range(5)],
        samples_requested=3,
    )
    text = render(result, audit_model="test-model")
    assert "cluster" in text
    assert "context only" in text
    # And the derived call count must be real, not a hardcoded 495.
    assert "as 15 independent trials" in text


def main() -> int:
    tests = [
        (name, fn)
        for name, fn in sorted(globals().items())
        if name.startswith("test_") and callable(fn)
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
