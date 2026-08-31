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

import json
import sys
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from audit_variance import render_markdown, render_terminal  # noqa: E402
from ibr.bootstrap import ensure_sandbox  # noqa: E402
from ibr.variance import (  # noqa: E402
    PASSES_THROUGH,
    CorpusVariance,
    SubjectVariance,
    newcombe_difference_interval,
    required_samples_per_group,
    wilson_interval,
)
from model_comparison import (  # noqa: E402
    Comparison,
    ModelResult,
)
from model_comparison import render_markdown as render_comparison_markdown  # noqa: E402
from model_comparison import render_terminal as render_comparison_terminal  # noqa: E402

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


def test_newcombe_spans_zero_when_rates_match() -> None:
    lo, hi = newcombe_difference_interval(5, 50, 5, 50)
    assert lo < 0.0 < hi
    assert abs(lo + hi) < 1e-9, "equal rates should give a symmetric interval"


def test_newcombe_excludes_zero_for_a_large_real_difference() -> None:
    lo, hi = newcombe_difference_interval(20, 25, 2, 25)
    assert lo > 0.0, f"expected a significant difference, got [{lo}, {hi}]"


def test_newcombe_is_antisymmetric() -> None:
    forward = newcombe_difference_interval(2, 175, 0, 175)
    reverse = newcombe_difference_interval(0, 175, 2, 175)
    assert abs(forward[0] + reverse[1]) < 1e-12
    assert abs(forward[1] + reverse[0]) < 1e-12


def test_newcombe_stays_on_the_difference_scale() -> None:
    for a in range(0, 26, 5):
        for b in range(0, 26, 5):
            lo, hi = newcombe_difference_interval(a, 25, b, 25)
            assert -1.0 <= lo <= hi <= 1.0


def test_newcombe_handles_no_trials() -> None:
    assert newcombe_difference_interval(0, 0, 0, 10) == (-1.0, 1.0)


def test_required_samples_grows_as_the_difference_shrinks() -> None:
    big = required_samples_per_group(0.50, 0.25)
    small = required_samples_per_group(0.011, 0.0055)
    assert big is not None and small is not None
    assert small > big * 10, "detecting a tiny difference must need far more n"
    # Order-of-magnitude sanity: halving a ~1% rate is a thousands-of-samples job.
    assert 1_000 < small < 100_000


def test_required_samples_is_undefined_only_for_equal_rates() -> None:
    assert required_samples_per_group(0.02, 0.02) is None
    assert required_samples_per_group(0.0, 0.0) is None
    assert required_samples_per_group(1.0, 1.0) is None


def test_required_samples_handles_the_maximally_separable_pair() -> None:
    """0% versus 100% is the easiest comparison there is, not the hardest.

    Both rates sitting at the ends of the scale makes the pooled variance zero,
    and a guard that returned None on zero variance therefore reported "no
    sample size would separate them" about the most separable pair possible —
    exactly backwards, in a sentence the report quotes verbatim.
    """
    for a, b in ((0.0, 1.0), (1.0, 0.0)):
        needed = required_samples_per_group(a, b)
        assert needed is not None, f"req({a}, {b}) claimed to be impossible"
        assert needed == 1, f"req({a}, {b}) = {needed}, expected 1"

    # Sanity: the Newcombe interval agrees these are distinguishable.
    lo, hi = newcombe_difference_interval(0, 100, 100, 100)
    assert hi < 0.0, "0/100 vs 100/100 should be significantly different"


def test_required_samples_scales_sensibly_off_the_extremes() -> None:
    assert required_samples_per_group(0.0, 0.5) is not None
    easy = required_samples_per_group(0.5, 0.25)
    hard = required_samples_per_group(0.5, 0.48)
    assert easy is not None and hard is not None
    assert hard > easy * 10


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
# Sample store.
# =========================================================================


def test_sample_store_round_trips_and_accumulates() -> None:
    import tempfile
    from pathlib import Path as _Path

    from ibr.variance import SampleStore

    with tempfile.TemporaryDirectory() as tmp:
        path = _Path(tmp) / "samples.jsonl"
        store = SampleStore(path)
        assert store.total() == 0
        assert store.existing("m", "s") == []

        store.record("m", "s", "high_risk")
        store.record("m", "s", "suspicious")
        store.record("m", "other", "safe")
        store.record("other-model", "s", "high_risk")

        assert store.total() == 4
        assert store.existing("m", "s") == ["high_risk", "suspicious"]
        assert store.existing("m", "other") == ["safe"]

        # A second store over the same file must see everything.
        reopened = SampleStore(path)
        assert reopened.total() == 4
        assert reopened.existing("m", "s") == ["high_risk", "suspicious"]
        # Keys are per (model, subject) — samples must not bleed across models.
        assert reopened.existing("other-model", "s") == ["high_risk"]


def test_sample_store_writes_only_to_its_own_shard() -> None:
    """No two processes share a file, so there is nothing to interleave.

    Measured before this change: four concurrent writers on one file lost 32%
    of records and tore lines in half. The fail-closed loader then refused to
    open the damaged file, so one accidental double-run permanently bricked a
    store holding thousands of paid-for samples. Sharding removes the shared
    resource rather than guarding it.
    """
    import os
    import tempfile
    from pathlib import Path as _Path

    from ibr.variance import SampleStore

    with tempfile.TemporaryDirectory() as tmp:
        base = _Path(tmp) / "audit_samples.jsonl"
        store = SampleStore(base)
        store.record("m", "s", "safe")

        assert str(os.getpid()) in store.shard_path.name
        assert store.shard_path != base
        assert store.shard_path.exists()
        assert not base.exists(), "wrote to the shared base path"


def test_sample_store_reads_every_shard_including_other_processes() -> None:
    import tempfile
    from pathlib import Path as _Path

    from ibr.variance import SampleStore

    with tempfile.TemporaryDirectory() as tmp:
        base = _Path(tmp) / "audit_samples.jsonl"
        # Two shards as if written by other processes, plus a legacy
        # pre-sharding file at the base path.
        for name, verdict in (
            ("audit_samples.111.jsonl", "safe"),
            ("audit_samples.222.jsonl", "suspicious"),
            ("audit_samples.jsonl", "high_risk"),
        ):
            (_Path(tmp) / name).write_text(
                json.dumps({"model": "m", "subject": "s", "verdict": verdict}) + "\n",
                encoding="utf-8",
            )

        store = SampleStore(base)
        assert store.total() == 3, "a shard was not read"
        assert sorted(store.existing("m", "s")) == ["high_risk", "safe", "suspicious"]


def test_sample_store_tolerates_a_shard_being_written_right_now() -> None:
    """A truncated last line means a live writer, not damage.

    `record` writes one complete `json + "\\n"` per call, so a file that ends
    in a newline holds only whole records. Tolerating a malformed final line
    only when the file is *also* unterminated makes the rule exact rather than
    a guess: it stops a concurrent run from crashing the reader, and a corrupt
    line that happens to be last but properly terminated is still fatal.
    """
    import tempfile
    from pathlib import Path as _Path

    from ibr.variance import SampleStore

    with tempfile.TemporaryDirectory() as tmp:
        base = _Path(tmp) / "audit_samples.jsonl"
        good = json.dumps({"model": "m", "subject": "s", "verdict": "safe"})
        (_Path(tmp) / "audit_samples.999.jsonl").write_text(
            good + "\n" + good + "\n" + '{"model": "m", "subj',  # mid-write
            encoding="utf-8",
        )

        store = SampleStore(base)
        assert store.total() == 2
        assert store.partial_lines_skipped == 1

        # Damage that is not at the end is still fatal.
        (_Path(tmp) / "audit_samples.998.jsonl").write_text(
            good + "\ntorn in the middle\n" + good + "\n", encoding="utf-8"
        )
        try:
            SampleStore(base)
        except ValueError as exc:
            assert "line 2" in str(exc)
        else:
            raise AssertionError("mid-file corruption was tolerated")

        # A malformed final line that IS newline-terminated was fully written,
        # so it is damage rather than a live writer.
        (_Path(tmp) / "audit_samples.997.jsonl").write_text(
            good + "\nfully written but garbage\n", encoding="utf-8"
        )
        try:
            SampleStore(base)
        except ValueError:
            pass
        else:
            raise AssertionError(
                "a terminated corrupt final line was mistaken for a live write"
            )


def test_sample_store_rejects_a_corrupt_file() -> None:
    """Fail-closed: silently dropping samples would distort the denominator."""
    import tempfile
    from pathlib import Path as _Path

    from ibr.variance import SampleStore

    with tempfile.TemporaryDirectory() as tmp:
        path = _Path(tmp) / "samples.jsonl"
        path.write_text(
            '{"model": "m", "subject": "s", "verdict": "high_risk"}\n'
            "not json at all\n",
            encoding="utf-8",
        )
        try:
            SampleStore(path)
        except ValueError as exc:
            assert "line 2" in str(exc)
        else:
            raise AssertionError("a corrupt sample line was accepted")


def test_sample_store_rejects_an_unknown_verdict() -> None:
    import tempfile
    from pathlib import Path as _Path

    from ibr.variance import SampleStore

    with tempfile.TemporaryDirectory() as tmp:
        path = _Path(tmp) / "samples.jsonl"
        path.write_text(
            '{"model": "m", "subject": "s", "verdict": "totally_fine"}\n',
            encoding="utf-8",
        )
        try:
            SampleStore(path)
        except ValueError as exc:
            assert "unknown verdict" in str(exc)
        else:
            raise AssertionError("an unknown verdict was accepted")


def test_measure_subject_reuses_stored_samples_without_calling_out() -> None:
    """The resumability guarantee, checked without touching the network.

    If this regressed, a resumed run would silently re-bill every sample it
    already had — the failure would be invisible except on the invoice.
    """
    import tempfile
    from pathlib import Path as _Path

    from ibr.issues import Issue
    from ibr.variance import SampleStore, measure_subject

    with tempfile.TemporaryDirectory() as tmp:
        path = _Path(tmp) / "samples.jsonl"
        store = SampleStore(path)
        for _ in range(5):
            store.record("test-model", "subj", "high_risk")

        issue = Issue(issue_id="x", title="t", author="a", body="b")
        # No client and no network: if it tried to call out, this would raise.
        result = measure_subject(
            "subj",
            "Subject",
            issue,
            is_malicious=True,
            samples=5,
            audit_model="test-model",
            store=store,
        )
        assert result.trials == 5
        assert result.reused == 5
        assert result.errors == 0
        assert result.verdicts == ["high_risk"] * 5


def test_measure_subject_caps_reuse_at_the_requested_n() -> None:
    """Asking for fewer samples than are stored must not inflate n."""
    import tempfile
    from pathlib import Path as _Path

    from ibr.issues import Issue
    from ibr.variance import SampleStore, measure_subject

    with tempfile.TemporaryDirectory() as tmp:
        store = SampleStore(_Path(tmp) / "samples.jsonl")
        for _ in range(10):
            store.record("test-model", "subj", "high_risk")

        result = measure_subject(
            "subj",
            "Subject",
            Issue(issue_id="x", title="t", author="a", body="b"),
            is_malicious=True,
            samples=4,
            audit_model="test-model",
            store=store,
        )
        assert result.trials == 4, "stored samples beyond the target leaked into n"


# =========================================================================
# Failed calls must never count as detections.
# =========================================================================


def test_a_failed_audit_call_is_not_counted_as_a_detection() -> None:
    """The measurement's most dangerous failure mode, pinned.

    `audit_only` fails closed to high_risk so the pipeline refuses to act.
    That is correct for the pipeline and a lie for a measurement: counting a
    timeout as a catch is how a screening layer with a broken connection
    reports a perfect hit rate. This regressed silently once — the except
    clause meant to catch it was unreachable, because audit_only swallows
    APIError itself and never propagates.
    """
    import openai as _openai

    from ibr import pipeline as _pipeline
    from ibr.issues import Issue
    from ibr.variance import measure_subject

    original = _pipeline.call_structured_tool

    def always_fails(**_kwargs):
        raise _openai.APITimeoutError(request=None)

    # A stand-in client, so audit_only skips build_client() and with it the
    # API-key check. Without this the test needs a key to prove it needs no
    # key: it passed locally where .env exists and failed in CI where it
    # doesn't. The object is never touched, because the patched call raises
    # before anything uses it.
    fake_client = cast("Any", object())

    _pipeline.call_structured_tool = always_fails
    try:
        result = measure_subject(
            "subj",
            "Subject",
            Issue(issue_id="x", title="t", author="a", body="b"),
            is_malicious=True,
            samples=5,
            concurrency=1,
            client=fake_client,
        )
    finally:
        _pipeline.call_structured_tool = original

    assert result.errors == 5, "failed calls were not counted as errors"
    assert result.trials == 0, (
        f"failed calls leaked into the sample set as {result.verdicts}"
    )
    # With no usable samples the interval must be maximally uninformative,
    # not a confident zero.
    assert result.interval == (0.0, 1.0)


def test_a_successful_verdict_is_written_to_the_sample_store() -> None:
    """The positive half of the checkpoint contract.

    Only the failure path had a test, which is the wrong half to verify alone:
    the entire n=200 accumulation rests on successful verdicts actually
    reaching disk, and a store that silently wrote nothing would look
    identical to one that worked until the next run re-ran everything.
    """
    import tempfile
    from pathlib import Path as _Path

    from ibr import variance as _variance
    from ibr.issues import Issue
    from ibr.schemas import AuditVerdict
    from ibr.variance import SampleStore, measure_subject

    # Patched on ibr.variance, not ibr.pipeline: variance.py binds audit_only
    # at import time, so replacing it on the defining module has no effect
    # here. The failure-path tests patch call_structured_tool instead, which
    # audit_only looks up dynamically — same reason, opposite direction.
    original = _variance.audit_only
    calls = {"n": 0}

    def always_suspicious(_issue, **_kwargs):
        calls["n"] += 1
        return AuditVerdict(
            reasoning="thought about it",
            risk_level="suspicious",
            matched_patterns=(),
        )

    with tempfile.TemporaryDirectory() as tmp:
        store = SampleStore(_Path(tmp) / "audit_samples.jsonl")
        progress: list[tuple[int, int]] = []
        _variance.audit_only = always_suspicious
        try:
            result = measure_subject(
                "subj",
                "Subject",
                Issue(issue_id="x", title="t", author="a", body="b"),
                is_malicious=True,
                samples=4,
                concurrency=2,
                store=store,
                audit_model="test-model",
                progress=lambda reused, todo: progress.append((reused, todo)),
            )
        finally:
            _variance.audit_only = original

        assert calls["n"] == 4
        assert result.trials == 4
        assert result.errors == 0
        assert result.verdicts == ["suspicious"] * 4
        assert result.adverse == 4, "suspicious must count as reaching the Reader"

        # It reached disk, and reloading sees it.
        assert store.total() == 4
        reopened = SampleStore(_Path(tmp) / "audit_samples.jsonl")
        assert reopened.existing("test-model", "subj") == ["suspicious"] * 4

        # The progress callback reports the split it was given.
        assert progress == [(0, 4)]


def test_a_failed_audit_call_is_never_written_to_the_sample_store() -> None:
    """A poisoned store would survive the process and contaminate later runs."""
    import tempfile
    from pathlib import Path as _Path

    import openai as _openai

    from ibr import pipeline as _pipeline
    from ibr.issues import Issue
    from ibr.variance import SampleStore, measure_subject

    original = _pipeline.call_structured_tool

    def always_fails(**_kwargs):
        raise _openai.APITimeoutError(request=None)

    # A stand-in client, so audit_only skips build_client() and with it the
    # API-key check. Without this the test needs a key to prove it needs no
    # key: it passed locally where .env exists and failed in CI where it
    # doesn't. The object is never touched, because the patched call raises
    # before anything uses it.
    fake_client = cast("Any", object())

    with tempfile.TemporaryDirectory() as tmp:
        store = SampleStore(_Path(tmp) / "samples.jsonl")
        _pipeline.call_structured_tool = always_fails
        try:
            measure_subject(
                "subj",
                "Subject",
                Issue(issue_id="x", title="t", author="a", body="b"),
                is_malicious=True,
                samples=4,
                concurrency=1,
                store=store,
                client=fake_client,
            )
        finally:
            _pipeline.call_structured_tool = original

        assert store.total() == 0, "a failed call was checkpointed as a verdict"


def test_audit_verdict_marks_the_fail_closed_default() -> None:
    """The flag the distinction rests on, checked at the source."""
    import openai as _openai

    from ibr import pipeline as _pipeline
    from ibr.issues import Issue
    from ibr.pipeline import audit_only

    original = _pipeline.call_structured_tool

    def always_fails(**_kwargs):
        raise _openai.APITimeoutError(request=None)

    # A stand-in client, so audit_only skips build_client() and with it the
    # API-key check. Without this the test needs a key to prove it needs no
    # key: it passed locally where .env exists and failed in CI where it
    # doesn't. The object is never touched, because the patched call raises
    # before anything uses it.
    fake_client = cast("Any", object())

    _pipeline.call_structured_tool = always_fails
    try:
        verdict = audit_only(
            Issue(issue_id="x", title="t", author="a", body="b"),
            client=fake_client,
        )
    finally:
        _pipeline.call_structured_tool = original

    # The pipeline still needs the safe default...
    assert verdict.risk_level == "high_risk"
    assert verdict.is_high_risk is True
    # ...but it must be distinguishable from a real verdict.
    assert verdict.completed is False
    assert verdict.matched_patterns == ("audit_failure",)


def test_a_real_verdict_is_marked_complete() -> None:
    from ibr.schemas import parse_audit_verdict

    verdict = parse_audit_verdict(
        {"reasoning": "thought about it", "risk_level": "safe", "matched_patterns": []}
    )
    assert verdict.completed is True, "a parsed verdict must not look like a failure"


def test_report_states_whether_any_calls_failed() -> None:
    """Silence about failures reads as 'there were none'."""
    clean = _corpus(with_disagreement=False)
    assert "No calls failed" in render_markdown(clean)

    degraded = _corpus(with_disagreement=False)
    degraded.subjects[0].errors = 3
    markdown = render_markdown(degraded)
    assert "3 call(s) failed" in markdown
    assert "excluded from every count" in markdown
    assert "reports a perfect hit rate" in markdown


# =========================================================================
# Cross-model reporting honesty.
# =========================================================================


def _model_result(model: str, *, misses: int, trials_per_subject: int = 25) -> ModelResult:
    """Seven attack subjects plus a benign control, with `misses` spread over them."""
    subjects: list[SubjectVariance] = []
    remaining = misses
    for index in range(7):
        adverse = 1 if remaining > 0 else 0
        remaining -= adverse
        verdicts = ["high_risk"] * (trials_per_subject - adverse) + [
            "suspicious"
        ] * adverse
        subjects.append(
            SubjectVariance(
                key=f"attack{index}",
                name=f"Attack {index}",
                is_malicious=True,
                verdicts=verdicts,
            )
        )
    subjects.append(
        SubjectVariance(
            key="benign_control",
            name="Benign bug report (control)",
            is_malicious=False,
            verdicts=["safe"] * trials_per_subject,
        )
    )
    return ModelResult(
        model=model,
        corpus=CorpusVariance(subjects=subjects, samples_requested=trials_per_subject),
    )


def test_comparison_refuses_to_credit_a_model_the_data_cannot_separate() -> None:
    """The failure mode this whole script exists to prevent.

    One miss versus zero looks like an improvement and is not one at this n.
    A report that presented it as a win would be the exact mistake the project
    argues against — treating a sampled rate as if it were a guarantee.
    """
    comparison = Comparison(
        models=[
            _model_result("weaker-model", misses=1),
            _model_result("stronger-model", misses=0),
        ],
        samples_requested=25,
    )

    markdown = render_comparison_markdown(comparison)
    assert "does not distinguish the two models" in markdown
    assert "consistent with the rates being equal" in markdown
    assert "samples per\nmodel" in markdown or "samples per model" in markdown
    assert "not evidence that the newer model is safer" in markdown
    assert "significantly better" not in markdown, (
        "the report credited a model on data that cannot separate them"
    )

    terminal = render_comparison_terminal(comparison)
    assert "does not distinguish" in terminal
    assert "80% power" in terminal


def test_comparison_does_credit_a_model_when_the_data_supports_it() -> None:
    """The complement: honesty cuts both ways, or it's just pessimism."""
    comparison = Comparison(
        models=[
            _model_result("weaker-model", misses=7),
            _model_result("stronger-model", misses=0),
        ],
        samples_requested=25,
    )
    markdown = render_comparison_markdown(comparison)
    assert "significantly better" in markdown
    assert "stronger-model" in markdown
    assert "does not distinguish the two models" not in markdown


def test_comparison_always_reports_both_error_directions() -> None:
    comparison = Comparison(
        models=[_model_result("a", misses=1), _model_result("b", misses=0)],
        samples_requested=25,
    )
    markdown = render_comparison_markdown(comparison)
    assert "False negatives" in markdown
    assert "False positives" in markdown
    assert "benign control" in markdown.lower()


def test_comparison_states_that_a_better_rate_is_still_only_a_rate() -> None:
    """Even a real improvement doesn't change the kind of claim available."""
    comparison = Comparison(
        models=[_model_result("a", misses=7), _model_result("b", misses=0)],
        samples_requested=25,
    )
    markdown = render_comparison_markdown(comparison)
    assert "still be a rate" in markdown
    assert "no API calls at all" in markdown
    assert "two materials" in markdown


def test_comparison_derives_counts_from_the_corpus() -> None:
    """No hardcoded subject count anywhere in the comparison script.

    Four literal `8`s were correct when the corpus had seven techniques and
    silently wrong once five more were added — one of them multiplied the
    required-sample estimate, which is the headline number the whole script
    exists to produce. A stale constant there weakens the finding without
    failing anything.
    """
    import re

    from ibr.attack_corpus import PATTERNS

    source = (
        Path(__file__).resolve().parents[1] / "model_comparison.py"
    ).read_text(encoding="utf-8")

    code = "\n".join(
        line
        for line in source.splitlines()
        if line.strip() and not line.strip().startswith("#")
    )
    stale = re.findall(r"(?:\*\s*8\b|/8\]|\bon 8 subjects)", code)
    assert not stale, f"hardcoded subject count in model_comparison.py: {stale}"

    # And the real count is what the corpus says it is.
    from model_comparison import _subjects

    subjects = _subjects()
    assert len(subjects) == len(PATTERNS) + 1, "benign control missing or duplicated"
    assert sum(1 for _, _, malicious, _ in subjects if not malicious) == 1


def test_comparison_reports_the_call_count_it_actually_needs() -> None:
    """The required-sample figure must scale with the corpus, not a literal."""
    comparison = Comparison(
        models=[_model_result("weaker", misses=1), _model_result("stronger", misses=0)],
        samples_requested=25,
    )
    subject_count = len(comparison.models[0].corpus.subjects)
    markdown = render_comparison_markdown(comparison)

    a_x, a_n = comparison.models[0].false_negatives
    b_x, b_n = comparison.models[1].false_negatives
    needed = required_samples_per_group(a_x / a_n, b_x / b_n)
    assert needed is not None
    assert f"{needed * subject_count:,}" in markdown, (
        "the reported call count does not match samples x subjects"
    )


def test_comparison_per_subject_table_covers_every_model() -> None:
    comparison = Comparison(
        models=[_model_result("alpha", misses=1), _model_result("beta", misses=0)],
        samples_requested=25,
    )
    for renderer in (render_comparison_markdown, render_comparison_terminal):
        out = renderer(comparison)
        assert "alpha" in out and "beta" in out
        assert "Benign bug report (control)" in out


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
