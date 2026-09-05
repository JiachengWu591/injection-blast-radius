"""The batch runner and the idempotency ledger.

Two things are being guarded, and they fail in opposite directions.

**An error must never read as a decision.** This project has shipped that bug
twice — a failed audit counted as a detection, an API error reported as "the
model declined" — and both times the cause was a failure path and a decision
path producing the same value. `IssueOutcome.status` has three values so the
mistake needs a deliberate edit rather than an oversight.

**An action must never happen twice, and must never be silently skipped.** The
ledger records an intent before the sink runs and a confirmation after, so a
run interrupted mid-action leaves a trace that cannot be resolved by guessing.
A resumed run refuses and names the key. That refusal is the fail-closed rule
applied to the only part of this project with an effect outside the process.

Run standalone:
    python tests/test_batch.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import replay  # noqa: E402

from ibr import sandbox_fs  # noqa: E402
from ibr.batch import IssueOutcome, run_batch  # noqa: E402
from ibr.bootstrap import ensure_sandbox  # noqa: E402
from ibr.config import LABELS_PATH, PUBLIC_COMMENTS_PATH  # noqa: E402
from ibr.executor import COMMENT_TEMPLATES, execute  # noqa: E402
from ibr.issues import Issue, load_issue  # noqa: E402
from ibr.schemas import ReaderOutput  # noqa: E402
from ibr.sinks import (  # noqa: E402
    ActionKey,
    ActionLedger,
    ActionSink,
    DanglingIntent,
    DryRunSink,
    IdempotentSink,
)
from ibr.sources import load_labelled_corpus  # noqa: E402

LEDGER = Path("logs/test_ledger.jsonl")


def _fresh_ledger() -> ActionLedger:
    ensure_sandbox()
    sandbox_fs.write_text(LEDGER, "")
    return ActionLedger(path=LEDGER)


def _issue(issue_id: str = "b-1") -> Issue:
    return Issue(
        issue_id=issue_id, title="Crash on start", author="dev-1", body="boom"
    )


def _reader(action: str, issue_type: str = "bug") -> ReaderOutput:
    return ReaderOutput(
        reasoning="(fixture)",
        issue_type=issue_type,
        suggested_action=action,
        summary="(fixture)",
    )


# --- the ledger -------------------------------------------------------------


def test_a_fresh_action_is_performed_once() -> None:
    ledger = _fresh_ledger()
    inner = DryRunSink()
    sink = IdempotentSink(inner=inner, ledger=ledger)

    sink.add_label("77", "bug")
    assert [a.payload for a in inner.labels] == ["bug"]
    assert len(sink.performed) == 1
    assert sink.skipped == []


def test_the_same_action_is_not_performed_twice() -> None:
    """The gap ARCHITECTURE.md named: running the same issue twice posts twice."""
    ledger = _fresh_ledger()
    inner = DryRunSink()
    sink = IdempotentSink(inner=inner, ledger=ledger)

    sink.add_label("77", "bug")
    sink.add_label("77", "bug")

    assert len(inner.labels) == 1, "the inner sink was asked twice"
    assert len(sink.skipped) == 1
    assert str(sink.skipped[0]) == str(ActionKey.of("label", "77", "bug"))


def test_a_duplicate_comment_is_suppressed_too() -> None:
    """The same guarantee as for labels, on the action that is public.

    Found by the coverage gate: the duplicate test used `add_label`, so the
    early return in `publish_comment` had never run. Publishing is the
    higher-stakes half — a repeated label is untidy, a repeated public comment
    is the thing an operator would be embarrassed by.
    """
    ledger = _fresh_ledger()
    inner = DryRunSink()
    sink = IdempotentSink(inner=inner, ledger=ledger)

    body = COMMENT_TEMPLATES["bug"]
    sink.publish_comment("77", body)
    sink.publish_comment("77", body)

    assert len(inner.comments) == 1, "the same comment was published twice"
    assert len(sink.skipped) == 1


def test_a_ledger_with_no_file_yet_is_empty_not_broken() -> None:
    """First run on a fresh install. Nothing has happened, so nothing is done."""
    ensure_sandbox()
    missing = Path("logs/never_written_ledger.jsonl")
    resolved = sandbox_fs.resolve_in_sandbox(missing)
    if resolved.exists():
        resolved.unlink()

    ledger = ActionLedger(path=missing)
    assert ledger.state() == {}
    assert ledger.check(ActionKey.of("label", "1", "bug")) == "fresh"


def test_a_blank_line_in_the_ledger_is_skipped() -> None:
    """Append-only files pick up stray newlines; that is not corruption."""
    ledger = _fresh_ledger()
    ledger.done(ActionKey.of("label", "77", "bug"))
    sandbox_fs.append_text(LEDGER, "\n\n")
    ledger.done(ActionKey.of("label", "78", "bug"))

    state = ActionLedger(path=LEDGER).state()
    assert state.get(str(ActionKey.of("label", "77", "bug"))) == "done"
    assert state.get(str(ActionKey.of("label", "78", "bug"))) == "done"


def test_a_different_body_is_a_different_action() -> None:
    """Deduplication must not swallow a genuinely new action.

    Same issue, same kind, different text is a different thing to publish. A
    key built only from (issue, kind) would drop it, which is the failure mode
    that looks like the system working.
    """
    ledger = _fresh_ledger()
    inner = DryRunSink()
    sink = IdempotentSink(inner=inner, ledger=ledger)

    sink.publish_comment("77", "first body")
    sink.publish_comment("77", "second body")

    assert len(inner.comments) == 2
    assert sink.skipped == []


def test_a_resumed_run_skips_what_a_previous_one_finished() -> None:
    """The ledger is on disk, so a second process sees the first one's work."""
    ledger = _fresh_ledger()
    first = IdempotentSink(inner=DryRunSink(), ledger=ledger)
    first.add_label("77", "bug")

    second_inner = DryRunSink()
    second = IdempotentSink(inner=second_inner, ledger=ActionLedger(path=LEDGER))
    second.add_label("77", "bug")

    assert second_inner.actions == [], "a resumed run repeated a finished action"
    assert len(second.skipped) == 1


def test_a_dangling_intent_refuses_rather_than_guessing() -> None:
    """The case where both single-phase designs are wrong.

    An intent with no confirmation means the process died between deciding and
    landing the action. Retrying risks a duplicate; skipping risks losing it.
    Neither is a choice code should make, so it raises and names the key.
    """
    ledger = _fresh_ledger()
    key = ActionKey.of("comment", "77", COMMENT_TEMPLATES["bug"])
    ledger.intend(key)  # and then, notionally, the process died

    sink = IdempotentSink(inner=DryRunSink(), ledger=ActionLedger(path=LEDGER))
    try:
        sink.publish_comment("77", COMMENT_TEMPLATES["bug"])
    except DanglingIntent as exc:
        assert str(key) in str(exc)
        assert "confirm" in str(exc) and "discard" in str(exc), (
            "the error must say what an operator can do about it"
        )
    else:
        raise AssertionError("a dangling intent was resolved by guessing")


def test_an_operator_can_resolve_a_dangling_intent_either_way() -> None:
    ledger = _fresh_ledger()
    key = ActionKey.of("label", "77", "bug")

    ledger.intend(key)
    ledger.confirm(key)
    confirmed_inner = DryRunSink()
    IdempotentSink(inner=confirmed_inner, ledger=ActionLedger(path=LEDGER)).add_label(
        "77", "bug"
    )
    assert confirmed_inner.actions == [], "confirm should mean do not repeat"

    other = ActionKey.of("label", "78", "bug")
    ledger.intend(other)
    ledger.discard(other)
    discarded_inner = DryRunSink()
    IdempotentSink(inner=discarded_inner, ledger=ActionLedger(path=LEDGER)).add_label(
        "78", "bug"
    )
    assert len(discarded_inner.actions) == 1, "discard should allow a retry"


def test_the_ledger_tolerates_a_torn_last_line_only() -> None:
    """A crash mid-append truncates the last line; anything else is corruption.

    The same rule the sample store settled on: a malformed line is tolerated
    only when it is both last *and* unterminated. Tolerating a bad line
    anywhere would mean a ledger could lose an arbitrary action and still
    load, and the ledger's whole job is to know what already happened.

    The first version of this test asserted
    `ledger.state().get(key) is None or True`, which cannot fail, so it agreed
    with either rule. The three cases below are the ones that separate them.
    """
    # 1. Genuinely torn: last line, no trailing newline. Tolerated, and the
    #    earlier records still load.
    ledger = _fresh_ledger()
    settled = ActionKey.of("label", "77", "bug")
    ledger.done(settled)
    sandbox_fs.append_text(LEDGER, '{"key": "label:78:abc", "phase"')
    state = ledger.state()
    assert state.get(str(settled)) == "done", (
        "a torn final line lost the completed record above it, so a resumed "
        f"run would redo an action that already happened: {state}"
    )
    assert "label:78:abc" not in state, "a half-written line was believed"

    # 2. Last line, but the file is terminated. That is damage, not an
    #    interrupted write — and it is the case the position-only rule got
    #    wrong. A lost `done` here leaves an intent reading as
    #    never-attempted, and the resume publishes twice.
    sandbox_fs.write_text(
        LEDGER, '{"key": "x", "phase": "intent"}\n{"key": "y", "phase"}\n'
    )
    try:
        ActionLedger(path=LEDGER).state()
    except DanglingIntent as exc:
        assert "cannot be repaired by inference" in str(exc)
    else:
        raise AssertionError(
            "a corrupt but fully-terminated last line was tolerated. `_append` "
            "writes json + newline per call, so a file ending in a newline "
            "holds only whole records: this one was corrupted by something "
            "other than an interrupted write, and dropping it silently is how "
            "a lost `done` turns into a duplicate publish."
        )

    # 3. Corrupt in the middle, terminated. Fatal under either rule; kept so
    #    the obvious case cannot regress while attention is on case 2.
    sandbox_fs.write_text(LEDGER, '{"broken"\n{"key": "x", "phase": "done"}\n')
    try:
        ActionLedger(path=LEDGER).state()
    except DanglingIntent as exc:
        assert "cannot be repaired by inference" in str(exc)
    else:
        raise AssertionError("a corrupted middle line was tolerated")


def test_the_intent_is_on_disk_before_the_inner_sink_runs() -> None:
    """The ordering *is* the design, so the ordering is what has to be tested.

    Found by mutation: deleting the pre-write broke no other assertion here.
    Every other test passed, and the ledger had quietly become single-phase —
    recording only after the inner sink returns, which loses the action when
    the process dies mid-call and makes the retry post twice. That is the exact
    failure the two-phase design exists to prevent, so it cannot be guarded by
    inspecting the end state; something has to watch from inside the call.

    `state()` rather than `check()`, because `check()` raises on an intent —
    which is correct for a resumed run and useless for observing one in flight.
    """
    ledger = _fresh_ledger()
    key = ActionKey.of("label", "77", "bug")
    observed: list[str] = []

    class WatchesTheLedger:
        def publish_comment(self, issue_id: str, body: str) -> None:
            observed.append("comment")

        def add_label(self, issue_id: str, label: str) -> None:
            observed.append(ActionLedger(path=LEDGER).state().get(str(key), "fresh"))

    IdempotentSink(inner=WatchesTheLedger(), ledger=ledger).add_label("77", "bug")

    assert observed == ["intent"], (
        f"the ledger said {observed!r} while the action was in flight, expected "
        "['intent']. Without the pre-write a crash at this point leaves no "
        "trace, and the resumed run posts a second time."
    )
    # And once it returns, the intent must have been settled.
    assert ledger.state()[str(key)] == "done"


def test_an_idempotent_sink_is_still_a_sink() -> None:
    ledger = _fresh_ledger()
    sink = IdempotentSink(inner=DryRunSink(), ledger=ledger)
    assert isinstance(sink, ActionSink)


def test_the_wrapper_is_never_consulted_on_a_no_action_path() -> None:
    """Wrapping must not create a new way for a refusal to become visible.

    The same invariant tests/test_seams.py holds for a bare sink. Adding a
    ledger means a no_action path could now leave a row on disk, which is an
    externally visible trace of a refusal.
    """
    ledger = _fresh_ledger()
    sink = IdempotentSink(inner=DryRunSink(), ledger=ledger)

    for reader_output in (None, _reader("no_action"), _reader("not_an_action")):
        decision = execute("79", reader_output, sink=sink)
        assert decision.action_taken == "no_action"

    assert sink.performed == [] and sink.skipped == []
    assert ledger.state() == {}, (
        f"a no_action path wrote to the ledger: {ledger.state()}"
    )


# --- the batch runner -------------------------------------------------------


def _cassette_client() -> Any:
    return cast("Any", replay.load("isolated_benign"))


def _recorded_issue() -> Issue:
    """The issue the `isolated_benign` cassette was recorded against.

    The cassette checks a request fingerprint, so a made-up issue is rejected
    rather than replayed — which is the recording machinery working, and the
    reason these tests use the real fixture instead of a convenient stand-in.
    """
    return load_issue("benign")


def test_a_batch_runs_every_issue_and_writes_nothing_in_dry_run() -> None:
    ensure_sandbox()
    before = (
        sandbox_fs.read_text(PUBLIC_COMMENTS_PATH),
        sandbox_fs.read_text(LABELS_PATH),
    )
    sink = DryRunSink()
    report = run_batch(
        [(_recorded_issue(), "plain")],
        sink=sink,
        client=_cassette_client(),
        concurrency=1,
    )

    assert len(report.outcomes) == 1
    assert report.failed == []
    assert (
        sandbox_fs.read_text(PUBLIC_COMMENTS_PATH),
        sandbox_fs.read_text(LABELS_PATH),
    ) == before, "a dry run changed a public surface"


def test_an_error_is_a_third_status_not_a_quiet_no_action() -> None:
    """The bug this project shipped twice, made structurally hard to repeat."""

    class Exploding:
        @property
        def chat(self) -> Any:
            raise RuntimeError("connection reset by peer")

    report = run_batch(
        [(_issue("b-2"), "plain")],
        sink=DryRunSink(),
        client=cast("Any", Exploding()),
        concurrency=1,
    )

    assert len(report.failed) == 1
    outcome = report.outcomes[0]
    assert outcome.status == "failed"
    assert outcome.error and "connection reset" in outcome.error
    # And it must not masquerade as the audit having refused.
    assert not outcome.blocked_by_audit
    assert report.acted == []


def test_one_bad_issue_does_not_end_the_batch() -> None:
    class ExplodesOnce:
        def __init__(self) -> None:
            self.calls = 0

        @property
        def chat(self) -> Any:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("transient")
            raise RuntimeError("also transient")

    report = run_batch(
        [(_issue("b-3"), "plain"), (_issue("b-4"), "plain")],
        sink=DryRunSink(),
        client=cast("Any", ExplodesOnce()),
        concurrency=1,
    )
    assert len(report.outcomes) == 2, "the batch stopped at the first failure"
    assert len(report.failed) == 2


def test_already_done_issues_are_skipped_not_rerun() -> None:
    """Resume at the issue level. This is the half that saves money."""
    recorded = _recorded_issue()
    report = run_batch(
        [(_issue("b-5"), "plain"), (recorded, "plain")],
        sink=DryRunSink(),
        client=_cassette_client(),
        concurrency=1,
        already_done=frozenset({"b-5"}),
    )
    assert report.skipped_already_done == ["b-5"]
    assert [o.issue_id for o in report.outcomes] == [recorded.issue_id]
    assert report.failed == [], "the issue that did run should have succeeded"


def test_the_concurrent_branch_runs_at_all() -> None:
    """`concurrency=8` is the default, and no test had ever executed it.

    Every call site in this file passed `concurrency=1`, so `run_batch` had two
    independent execution branches and the tested one was the branch nobody
    uses: `DEFAULT_CONCURRENCY` is 8, `batch_dry_run.py` takes that default,
    and ARCHITECTURE.md calls this "the production runner". The `else` arm — a
    ThreadPoolExecutor, and the ledger underneath it, which has no lock —
    was reached by nothing.

    Reachable offline, which is why the omission is worth fixing rather than
    excusing: the fakes below need no API and no cassette, so CI's
    "the offline suite cannot reach the API-calling paths" does not apply here.

    What this can and cannot show. It exercises the branch, so the ordering
    contract and the progress callback are now pinned and a crash in that arm
    would fail a test. It does not prove the ledger is race-free: three threads
    over distinct keys is not a stress test, and the unlocked append remains a
    hazard for an adopter who wraps a real sink. That belongs in the
    documentation, not in an assertion that would pass by luck.
    """

    class Exploding:
        """No API, no cassette. Every issue fails identically and in order."""

        @property
        def chat(self) -> Any:
            raise RuntimeError("connection reset by peer")

    issues = [(_issue(f"c-{n}"), "plain") for n in range(1, 8)]
    seen: list[tuple[int, int]] = []
    report = run_batch(
        issues,
        sink=DryRunSink(),
        client=cast("Any", Exploding()),
        concurrency=3,
        progress=lambda done, total: seen.append((done, total)),
    )

    assert len(report.outcomes) == len(issues), (
        f"{len(report.outcomes)} outcomes for {len(issues)} issues — the "
        "concurrent branch dropped or duplicated work"
    )
    assert [o.issue_id for o in report.outcomes] == [i.issue_id for i, _ in issues], (
        "the concurrent branch returned outcomes out of order. `pool.map` "
        "preserves input order and the report is read positionally, so this "
        "would misattribute every row to the wrong issue."
    )
    assert len(report.failed) == len(issues), "every issue was meant to fail"
    assert seen == [(n, len(issues)) for n in range(1, len(issues) + 1)], (
        f"progress was reported as {seen}; it must count 1..n against a fixed "
        "total, or a long run's progress line is meaningless"
    )
    for outcome in report.outcomes:
        assert outcome.status == "failed"
        assert outcome.action == "no_action", (
            "a failure produced an action. §1.4: an error is not a decision."
        )
        assert outcome.error and "connection reset" in outcome.error


def test_the_concurrent_and_serial_branches_agree() -> None:
    """Two code paths, one contract. The difference must be wall time only.

    Without this, a change to one branch can silently give the two different
    semantics — and the default is the one no other test runs.
    """

    class Exploding:
        @property
        def chat(self) -> Any:
            raise RuntimeError("connection reset by peer")

    issues = [(_issue(f"d-{n}"), "plain") for n in range(1, 6)]

    def fields(concurrency: int) -> list[tuple[str, str, str]]:
        report = run_batch(
            issues,
            sink=DryRunSink(),
            client=cast("Any", Exploding()),
            concurrency=concurrency,
        )
        return [
            (o.issue_id, o.status, o.action) for o in report.outcomes
        ]

    assert fields(1) == fields(4), (
        "the serial and concurrent branches disagree about what happened to "
        "the same issues"
    )


def test_the_report_separates_blocked_from_acted_from_failed() -> None:
    outcomes = [
        IssueOutcome(
            issue_id="a", status="acted", action="label_bug", risk_level="safe",
            stratum="plain", duration_ms=1, input_tokens=10, output_tokens=5,
        ),
        IssueOutcome(
            issue_id="b", status="no_action", action="no_action",
            risk_level="high_risk", stratum="mentions_config", duration_ms=1,
            input_tokens=7, output_tokens=3,
        ),
        IssueOutcome(
            issue_id="c", status="failed", action="no_action", risk_level=None,
            stratum="plain", duration_ms=1, input_tokens=0, output_tokens=0,
            error="boom",
        ),
    ]
    from ibr.batch import BatchReport

    report = BatchReport(outcomes=outcomes)
    assert [o.issue_id for o in report.acted] == ["a"]
    assert [o.issue_id for o in report.blocked] == ["b"]
    assert [o.issue_id for o in report.failed] == ["c"]
    assert report.input_tokens == 17 and report.output_tokens == 8
    assert set(report.by_stratum()) == {"plain", "mentions_config"}
    # Rates are the caller's, so the report must not bake one in.
    assert abs(report.cost_usd(1.0, 2.0) - (17 / 1e6 + 16 / 1e6)) < 1e-12


def test_the_corpus_loads_as_labelled_pairs() -> None:
    pairs = load_labelled_corpus()
    assert len(pairs) >= 150
    for issue, stratum in pairs:
        assert isinstance(issue, Issue)
        assert stratum, f"{issue.issue_id} has no stratum"


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
