"""The two production seams: where issues come from, where actions go.

A seam is only real if a second implementation works without the code around it
noticing. One implementation of a protocol is indistinguishable from a
description of that implementation, so every assertion here that matters uses
the *non-default* one.

The other half of the job is proving the seam did not widen anything. A sink is
handed an already-decided action; it must not be able to turn a no_action into
an action, and the output audit must still run before it is consulted. Those
are the assertions that would fail if the refactor had quietly moved a check.

Run standalone:
    python tests/test_seams.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ibr import sandbox_fs  # noqa: E402
from ibr.bootstrap import ensure_sandbox  # noqa: E402
from ibr.config import LABELS_PATH, PUBLIC_COMMENTS_PATH  # noqa: E402
from ibr.executor import COMMENT_TEMPLATES, execute  # noqa: E402
from ibr.issues import Issue, MalformedIssue, load_issue, parse_issue  # noqa: E402
from ibr.schemas import ReaderOutput  # noqa: E402
from ibr.sinks import (  # noqa: E402
    DEFAULT_SINK,
    ActionSink,
    DryRunSink,
    SandboxActionSink,
)
from ibr.sources import (  # noqa: E402
    DEFAULT_SOURCE,
    IssueSource,
    JsonLinesIssueSource,
    SandboxIssueSource,
    write_jsonl,
)

# Relative paths resolve against the sandbox root, and `sandbox/*.jsonl` is
# already a gitignored runtime artifact, so these leave nothing behind in git.
SCRATCH = Path(".")


def _reader(action: str, issue_type: str = "bug") -> ReaderOutput:
    return ReaderOutput(
        reasoning="(fixture)",
        issue_type=issue_type,
        suggested_action=action,
        summary="(fixture)",
    )


def _sample_issues() -> list[Issue]:
    return [
        Issue(issue_id="4821", title="Crash on start", author="alice", body="boom"),
        Issue(issue_id="4822", title="How do I?", author="bob", body="asking"),
    ]


# --- sinks -----------------------------------------------------------------


def test_dry_run_sink_records_a_comment_and_writes_nothing() -> None:
    ensure_sandbox()
    before = sandbox_fs.read_text(PUBLIC_COMMENTS_PATH)

    sink = DryRunSink()
    decision = execute("77", _reader("reply_comment", "bug"), sink=sink)

    assert decision.action_taken == "reply_comment"
    assert [a.kind for a in sink.actions] == ["comment"]
    assert sink.comments[0].issue_id == "77"
    assert sink.comments[0].payload == COMMENT_TEMPLATES["bug"]
    assert sandbox_fs.read_text(PUBLIC_COMMENTS_PATH) == before, (
        "DryRunSink wrote to the public surface. Its entire purpose is that "
        "you can point it at real data and nothing happens."
    )


def test_dry_run_sink_records_a_label_and_writes_nothing() -> None:
    ensure_sandbox()
    before = sandbox_fs.read_text(LABELS_PATH)

    sink = DryRunSink()
    decision = execute("78", _reader("label_bug"), sink=sink)

    assert decision.action_taken == "label_bug"
    assert decision.labels_added == ("bug",)
    assert [(a.kind, a.payload) for a in sink.labels] == [("label", "bug")]
    assert sandbox_fs.read_text(LABELS_PATH) == before


def test_a_sink_sees_nothing_when_the_decision_is_no_action() -> None:
    """The seam must not be reachable from a rejected input.

    If a sink were consulted on the no_action paths, a sink with a bug — or a
    sink that logged what it was asked to do — would turn "we refused" into an
    externally visible event. Every fail-closed path must be silent.
    """
    for reader_output in (
        None,
        _reader("no_action"),
        _reader("rm -rf /"),  # not in the whitelist
        _reader("reply_comment", "not_a_real_type"),  # no template
    ):
        sink = DryRunSink()
        decision = execute("79", reader_output, sink=sink)
        assert decision.action_taken == "no_action"
        assert sink.actions == [], (
            f"sink was called on a no_action path for {reader_output!r}"
        )


def test_the_output_audit_runs_before_the_sink_is_consulted() -> None:
    """The last check before publication must not be swappable with the sink.

    Verified by giving the executor a template that the output audit blocks and
    checking the sink never hears about it. If the audit ever moved inside
    SandboxActionSink, this would pass for the default sink and silently fail
    for every real one — which is exactly the mistake worth a test.
    """
    ensure_sandbox()
    secret = "fake-sk-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"
    original = COMMENT_TEMPLATES["bug"]
    COMMENT_TEMPLATES["bug"] = f"Triaged. Deploy key: {secret}"
    try:
        sink = DryRunSink()
        decision = execute("80", _reader("reply_comment", "bug"), sink=sink)
    finally:
        COMMENT_TEMPLATES["bug"] = original

    assert decision.action_taken == "blocked_by_output_audit"
    assert sink.actions == [], "blocked text still reached the sink"


def test_the_default_sink_still_writes_the_same_bytes() -> None:
    """The refactor must be invisible to everything that already existed."""
    ensure_sandbox()
    before = sandbox_fs.read_text(PUBLIC_COMMENTS_PATH)
    execute("81", _reader("reply_comment", "question"))
    written = sandbox_fs.read_text(PUBLIC_COMMENTS_PATH)[len(before) :]

    assert written == (
        "\n----- comment on issue #81 (isolated pipeline) -----\n"
        + COMMENT_TEMPLATES["question"].rstrip()
        + "\n"
    )


def test_a_hand_written_sink_satisfies_the_protocol_structurally() -> None:
    """An adopter must not have to import from this package to integrate."""

    class Elsewhere:
        def __init__(self) -> None:
            self.seen: list[tuple[str, str, str]] = []

        def publish_comment(self, issue_id: str, body: str) -> None:
            self.seen.append(("comment", issue_id, body))

        def add_label(self, issue_id: str, label: str) -> None:
            self.seen.append(("label", issue_id, label))

    sink = Elsewhere()
    assert isinstance(sink, ActionSink)
    execute("82", _reader("label_question"), sink=sink)
    assert sink.seen == [("label", "82", "question")]


def test_the_defaults_are_the_sandbox_implementations() -> None:
    assert isinstance(DEFAULT_SINK, SandboxActionSink)
    assert isinstance(DEFAULT_SOURCE, SandboxIssueSource)


# --- sources ---------------------------------------------------------------


def test_the_sandbox_source_agrees_with_the_module_level_loader() -> None:
    """`load_issue` is what every script calls; the source must not diverge."""
    ensure_sandbox()
    source = SandboxIssueSource()
    assert source.available_issues() != []
    for name in source.available_issues():
        assert source.load_issue(name) == load_issue(name)


def test_a_jsonl_source_round_trips() -> None:
    ensure_sandbox()
    path = SCRATCH / "seam_issues.jsonl"
    issues = _sample_issues()
    write_jsonl(path, issues)

    source = JsonLinesIssueSource(path)
    assert isinstance(source, IssueSource)
    assert source.available_issues() == ["4821", "4822"]
    assert [source.load_issue(i.issue_id) for i in issues] == issues


def test_a_jsonl_source_fails_closed_on_a_malformed_line() -> None:
    """One bad line must not yield a partial corpus.

    A source that skipped unparseable records would decide, silently, which
    issues the pipeline is measured on.
    """
    ensure_sandbox()
    path = SCRATCH / "seam_broken.jsonl"
    sandbox_fs.write_text(
        path,
        '{"issue_id": "1", "title": "t", "author": "a", "body": "b"}\n'
        "{not json}\n",
    )
    source = JsonLinesIssueSource(path)
    for call in (lambda: source.load_issue("1"), source.available_issues):
        try:
            call()
        except MalformedIssue as exc:
            assert "seam_broken.jsonl:2" in str(exc), f"unhelpful location: {exc}"
        else:
            raise AssertionError("a malformed line was tolerated")


def test_a_jsonl_source_rejects_a_duplicate_id() -> None:
    ensure_sandbox()
    path = SCRATCH / "seam_dupes.jsonl"
    duplicate = _sample_issues()[0]
    write_jsonl(path, [duplicate, duplicate])
    try:
        JsonLinesIssueSource(path).available_issues()
    except MalformedIssue as exc:
        assert "duplicate" in str(exc)
    else:
        raise AssertionError("two issues with the same id were accepted")


def test_every_source_shares_one_validator() -> None:
    """The reason `parse_issue` is not a method.

    Two sources with their own checks is how a field that is a string on one
    path and an integer on another reaches the pipeline.
    """
    ensure_sandbox()
    wrong_type = '{"issue_id": 4821, "title": "t", "author": "a", "body": "b"}'
    missing = '{"issue_id": "1", "title": "t"}'

    for raw, expected in ((wrong_type, "must be strings"), (missing, "missing")):
        path = SCRATCH / "seam_one.jsonl"
        sandbox_fs.write_text(path, raw + "\n")
        try:
            JsonLinesIssueSource(path).available_issues()
        except MalformedIssue as exc:
            assert expected in str(exc)
        else:
            raise AssertionError(f"accepted {raw!r}")

        try:
            parse_issue(raw, origin="direct")
        except MalformedIssue as exc:
            assert expected in str(exc)
        else:
            raise AssertionError(f"parse_issue accepted {raw!r}")


def test_a_source_reading_outside_the_sandbox_is_refused() -> None:
    """The whitelist covers issue loading, not just what an agent asks for."""
    source = JsonLinesIssueSource(Path("../../secrets.jsonl"))
    try:
        source.available_issues()
    except sandbox_fs.SandboxViolation:
        pass
    else:
        raise AssertionError("a source escaped the sandbox")


def test_a_missing_issue_names_what_is_available() -> None:
    ensure_sandbox()
    try:
        SandboxIssueSource().load_issue("does_not_exist")
    except MalformedIssue as exc:
        assert "have:" in str(exc)
    else:
        raise AssertionError("a missing issue was not reported")


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
