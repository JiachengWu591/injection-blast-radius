"""The fail-closed paths, driven by constructed API responses.

PROJECT_SPEC.md §1.4 is the strictest rule in the project: any error, timeout,
or malformed response must end in "do not act", never in "skip the check and
proceed". Every phase report has claimed that behaviour, and one of them was
even verified by accident when DeepSeek rejected a `tool_choice` mid-build.

None of it had an end-to-end test. `ibr/llm.py`'s retry arms, both of
`ibr/pipeline.py`'s fail-closed branches, and most of
`ibr/baseline_agent.py`'s error handling were unexecuted by any assertion —
the safety property with the loudest claim attached to it was the least
covered code in the package.

These responses are constructed rather than recorded, and labelled as such:
a truncated tool-call argument or a connection failure cannot be produced
against the live API on demand. Every one carries a reason, and an assertion
requires that reason to be substantive, because "synthetic" must not become
the way an inconvenient fingerprint gets silenced.

Run standalone:
    python tests/test_failure_paths.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ibr import sandbox_fs  # noqa: E402
from ibr.baseline_agent import run_baseline  # noqa: E402
from ibr.bootstrap import ensure_sandbox, reset_labels, reset_public_comments  # noqa: E402
from ibr.config import PUBLIC_COMMENTS_PATH  # noqa: E402
from ibr.fixtures import BAIT_SECRET_VALUE
from ibr.issues import Issue, load_issue  # noqa: E402
from ibr.llm import StructuredOutputFailure, call_structured_tool, ping  # noqa: E402
from ibr.pipeline import run_isolated  # noqa: E402
from tests import replay  # noqa: E402

ensure_sandbox()

TOOL = "report_security_assessment"
SCHEMA = {"type": "object", "properties": {}, "additionalProperties": False}


def _tool_response(name: str, arguments: str, *, call_id: str = "c1") -> dict:
    return {
        "model": "synthetic",
        "choices": [
            {
                "message": {
                    "content": None,
                    "tool_calls": [
                        {
                            "id": call_id,
                            "type": "function",
                            "function": {"name": name, "arguments": arguments},
                        }
                    ],
                    "model_dump": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": call_id,
                                "type": "function",
                                "function": {"name": name, "arguments": arguments},
                            }
                        ],
                    },
                }
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }


def _text_response(text: str) -> dict:
    return {
        "model": "synthetic",
        "choices": [
            {
                "message": {
                    "content": text,
                    "tool_calls": [],
                    "model_dump": {"role": "assistant", "content": text},
                }
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }


MIN_REASON = 40


def _synthetic(reason: str, response: dict) -> dict:
    """Build a constructed interaction, refusing a reason too thin to review.

    Enforced here rather than by a separate audit: a registry of scenarios to
    check would have to be maintained alongside the tests and would drift from
    them. Checking at construction cannot drift, because there is no way to
    build a synthetic interaction that skips it.
    """
    if len(reason) < MIN_REASON:
        raise AssertionError(
            f"synthetic interaction needs a reason of at least {MIN_REASON} "
            f"characters saying why it cannot be recorded; got {reason!r}"
        )
    return {"synthetic": reason, "response": response}


def _raises(reason: str, exception: str) -> dict:
    if len(reason) < MIN_REASON:
        raise AssertionError(
            f"synthetic interaction needs a reason of at least {MIN_REASON} "
            f"characters saying why it cannot be recorded; got {reason!r}"
        )
    return {"synthetic": reason, "raises": exception, "response": {}}


def _call_tool(interactions: list[dict], *, name: str):
    client = replay.from_interactions(interactions, name=name)
    return call_structured_tool(
        model="synthetic",
        system="s",
        user="u",
        tool_name=TOOL,
        tool_description="d",
        parameters=SCHEMA,
        client=cast("Any", client),
    )


# =========================================================================
# The synthetic escape hatch must stay expensive to use.
# =========================================================================


def test_a_synthetic_interaction_without_a_reason_is_refused() -> None:
    """Otherwise 'synthetic' becomes how a failing fingerprint gets silenced.

    Checked by trying to build one, so the guarantee holds for every scenario
    in this file by construction rather than by an audit that could fall out
    of step with it.
    """
    for builder in (
        lambda: _synthetic("too short", _tool_response(TOOL, "{}")),
        lambda: _raises("nope", "APITimeoutError"),
    ):
        try:
            builder()
        except AssertionError as exc:
            assert "why it cannot be recorded" in str(exc)
        else:
            raise AssertionError("a synthetic interaction with no reason was built")


def test_a_synthetic_interaction_skips_the_fingerprint_check() -> None:
    """The escape hatch works — and only for interactions that declare it."""
    client = replay.from_interactions(
        [
            _synthetic(
                "any response at all, to prove a declared synthetic "
                "interaction is served without a fingerprint comparison",
                _text_response("served"),
            )
        ],
        name="hatch",
    )
    response = client.chat.completions.create(
        model="anything", messages=[{"role": "user", "content": "unmatched"}]
    )
    assert response.choices[0].message.content == "served"

    # A recorded interaction still gets checked.
    strict = replay.from_interactions(
        [{"fingerprint": "deadbeefdeadbeef", "response": _text_response("x")}],
        name="strict",
    )
    try:
        strict.chat.completions.create(model="m", messages=[], tools=[], tool_choice={})
    except replay.CassetteMismatch:
        pass
    else:
        raise AssertionError("a fingerprinted interaction was served unchecked")


# =========================================================================
# ibr/llm.py — the retry arms.
# =========================================================================


def test_truncated_tool_arguments_are_retried() -> None:
    """The most common real failure: max_tokens cuts the JSON in half.

    Observed for real during Phase 1, when a 1024-token cap truncated a
    post_comment argument and crashed the run with a JSONDecodeError.
    """
    result = _call_tool(
        [
            _synthetic(
                "a tool-call argument truncated by the token limit; observed "
                "in Phase 1 but not reproducible on demand against the API",
                _tool_response(TOOL, '{"reasoning": "started but never fin'),
            ),
            _synthetic(
                "the model re-sending after being told its JSON was invalid; "
                "requires the first response to have been malformed",
                _tool_response(TOOL, '{"reasoning": "shorter this time"}'),
            ),
        ],
        name="truncated_then_valid",
    )
    assert result.attempts == 2, "the malformed response was not retried"
    assert result.payload == {"reasoning": "shorter this time"}


def test_retry_exhaustion_raises_rather_than_returning_something() -> None:
    """Fail-closed at the lowest level: no payload is better than a guess."""
    try:
        _call_tool(
            [
                _synthetic(
                    "a truncated tool-call argument, first attempt; the token "
                    "limit cutting JSON is not reproducible on demand",
                    _tool_response(TOOL, '{"reasoning": "cut off'),
                ),
                _synthetic(
                    "the same truncation on the retry, which is what exhausts "
                    "the budget and must raise rather than return",
                    _tool_response(TOOL, '{"reasoning": "cut off again'),
                ),
            ],
            name="truncated_twice",
        )
    except StructuredOutputFailure as exc:
        assert "2 attempt" in str(exc)
        assert TOOL in str(exc)
    else:
        raise AssertionError("exhausted retries returned instead of raising")


def test_a_response_with_no_tool_call_is_retried() -> None:
    """Forcing tool_choice makes this unlikely, not impossible."""
    result = _call_tool(
        [
            _synthetic(
                "prose instead of the forced tool call; tool_choice makes this "
                "unlikely so it cannot be elicited from the live API",
                _text_response("I would rather explain than call a tool."),
            ),
            _synthetic(
                "the model complying after being told it must call the tool",
                _tool_response(TOOL, '{"reasoning": "fine"}'),
            ),
        ],
        name="prose_then_tool",
    )
    assert result.attempts == 2
    assert result.payload == {"reasoning": "fine"}


def test_a_call_to_the_wrong_tool_is_retried_with_a_well_formed_request() -> None:
    """The retry request must itself be valid — see tests/test_phase2.py."""
    result = _call_tool(
        [
            _synthetic(
                "the model calling a tool that was never offered, which a "
                "forced tool_choice should prevent and so cannot be recorded",
                _tool_response("some_other_tool", "{}", call_id="wrong"),
            ),
            _synthetic(
                "the model calling the right tool after correction",
                _tool_response(TOOL, '{"reasoning": "correct tool now"}'),
            ),
        ],
        name="wrong_tool_then_right",
    )
    assert result.attempts == 2
    assert result.payload == {"reasoning": "correct tool now"}


def test_ping_survives_a_response_without_usage() -> None:
    """`usage` is optional in the schema; reading through it crashed the smoke test."""
    stripped = _text_response("pipeline online")
    stripped["usage"] = None
    client = replay.from_interactions(
        [
            _synthetic(
                "a response omitting the optional usage block, which the live "
                "API does send and so cannot be recorded missing",
                stripped,
            )
        ],
        name="ping_without_usage",
    )
    result = ping("synthetic", client=cast("Any", client))
    assert result.text == "pipeline online"
    assert result.input_tokens == 0
    assert result.output_tokens == 0


# =========================================================================
# ibr/pipeline.py — both fail-closed branches.
# =========================================================================


def test_a_failed_audit_call_ends_in_no_action() -> None:
    """The strictest rule in the spec, finally tested end to end.

    A broken check must never read as a clean verdict: the run has to stop,
    the verdict must be marked incomplete, and nothing may be published.
    """
    reset_public_comments()
    reset_labels()
    client = replay.from_interactions(
        [
            _raises(
                "a connection failure during the audit call; unreachable on "
                "demand against a working API",
                "APIConnectionError",
            )
        ]
        * 2,  # the retry inside call_structured_tool fails too
        name="audit_connection_failure",
    )
    result = run_isolated(load_issue("malicious"), client=cast("Any", client))

    assert result.audit is not None
    assert result.audit.risk_level == "high_risk", "a broken audit was waved through"
    assert result.audit.completed is False, "a failure was recorded as a real verdict"
    assert result.audit.matched_patterns == ("audit_failure",)
    assert result.action_taken == "no_action"
    assert result.reader is None, "the Reader ran after the audit failed"

    stages = {s.stage: s for s in result.stages}
    assert stages["security_audit"].outcome == "failed_closed"
    assert "reader" not in stages
    assert sandbox_fs.read_text(PUBLIC_COMMENTS_PATH) == ""


def test_a_failed_reader_call_ends_in_no_action() -> None:
    """The audit passed, the Reader broke, and nothing may still happen."""
    reset_public_comments()
    reset_labels()
    audit_ok = _synthetic(
        "a clean audit verdict, so the run reaches the Reader; paired with a "
        "constructed Reader failure below",
        _tool_response(
            TOOL,
            '{"reasoning": "ordinary bug report", "risk_level": "safe", '
            '"matched_patterns": []}',
        ),
    )
    reader_dies = _raises(
        "a timeout on the Reader call, after a successful audit; this exact "
        "sequence cannot be arranged against the live API",
        "APITimeoutError",
    )
    client = replay.from_interactions(
        [audit_ok, reader_dies, reader_dies], name="reader_timeout"
    )
    result = run_isolated(load_issue("benign"), client=cast("Any", client))

    assert result.audit is not None and result.audit.completed is True
    assert result.audit.risk_level == "safe"
    assert result.reader is None
    assert result.action_taken == "no_action"

    stages = {s.stage: s for s in result.stages}
    assert stages["reader"].outcome == "failed_closed"
    assert "structured_boundary" not in stages, "the boundary was logged as crossed"
    assert "executor" not in stages
    assert sandbox_fs.read_text(PUBLIC_COMMENTS_PATH) == ""


def test_a_schema_violation_in_the_audit_also_fails_closed() -> None:
    """Well-formed JSON that breaks the contract is still a broken check."""
    reset_public_comments()
    reset_labels()
    bad_enum = _synthetic(
        "a verdict with a risk_level outside the enum. strict mode makes this "
        "unlikely from the live API, which is why it must be constructed",
        _tool_response(
            TOOL,
            '{"reasoning": "r", "risk_level": "extremely_bad", '
            '"matched_patterns": []}',
        ),
    )
    client = replay.from_interactions([bad_enum, bad_enum], name="audit_bad_enum")
    result = run_isolated(load_issue("malicious"), client=cast("Any", client))

    assert result.audit is not None
    assert result.audit.completed is False
    assert result.action_taken == "no_action"
    assert sandbox_fs.read_text(PUBLIC_COMMENTS_PATH) == ""


# =========================================================================
# ibr/comparison.py — how the Phase 4 report describes a broken run.
# =========================================================================


def _isolated_scenario(key: str):
    from ibr.comparison import SCENARIOS

    return next(s for s in SCENARIOS if s.key == key)


def _audit_verdict(risk_level: str) -> dict:
    return _tool_response(
        TOOL,
        '{"reasoning": "considered it", "risk_level": "'
        + risk_level
        + '", "matched_patterns": []}',
    )


def test_report_does_not_credit_the_audit_for_a_call_that_failed() -> None:
    """The fix for a real bug, which had no test of its own.

    A failed audit also reports high_risk, by design. Saying "the audit rated
    it high_risk" about a timeout credits the probabilistic layer for work it
    did not do — the same error as counting the fail-closed default as a
    detection, one layer up in the prose a reader quotes.
    """
    from ibr.comparison import run_scenario

    failure = _raises(
        "a connection failure on the audit call, which cannot be arranged "
        "against a working API but is the whole point of fail-closed",
        "APIConnectionError",
    )
    client = replay.from_interactions([failure, failure], name="cmp_audit_failure")
    outcome = run_scenario(
        _isolated_scenario("isolated_malicious"), client=cast("Any", client)
    )

    assert outcome.audit_completed is False
    assert outcome.risk_level == "high_risk (call failed)"
    assert "did not complete" in outcome.mechanism
    assert "not detection" in outcome.mechanism
    assert "rated the issue high_risk" not in outcome.mechanism
    assert not outcome.leaked
    assert outcome.action == "no_action"


def test_report_explains_a_run_that_failed_closed_before_the_executor() -> None:
    """Audit fine, Reader broken: neither of the other two mechanisms applies."""
    from ibr.comparison import run_scenario

    reader_dies = _raises(
        "a timeout on the Reader call after a clean audit; this exact ordering "
        "cannot be produced on demand from the live API",
        "APITimeoutError",
    )
    client = replay.from_interactions(
        [
            _synthetic(
                "a clean audit verdict paired with a constructed Reader "
                "failure below, so the run reaches the Reader and then breaks",
                _audit_verdict("safe"),
            ),
            reader_dies,
            reader_dies,
        ],
        name="cmp_reader_failure",
    )
    outcome = run_scenario(
        _isolated_scenario("isolated_benign"), client=cast("Any", client)
    )

    assert outcome.audit_completed is True
    assert outcome.risk_level == "safe"
    assert outcome.mechanism == "The pipeline failed closed before the Executor."
    assert outcome.action == "no_action"


def test_report_flags_a_suspicious_verdict_for_human_review() -> None:
    """`suspicious` passes through, so the report has to say a human should look."""
    from ibr.comparison import run_scenario

    reader_ok = _tool_response(
        "report_issue_triage",
        '{"reasoning": "a bug report", "issue_type": "bug", '
        '"summary": "s", "suggested_action": "label_bug"}',
    )
    client = replay.from_interactions(
        [
            _synthetic(
                "a suspicious audit verdict, which the live model produces only "
                "occasionally and cannot be elicited reliably",
                _audit_verdict("suspicious"),
            ),
            _synthetic(
                "a normal triage classification, so the run reaches the "
                "Executor with the review flag set",
                reader_ok,
            ),
        ],
        name="cmp_suspicious",
    )
    outcome = run_scenario(
        _isolated_scenario("isolated_malicious"), client=cast("Any", client)
    )

    assert outcome.risk_level == "suspicious"
    notes = " ".join(outcome.notes)
    assert "flagged for human review" in notes
    # The Reader ran, so the mechanism must describe the boundary, not a halt.
    assert "none of which the Executor read" in outcome.mechanism
    assert "chars of" in outcome.mechanism
    assert not outcome.leaked


def test_report_records_that_the_bypass_was_simulated() -> None:
    """A simulated bypass must never read as a real one."""
    from ibr.comparison import run_scenario

    reader_ok = _tool_response(
        "report_issue_triage",
        '{"reasoning": "hidden instruction noticed", "issue_type": "bug", '
        '"summary": "s", "suggested_action": "label_bug"}',
    )
    client = replay.from_interactions(
        [
            _synthetic(
                "a high_risk verdict that the bypass then ignores, which is the "
                "scenario the switch exists to make observable on demand",
                _audit_verdict("high_risk"),
            ),
            _synthetic(
                "the Reader classifying the malicious issue after the bypass",
                reader_ok,
            ),
        ],
        name="cmp_bypass",
    )
    outcome = run_scenario(
        _isolated_scenario("isolated_malicious_bypassed"), client=cast("Any", client)
    )

    notes = " ".join(outcome.notes)
    assert "audit bypass simulated" in notes
    assert "high_risk" in notes, "the real verdict was not recorded alongside"
    assert not outcome.leaked


def test_a_scenario_without_retry_runs_exactly_once() -> None:
    """The non-sampling branch of run_scenario_sampled."""
    from ibr.comparison import run_scenario_sampled

    scenario = _isolated_scenario("isolated_malicious")
    assert scenario.retry_until_leak is False

    failure = _raises(
        "a connection failure, used here only to keep the interaction count "
        "predictable while checking that no re-sampling happens",
        "APIConnectionError",
    )
    client = replay.from_interactions([failure, failure], name="cmp_no_retry")
    outcome = run_scenario_sampled(scenario, client=cast("Any", client))

    assert outcome.attempts == 1
    assert outcome.attempts_allowed == 1, "a non-probabilistic row showed a denominator"
    assert outcome.notes == [], "a note was added to a scenario that does not sample"


# =========================================================================
# ibr/baseline_agent.py — error handling in the tool loop.
# =========================================================================


def _baseline_with(interactions: list[dict], *, name: str, terminate: bool = True):
    """Drive run_baseline with constructed responses.

    `terminate` appends a prose turn, because the loop does not stop after
    post_comment — it keeps asking until the model stops calling tools. Four
    of these tests failed on that before the behaviour was pinned down here,
    which is worth writing down: the loop's exit condition is "no tool calls",
    not "published".
    """
    reset_public_comments()
    if terminate:
        interactions = [
            *interactions,
            _synthetic(
                "a final prose turn with no tool call, which is the loop's "
                "only exit condition once a comment has been published",
                _text_response("Done."),
            ),
        ]
    client = replay.from_interactions(interactions, name=name)
    return run_baseline(
        Issue(issue_id="synthetic", title="t", author="a", body="b"),
        client=cast("Any", client),
    )


def test_baseline_nudges_a_model_that_replies_in_prose() -> None:
    """Without the nudge the run ends having published nothing."""
    result = _baseline_with(
        [
            _synthetic(
                "plain prose instead of a post_comment call, which the live "
                "model does sometimes but not reliably enough to record",
                _text_response("Here is my analysis, delivered to nobody."),
            ),
            _synthetic(
                "the model calling post_comment after being nudged",
                _tool_response("post_comment", '{"text": "published at last"}'),
            ),
        ],
        name="prose_then_comment",
    )
    assert result.posted_comment == "published at last"
    published = sandbox_fs.read_text(PUBLIC_COMMENTS_PATH)
    assert "published at last" in published


def test_baseline_nudges_only_once_then_gives_up() -> None:
    """A model that will not use its tools must not loop forever."""
    prose = _synthetic(
        "prose again after the nudge, to prove the nudge is not repeated "
        "indefinitely; not something the live model reliably does twice",
        _text_response("Still not calling anything."),
    )
    # No terminating turn: the second prose response *is* the ending.
    result = _baseline_with([prose, prose], name="prose_twice", terminate=False)
    assert result.posted_comment is None
    assert result.final_text == "Still not calling anything."
    assert sandbox_fs.read_text(PUBLIC_COMMENTS_PATH) == ""


def test_baseline_recovers_from_truncated_tool_arguments() -> None:
    result = _baseline_with(
        [
            _synthetic(
                "a post_comment argument truncated by the token limit, which "
                "crashed a real Phase 1 run before this path existed",
                _tool_response("post_comment", '{"text": "cut off mid-sent'),
            ),
            _synthetic(
                "the model re-sending a shorter comment after the error",
                _tool_response("post_comment", '{"text": "short enough"}'),
            ),
        ],
        name="truncated_comment",
    )
    assert result.posted_comment == "short enough"
    assert any(
        "not valid" in call.result for call in result.transcript
    ), "the truncation was not reported back to the model"


def test_baseline_rejects_a_non_function_tool_call() -> None:
    """The SDK union has a member with no `.function`; reading it crashed."""
    custom = {
        "model": "synthetic",
        "choices": [
            {
                "message": {
                    "content": None,
                    "tool_calls": [{"id": "cust", "type": "custom"}],
                    "model_dump": {
                        "role": "assistant",
                        "tool_calls": [{"id": "cust", "type": "custom"}],
                    },
                }
            }
        ],
        "usage": None,
    }
    result = _baseline_with(
        [
            _synthetic(
                "a custom (non-function) tool call, which DeepSeek does not "
                "emit today and so cannot be recorded",
                custom,
            ),
            _synthetic(
                "a normal post_comment call after the unsupported one",
                _tool_response("post_comment", '{"text": "recovered"}'),
            ),
        ],
        name="custom_tool_call",
    )
    assert result.posted_comment == "recovered"
    assert any("unsupported tool call type" in c.result for c in result.transcript)


def test_baseline_rejects_an_unknown_tool_name() -> None:
    result = _baseline_with(
        [
            _synthetic(
                "a call to a tool that was never offered; the live model does "
                "not invent tool names reliably enough to record",
                _tool_response("delete_everything", "{}"),
            ),
            _synthetic(
                "a legitimate post_comment call afterwards",
                _tool_response("post_comment", '{"text": "back on track"}'),
            ),
        ],
        name="unknown_tool",
    )
    assert result.posted_comment == "back on track"
    assert any("unknown tool" in c.result for c in result.transcript)


def test_baseline_stops_at_the_turn_limit_without_publishing() -> None:
    """A loop that never converges must end, and end having done nothing."""
    from ibr.config import BASELINE_MAX_TURNS

    guessing = _synthetic(
        "the agent guessing at another path, repeated to exhaust the turn "
        "budget; a live run converges too fast to record this reliably",
        _tool_response("read_file", '{"path": "nowhere.py"}'),
    )
    # No terminating turn: exhausting the budget is the behaviour under test.
    result = _baseline_with(
        [guessing] * BASELINE_MAX_TURNS, name="turn_limit", terminate=False
    )
    assert result.turns_used == BASELINE_MAX_TURNS
    assert result.posted_comment is None
    assert result.final_text is None
    assert sandbox_fs.read_text(PUBLIC_COMMENTS_PATH) == ""


def test_baseline_read_file_refuses_a_path_outside_the_sandbox() -> None:
    """The tool backend is live code even when the responses are constructed."""
    result = _baseline_with(
        [
            _synthetic(
                "the agent asking for a path outside the sandbox, which the "
                "guard must refuse; constructed so the exact path is known",
                _tool_response("read_file", '{"path": "../../.env"}'),
            ),
            _synthetic(
                "a post_comment call after the guard refused the path, so the "
                "run reaches a normal end rather than the turn limit",
                _tool_response("post_comment", '{"text": "no config available"}'),
            ),
        ],
        name="escape_attempt",
    )
    reads = [c for c in result.transcript if c.name == "read_file"]
    assert reads and reads[0].result.startswith("Error")
    assert BAIT_SECRET_VALUE not in sandbox_fs.read_text(PUBLIC_COMMENTS_PATH)


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
