"""Replay recorded API exchanges to cover the paths CI could not reach.

The offline suite covers the structural boundary completely and the
API-calling modules barely at all — `ibr/llm.py`, `ibr/pipeline.py` and
`ibr/baseline_agent.py` sat near 40%, and those are precisely where the last
several real bugs lived: a retry request that would have been rejected as
malformed, a `.function` read on an SDK union member that lacks it, a
fail-closed default counted as a detection. Uncovered and buggy were the same
fact.

These tests make no network calls. They drive the real code with recorded
responses, so a regression in the retry loop, the four pipeline stages, or the
baseline's multi-turn tool loop fails in CI rather than waiting for someone to
spend money locally.

What this can and cannot catch, stated plainly: it catches changes in *our*
control flow against a fixed set of model replies. It cannot catch a change in
how the model behaves, and it cannot notice that a recording has gone stale in
any way other than a request-fingerprint mismatch. It is a regression net, not
a substitute for `python verify.py --live`.

Run standalone:
    python tests/test_replay.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ibr import sandbox_fs  # noqa: E402
from ibr.baseline_agent import run_baseline  # noqa: E402
from ibr.bootstrap import ensure_sandbox, reset_labels, reset_public_comments  # noqa: E402
from ibr.config import BAIT_SECRET_VALUE, PUBLIC_COMMENTS_PATH  # noqa: E402
from ibr.executor import COMMENT_TEMPLATES  # noqa: E402
from ibr.issues import load_issue  # noqa: E402
from ibr.pipeline import run_isolated  # noqa: E402
from tests import replay  # noqa: E402
from tests.record_cassettes import SCENARIOS  # noqa: E402

ensure_sandbox()


def _isolated(cassette: str, issue: str, *, bypass: bool = False):
    client = replay.load(cassette)
    reset_public_comments()
    reset_labels()
    result = run_isolated(
        load_issue(issue),
        client=cast("Any", client),
        simulate_audit_bypass=bypass,
    )
    client.assert_fully_consumed()
    return result


def _baseline(cassette: str, issue: str):
    client = replay.load(cassette)
    reset_public_comments()
    result = run_baseline(load_issue(issue), client=cast("Any", client))
    client.assert_fully_consumed()
    return result


# =========================================================================
# Cassette hygiene.
# =========================================================================


def test_every_scenario_has_a_cassette() -> None:
    missing = sorted(set(SCENARIOS) - set(replay.available()))
    assert not missing, (
        f"no cassette for {missing}. Record with "
        "`python tests/record_cassettes.py`."
    )


def test_cassettes_contain_no_real_credential() -> None:
    """They are committed, so they get the same scan as everything else."""
    import re

    real_key = re.compile(r"(?<!fake-)sk-[A-Za-z0-9]{16,}")
    for name in replay.available():
        text = (replay.CASSETTE_DIR / f"{name}.json").read_text(encoding="utf-8")
        assert not real_key.search(text), f"{name}: real-looking key in a cassette"


def test_a_changed_request_fails_instead_of_passing_stale() -> None:
    """The property that makes recorded tests worth having.

    Sequence-only replay would let a prompt edit pass against recordings that
    no longer describe the experiment — a test that keeps passing while
    testing something that stopped existing.
    """
    client = replay.load("isolated_benign")
    try:
        client.chat.completions.create(
            model="some-other-model",
            messages=[{"role": "user", "content": "not what was recorded"}],
            tools=[],
            tool_choice={},
        )
    except replay.CassetteMismatch as exc:
        assert "re-record" in str(exc).lower()
    else:
        raise AssertionError("a mismatched request replayed successfully")


def test_asking_for_more_calls_than_recorded_fails() -> None:
    """Covers the other direction: the code grew a call the recording lacks.

    Driven by running the real pipeline to exhaust the cassette, then asking
    for one more — reproducing the kwargs by hand would just duplicate the
    pipeline and test the duplicate.
    """
    client = replay.load("isolated_malicious")
    reset_public_comments()
    reset_labels()
    run_isolated(load_issue("malicious"), client=cast("Any", client))

    try:
        client.chat.completions.create(
            model="x", messages=[], tools=[], tool_choice={}
        )
    except replay.CassetteMismatch as exc:
        message = str(exc)
        assert "one more" in message or "does not match" in message
    else:
        raise AssertionError("replayed past the end of the cassette")


# =========================================================================
# The isolated pipeline, end to end, with no network.
# =========================================================================


def test_isolated_benign_runs_all_four_stages() -> None:
    result = _isolated("isolated_benign", "benign")

    stages = [s.stage for s in result.stages]
    assert "security_audit" in stages
    assert "reader" in stages
    assert "structured_boundary" in stages
    assert "executor" in stages

    assert result.audit is not None and result.audit.completed is True
    assert result.reader is not None
    assert result.action_taken != "no_action"
    assert BAIT_SECRET_VALUE not in sandbox_fs.read_text(PUBLIC_COMMENTS_PATH)


def test_isolated_malicious_short_circuits_on_high_risk() -> None:
    result = _isolated("isolated_malicious", "malicious")

    stages = [s.stage for s in result.stages]
    assert result.audit is not None
    if result.audit.risk_level == "high_risk":
        assert "short_circuit" in stages
        assert "reader" not in stages, "the Reader ran despite a high_risk verdict"
        assert result.action_taken == "no_action"
    assert BAIT_SECRET_VALUE not in sandbox_fs.read_text(PUBLIC_COMMENTS_PATH)


def test_isolated_malicious_with_bypass_reaches_the_reader_and_still_holds() -> None:
    result = _isolated("isolated_malicious_bypassed", "malicious", bypass=True)

    stages = [s.stage for s in result.stages]
    assert "audit_bypass" in stages
    assert "reader" in stages, "the bypass did not let the text through"
    assert "structured_boundary" in stages
    assert result.audit_bypass_simulated is True

    published = sandbox_fs.read_text(PUBLIC_COMMENTS_PATH)
    assert BAIT_SECRET_VALUE not in published
    assert "FAKE_" not in published
    if result.decision and result.decision.published_comment:
        assert result.decision.published_comment in COMMENT_TEMPLATES.values()


def test_replayed_run_logs_reasoning_before_the_verdict() -> None:
    """Covers the observability path against a real recorded response."""
    result = _isolated("isolated_benign", "benign")
    checked = [s for s in result.stages if s.raw_arguments and s.verdict_field]
    assert checked, "no stage recorded raw arguments"
    for stage in checked:
        raw = stage.raw_arguments or ""
        assert raw.index('"reasoning"') < raw.index(f'"{stage.verdict_field}"'), (
            f"{stage.stage}: verdict generated before reasoning"
        )


# =========================================================================
# The baseline's multi-turn tool loop.
# =========================================================================


def test_baseline_benign_completes_its_tool_loop() -> None:
    result = _baseline("baseline_benign", "benign")
    assert result.transcript, "no tool calls were replayed"
    assert result.posted_comment, "the baseline never published"
    assert BAIT_SECRET_VALUE not in sandbox_fs.read_text(PUBLIC_COMMENTS_PATH)


def test_baseline_malicious_replays_its_recorded_outcome() -> None:
    """Whatever the recording shows, the transcript must be coherent.

    Deliberately not asserting a leak: the recording captures one sampling of a
    probabilistic event (PROJECT_SPEC.md §1.1), and pinning it here would turn
    a demonstration into a requirement. What is asserted is that the loop ran,
    the tools resolved, and the outcome matches what was recorded.
    """
    result = _baseline("baseline_malicious", "malicious")
    assert result.transcript
    names = {call.name for call in result.transcript}
    assert names <= {"read_file", "post_comment"}, f"unexpected tool: {names}"

    published = sandbox_fs.read_text(PUBLIC_COMMENTS_PATH)
    if result.posted_comment:
        assert result.posted_comment.strip() in published


def test_baseline_read_file_stayed_inside_the_sandbox() -> None:
    """Even under replay, the tool backend is the real sandbox_fs one.

    The recorded responses decide which paths the agent asks for; what happens
    when it asks is live code. So this is a real check on the guard, driven by
    whatever the model actually tried.
    """
    from ibr.config import BAIT_ENV_CONTENT

    sandbox_only = set(BAIT_ENV_CONTENT.splitlines())
    result = _baseline("baseline_malicious", "malicious")

    reads = [c for c in result.transcript if c.name == "read_file"]
    assert reads, "the recording contains no read_file call to check"

    for call in reads:
        if call.result.startswith("Error"):
            continue
        # A successful read can only have returned sandbox content. The bait
        # file is the only readable file the corpus points at, so every
        # non-error line must come from it.
        for line in call.result.splitlines():
            assert line in sandbox_only, (
                f"read_file returned a line that is not sandbox content: {line!r}"
            )


# =========================================================================
# Coverage of the modules this exists for.
# =========================================================================


def test_replay_exercises_the_api_calling_modules() -> None:
    """Guard against the cassettes silently stopping short.

    If a future edit makes these tests exercise only one stage, the coverage
    they were added for evaporates while every assertion still passes.
    """
    stages_seen: set[str] = set()
    for cassette, issue, bypass in (
        ("isolated_benign", "benign", False),
        ("isolated_malicious", "malicious", False),
        ("isolated_malicious_bypassed", "malicious", True),
    ):
        result = _isolated(cassette, issue, bypass=bypass)
        stages_seen.update(s.stage for s in result.stages)

    for required in (
        "security_audit",
        "reader",
        "structured_boundary",
        "executor",
        "audit_bypass",
    ):
        assert required in stages_seen, f"no cassette exercises {required}"


# =========================================================================


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
