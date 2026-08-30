"""Phase 3 acceptance assertions (PROJECT_SPEC.md §4, Phase 3).

Structural tests need no API. Live tests run the real pipeline and then check
what the log says about it.

Run standalone:
    python tests/test_phase3.py
    python tests/test_phase3.py --offline
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ibr import sandbox_fs  # noqa: E402
from ibr.bootstrap import ensure_sandbox, reset_labels, reset_public_comments  # noqa: E402
from ibr.config import API_KEY_ENV_VAR, LOG_PATH  # noqa: E402
from ibr.issues import load_issue  # noqa: E402
from ibr.observability import (  # noqa: E402
    LogRecord,
    append_records,
    clear_log,
    group_runs,
    load_records,
    new_run_id,
    reasoning_precedes,
    scrub,
    summarize,
    utc_now,
)
from ibr.pipeline import run_isolated  # noqa: E402

ensure_sandbox()

REQUIRED_FIELDS = (
    "ts",
    "run_id",
    "architecture",
    "issue_id",
    "stage",
    "outcome",
    "duration_ms",
    "input_summary",
    "output_summary",
)


# =========================================================================
# Structural tests — no API calls.
# =========================================================================


def test_reasoning_precedes_reads_generation_order_not_dict_order() -> None:
    ordered = '{"reasoning": "thought about it", "risk_level": "safe"}'
    reversed_ = '{"risk_level": "safe", "reasoning": "thought about it"}'

    assert reasoning_precedes(ordered, "risk_level") is True
    assert reasoning_precedes(reversed_, "risk_level") is False

    # "Unknown" must never be reported as "yes".
    assert reasoning_precedes("", "risk_level") is None
    assert reasoning_precedes('{"risk_level": "safe"}', "risk_level") is None
    assert reasoning_precedes('{"reasoning": "x"}', "risk_level") is None


def test_scrub_removes_the_api_key() -> None:
    saved = os.environ.get(API_KEY_ENV_VAR)
    try:
        os.environ[API_KEY_ENV_VAR] = "sentinel-key-value-do-not-log"
        cleaned = scrub("prefix sentinel-key-value-do-not-log suffix")
        assert "sentinel-key-value-do-not-log" not in cleaned
        assert "<redacted:api-key>" in cleaned

        # An unset key must not turn every string into redaction soup.
        os.environ[API_KEY_ENV_VAR] = ""
        assert scrub("nothing to redact here") == "nothing to redact here"
    finally:
        if saved is None:
            os.environ.pop(API_KEY_ENV_VAR, None)
        else:
            os.environ[API_KEY_ENV_VAR] = saved


def test_log_record_scrubs_on_serialisation() -> None:
    saved = os.environ.get(API_KEY_ENV_VAR)
    try:
        os.environ[API_KEY_ENV_VAR] = "leaky-sentinel-abcdef"
        record = LogRecord(
            ts=utc_now(),
            run_id="test",
            architecture="isolated",
            issue_id="x",
            stage="s",
            outcome="o",
            duration_ms=1.0,
            input_summary="key is leaky-sentinel-abcdef",
            output_summary="also leaky-sentinel-abcdef",
            detail="and leaky-sentinel-abcdef again",
        )
        assert "leaky-sentinel-abcdef" not in record.to_json()
    finally:
        if saved is None:
            os.environ.pop(API_KEY_ENV_VAR, None)
        else:
            os.environ[API_KEY_ENV_VAR] = saved


def test_summarize_collapses_whitespace_and_truncates() -> None:
    assert summarize("a\n\n  b\tc") == "a b c"
    long = "x" * 500
    out = summarize(long, limit=50)
    assert len(out) == 50
    assert out.endswith("…")


def test_round_trip_through_the_log_file() -> None:
    clear_log()
    run_id = new_run_id()
    records = [
        LogRecord(
            ts=utc_now(),
            run_id=run_id,
            architecture="isolated",
            issue_id="round-trip",
            stage=f"stage_{i}",
            outcome="ok",
            duration_ms=float(i),
        )
        for i in range(3)
    ]
    append_records(records)

    loaded = load_records()
    assert len(loaded) == 3
    for entry in loaded:
        for name in REQUIRED_FIELDS:
            assert name in entry, f"log record missing {name!r}"
    assert [e["stage"] for e in loaded] == ["stage_0", "stage_1", "stage_2"]


def test_group_runs_preserves_first_appearance_order() -> None:
    records = [
        {"run_id": "b", "stage": "1"},
        {"run_id": "a", "stage": "2"},
        {"run_id": "b", "stage": "3"},
    ]
    grouped = group_runs(records)
    assert [run_id for run_id, _ in grouped] == ["b", "a"]
    assert [e["stage"] for e in grouped[0][1]] == ["1", "3"]


def test_corrupt_log_line_raises_instead_of_being_skipped() -> None:
    """Fail-closed applies to the log reader too — a skipped line is a lie."""
    clear_log()
    sandbox_fs.append_text(LOG_PATH, '{"run_id": "ok", "stage": "fine"}\n')
    sandbox_fs.append_text(LOG_PATH, "this is not json\n")
    try:
        load_records()
    except ValueError as exc:
        assert "line 2" in str(exc)
    else:
        raise AssertionError("a corrupt log line was silently skipped")
    finally:
        clear_log()


def test_append_records_ignores_empty_batches() -> None:
    clear_log()
    append_records([])
    assert load_records() == []


# =========================================================================
# Live tests — real pipeline runs, then inspect the log.
# =========================================================================


def live_test_malicious_run_is_fully_traced() -> None:
    """The Phase 3 acceptance criterion, checked mechanically."""
    clear_log()
    reset_public_comments()
    reset_labels()
    result = run_isolated(load_issue("malicious"))

    entries = load_records()
    assert entries, "the run produced no log records"
    assert {e["run_id"] for e in entries} == {result.run_id}

    stages = [e["stage"] for e in entries]
    assert "security_audit" in stages

    audit = next(e for e in entries if e["stage"] == "security_audit")
    assert audit["risk_level"] in ("safe", "suspicious", "high_risk")
    assert audit["input_summary"], "the audit stage logged no input summary"
    assert audit["output_summary"], "the audit stage logged no output summary"
    assert audit["duration_ms"] > 0

    # Whichever path the run took, the log has to explain it.
    if audit["risk_level"] == "high_risk":
        assert "short_circuit" in stages
    else:
        assert "reader" in stages and "structured_boundary" in stages


def live_test_log_shows_reasoning_before_the_verdict() -> None:
    """PROJECT_SPEC.md §4 Phase 3 and §8 both require this to be observable."""
    clear_log()
    run_isolated(load_issue("benign"))

    entries = load_records()
    checked = [e for e in entries if e.get("reasoning_first") is not None]
    assert checked, "no stage reported reasoning ordering"
    for entry in checked:
        assert entry["reasoning_first"] is True, (
            f"{entry['stage']}: the verdict was generated before the reasoning"
        )


def live_test_boundary_stage_records_what_was_held_back() -> None:
    clear_log()
    reset_public_comments()
    reset_labels()
    run_isolated(load_issue("malicious"), simulate_audit_bypass=True)

    entries = load_records()
    boundary = [e for e in entries if e["stage"] == "structured_boundary"]
    assert boundary, "the boundary stage was not logged"
    record = boundary[0]
    assert "stay behind" in record["detail"]
    assert "suggested_action=" in record["output_summary"]


def live_test_log_never_contains_the_operator_api_key() -> None:
    """The key is not supposed to reach the log; verify it against a real run."""
    key = os.environ.get(API_KEY_ENV_VAR, "").strip()
    assert key, "DEEPSEEK_API_KEY must be set for this test to mean anything"

    clear_log()
    run_isolated(load_issue("benign"))
    assert key not in sandbox_fs.read_text(LOG_PATH)


def live_test_both_architectures_log_in_the_same_schema() -> None:
    """Phase 4's comparison depends on this."""
    from ibr.baseline_agent import run_baseline

    clear_log()
    reset_public_comments()
    reset_labels()
    run_isolated(load_issue("benign"))
    run_baseline(load_issue("benign"))

    entries = load_records()
    architectures = {e["architecture"] for e in entries}
    assert architectures == {"isolated", "baseline"}
    for entry in entries:
        for name in REQUIRED_FIELDS:
            assert name in entry, f"{entry['architecture']} record missing {name!r}"


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
