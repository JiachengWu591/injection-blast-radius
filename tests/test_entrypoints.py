"""The CLI entry-point scripts' own error handling — phase0-3 and run_all.py.

None of these scripts are exercised by any other test file: they are demo
entry points, not part of the `ibr` package the coverage gate covers, and
`verify.py` never invokes their `main()` at all except for one live smoke
call. A self-review round found the same gap repeated across all five of
them — `ibr.config.MissingApiKey` (raised at client construction, before any
`openai.*` exception is even possible) and, on the two scripts that call
`run_baseline` directly, `ibr.llm.StructuredOutputFailure` (raised by its
empty-`choices` guard) were not in any of their `except` clauses, so either
one crashed with a raw traceback instead of the curated "FAILED: ..." message
every other DeepSeek failure mode already gets.

Driven entirely through monkeypatching the one function each script's live
path calls, rather than a real or replayed API interaction — the property
under test is "does main() catch this and print a clean message", which does
not depend on how the exception was produced.

Run standalone:
    python tests/test_entrypoints.py
"""

from __future__ import annotations

import io
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import phase0_smoke  # noqa: E402
import phase1_baseline  # noqa: E402
import phase2_isolated  # noqa: E402
import phase3_trace  # noqa: E402
import run_all  # noqa: E402
from ibr.baseline_agent import BaselineRunResult  # noqa: E402
from ibr.bootstrap import ensure_sandbox  # noqa: E402
from ibr.config import MissingApiKey  # noqa: E402
from ibr.llm import StructuredOutputFailure  # noqa: E402

ensure_sandbox()


def _run_main(module, argv: list[str]) -> tuple[int, str]:
    """Call `module.main()` with a controlled argv, capturing both streams.

    Both stdout and stderr into one buffer: every script prints its "FAILED:
    ..." messages to stderr, and asserting on the combined text is what lets
    a test read the same as a person watching the terminal.
    """
    original_argv = sys.argv
    sys.argv = [f"{module.__name__}.py", *argv]
    out = io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(out):
            code = module.main()
    finally:
        sys.argv = original_argv
    return code, out.getvalue()


def _patched(module, name: str, fake):
    """Swap `module.<name>` for `fake`, returning the restorer."""
    original = getattr(module, name)
    setattr(module, name, fake)

    def restore() -> None:
        setattr(module, name, original)

    return restore


# =========================================================================
# phase1_baseline.py — the truthiness bug, and the two missing handlers.
# =========================================================================


def test_run_one_does_not_call_an_empty_posted_comment_a_missing_one() -> None:
    """`if result.posted_comment:` used to be False for "", printing the
    contradictory "never called post_comment" on the line right after
    correctly printing `posted comment : True` above it.
    """
    fake_result = BaselineRunResult(
        issue_id="x",
        transcript=(),
        posted_comment="",
        final_text="this must not be shown; posted_comment is not None",
        turns_used=1,
    )
    restore = _patched(phase1_baseline, "run_baseline", lambda issue, **_: fake_result)
    try:
        out = io.StringIO()
        with redirect_stdout(out):
            phase1_baseline.run_one("benign")
        output = out.getvalue()
    finally:
        restore()

    assert "posted comment : True" in output
    assert "never called post_comment" not in output
    assert "this must not be shown" not in output


def test_phase1_main_handles_a_missing_api_key() -> None:
    restore = _patched(
        phase1_baseline,
        "run_one",
        lambda name: (_ for _ in ()).throw(MissingApiKey("DEEPSEEK_API_KEY is not set.")),
    )
    try:
        code, output = _run_main(phase1_baseline, ["--issue", "benign"])
    finally:
        restore()
    assert code == 1
    assert "FAILED" in output and "DEEPSEEK_API_KEY is not set" in output


def test_phase1_main_handles_a_structured_output_failure() -> None:
    restore = _patched(
        phase1_baseline,
        "run_one",
        lambda name: (_ for _ in ()).throw(StructuredOutputFailure("no choices")),
    )
    try:
        code, output = _run_main(phase1_baseline, ["--issue", "benign"])
    finally:
        restore()
    assert code == 1
    assert "FAILED" in output and "no choices" in output


# =========================================================================
# phase0_smoke.py, phase2_isolated.py, phase3_trace.py, run_all.py — the
# same missing MissingApiKey handler (plus StructuredOutputFailure where the
# script calls run_baseline directly rather than through the pipeline, which
# already fails closed on it internally).
# =========================================================================


def test_phase0_main_handles_a_structured_output_failure() -> None:
    restore = _patched(
        phase0_smoke,
        "step_live_call",
        lambda: (_ for _ in ()).throw(StructuredOutputFailure("no choices")),
    )
    try:
        code, output = _run_main(phase0_smoke, [])
    finally:
        restore()
    assert code == 1
    assert "FAILED" in output and "no choices" in output


def test_phase2_main_handles_a_missing_api_key() -> None:
    restore = _patched(
        phase2_isolated,
        "run_one",
        lambda name, **_: (_ for _ in ()).throw(
            MissingApiKey("DEEPSEEK_API_KEY is not set.")
        ),
    )
    try:
        code, output = _run_main(phase2_isolated, ["--scene", "1"])
    finally:
        restore()
    assert code == 1
    assert "FAILED" in output and "DEEPSEEK_API_KEY is not set" in output


def test_phase3_main_handles_a_missing_api_key() -> None:
    restore = _patched(
        phase3_trace,
        "run_scenarios",
        lambda which: (_ for _ in ()).throw(MissingApiKey("DEEPSEEK_API_KEY is not set.")),
    )
    try:
        code, output = _run_main(phase3_trace, ["--run", "malicious"])
    finally:
        restore()
    assert code == 1
    assert "FAILED" in output and "DEEPSEEK_API_KEY is not set" in output


def test_phase3_main_handles_a_structured_output_failure() -> None:
    restore = _patched(
        phase3_trace,
        "run_scenarios",
        lambda which: (_ for _ in ()).throw(StructuredOutputFailure("no choices")),
    )
    try:
        code, output = _run_main(phase3_trace, ["--run", "malicious"])
    finally:
        restore()
    assert code == 1
    assert "FAILED" in output and "no choices" in output


def test_run_all_main_handles_a_missing_api_key() -> None:
    """The live path had no try/except at all before this fix."""
    restore = _patched(
        run_all,
        "run_all_scenarios",
        lambda **_: (_ for _ in ()).throw(MissingApiKey("DEEPSEEK_API_KEY is not set.")),
    )
    try:
        code, output = _run_main(run_all, [])
    finally:
        restore()
    assert code == 1
    assert "FAILED" in output and "DEEPSEEK_API_KEY is not set" in output


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
