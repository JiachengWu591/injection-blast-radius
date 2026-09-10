"""tools/make_comparison_svg.py — four fixes from a self-review round.

None of these need a real or replayed pipeline run: the exception-handling
fixes are tested by monkeypatching `observe()` itself, and the rendering
fixes (`_leaked_lines`, `build_baseline_pane`) are pure functions of an
`Observation`, which is a plain dataclass this file constructs by hand.

Run standalone:
    python tests/test_make_comparison_svg.py
"""

from __future__ import annotations

import io
import sys
import types
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import openai  # noqa: E402

from ibr.config import MissingApiKey  # noqa: E402
from ibr.fixtures import BAIT_SECRET_VALUE  # noqa: E402
from ibr.llm import StructuredOutputFailure  # noqa: E402
from tools import make_comparison_svg  # noqa: E402


def _observation(**overrides) -> make_comparison_svg.Observation:
    base = {
        "baseline_tools": (),
        "baseline_leaked": False,
        "baseline_leaked_lines": (),
        "isolated_audit": "safe",
        "isolated_stages": (),
        "isolated_action": "no_action",
        "isolated_reasoning_chars": 0,
        "isolated_summary_chars": 0,
        "isolated_leaked": False,
        "isolated_surface_empty": True,
    }
    base.update(overrides)
    return make_comparison_svg.Observation(**base)


def _run_main(argv: list[str]) -> tuple[int, str]:
    original_argv = sys.argv
    sys.argv = ["make_comparison_svg.py", *argv]
    out = io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(out):
            code = make_comparison_svg.main()
    finally:
        sys.argv = original_argv
    return code, out.getvalue()


def _run_main_with_observe(fake) -> tuple[int, str]:
    original = make_comparison_svg.observe
    make_comparison_svg.observe = fake
    try:
        return _run_main([])
    finally:
        make_comparison_svg.observe = original


def _fake_auth_error(message: str) -> openai.AuthenticationError:
    """A real AuthenticationError instance, built without a live httpx response.

    httpx is not a direct dependency of this project (openai vendors its own
    transport), so this duck-types the two attributes AuthenticationError's
    constructor actually reads (`response.status_code`, `response.headers`,
    `response.request`) rather than pulling in a package the project has no
    other reason to install.
    """
    fake_response = types.SimpleNamespace(
        request=types.SimpleNamespace(method="POST", url="https://api.deepseek.com"),
        status_code=401,
        headers={},
    )
    return openai.AuthenticationError(message, response=fake_response, body=None)


# =========================================================================
# Fix 1: AuthenticationError must never print its own message.
# =========================================================================


def test_an_authentication_error_never_prints_the_exception_text() -> None:
    """AuthenticationError's message is built from the API's own error body,
    which for a real auth failure conventionally echoes back a fragment of
    the offending key. The single `except openai.APIError` handler used to
    print every subclass's message, including this one.
    """
    secret_looking_fragment = "sk-suspiciously-real-fragment"

    def fake() -> None:
        raise _fake_auth_error(f"Incorrect API key provided: {secret_looking_fragment}")

    code, output = _run_main_with_observe(fake)
    assert code == 1
    assert secret_looking_fragment not in output
    assert "the API key was rejected" in output


def test_a_missing_api_key_prints_the_friendly_message() -> None:
    def fake() -> None:
        raise MissingApiKey("DEEPSEEK_API_KEY is not set. Put it in .env.")

    code, output = _run_main_with_observe(fake)
    assert code == 1
    assert "DEEPSEEK_API_KEY is not set" in output


def test_a_structured_output_failure_prints_a_clean_message_not_a_traceback() -> None:
    def fake() -> None:
        raise StructuredOutputFailure("no valid structured output after retries")

    code, output = _run_main_with_observe(fake)
    assert code == 1
    assert "FAILED" in output
    assert "no valid structured output" in output


def test_other_api_errors_still_print_their_message() -> None:
    """The general handler must still work for every other openai.APIError
    subclass -- only AuthenticationError gets the fixed-string treatment.
    """

    def fake() -> None:
        # mypy does not scan tests/ (mypy.ini's files = ibr), so `request`'s
        # real type (httpx.Request) needs no suppression here -- unlike the
        # equivalent construction in tests/replay.py's _exception_named,
        # which passes `cast("Any", None)` because that helper is exercised
        # from files mypy does scan.
        raise openai.APIConnectionError(request=None)

    code, output = _run_main_with_observe(fake)
    assert code == 1
    assert "APIConnectionError" in output


# =========================================================================
# Fix 2: leaked_lines must agree with the same secret the verdict checks.
# =========================================================================


def test_leaked_lines_matches_the_same_secret_the_verdict_checks() -> None:
    """FAKE_ substring vs BAIT_SECRET_VALUE used to disagree.

    A surface quoting only BAIT_ENV_CONTENT's FAKE_DB_PASSWORD line (no API
    key) used to populate leaked_lines -- it contains "FAKE_" -- while
    baseline_leaked (BAIT_SECRET_VALUE in surface) stayed False: a red
    "leaked" line rendered directly above a banner saying no leak occurred.
    """
    db_password_only = (
        "some reply text\nFAKE_DB_PASSWORD=fake-pw-0000-not-a-real-password\n"
    )
    assert BAIT_SECRET_VALUE not in db_password_only
    assert make_comparison_svg._leaked_lines(db_password_only) == ()

    leaking = f"the key is {BAIT_SECRET_VALUE}\nan unrelated line\n"
    assert make_comparison_svg._leaked_lines(leaking) == (
        f"the key is {BAIT_SECRET_VALUE}",
    )


def test_build_baseline_pane_never_shows_a_leaked_line_when_not_leaked() -> None:
    """End-to-end through the pane: a non-matching leaked_lines must not
    contradict a False baseline_leaked banner.
    """
    obs = _observation(baseline_leaked=False, baseline_leaked_lines=())
    pane = make_comparison_svg.build_baseline_pane(obs)
    texts = [line.text for line in pane.lines]
    assert "no leak this run" in " ".join(texts).lower()
    assert not any("SECRET LEAKED" in t for t in texts)


# =========================================================================
# Fix 3: read_file must render the real argument, not an assumed one.
# =========================================================================


def test_build_baseline_pane_shows_the_real_read_file_argument() -> None:
    obs = _observation(
        baseline_tools=(("read_file", '{"path": "sandbox/config.json"}'),),
    )
    pane = make_comparison_svg.build_baseline_pane(obs)
    lines = [line.text for line in pane.lines]
    assert any("read_file(sandbox/config.json)" in line for line in lines)
    assert not any("read_file(sandbox/.env)" in line for line in lines)


def test_build_baseline_pane_falls_back_gracefully_on_bad_arguments() -> None:
    obs = _observation(baseline_tools=(("read_file", "not valid json"),))
    pane = make_comparison_svg.build_baseline_pane(obs)
    lines = [line.text for line in pane.lines]
    assert any("read_file(?)" in line for line in lines)


# =========================================================================
# Fix 4: --check no longer claims to detect staleness it cannot detect.
# =========================================================================


def test_check_reports_a_leak_regression_not_a_content_diff() -> None:
    make_comparison_svg.OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not make_comparison_svg.OUTPUT_PATH.exists():
        make_comparison_svg.OUTPUT_PATH.write_text("<svg></svg>\n", encoding="utf-8")

    def fake() -> make_comparison_svg.Observation:
        return _observation(isolated_leaked=True)

    original = make_comparison_svg.observe
    make_comparison_svg.observe = fake
    try:
        code, output = _run_main(["--check"])
    finally:
        make_comparison_svg.observe = original

    assert code == 1
    assert "isolated leaked" in output.lower()
    assert "FAILED" in output
    assert "not a staleness finding" in output


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
