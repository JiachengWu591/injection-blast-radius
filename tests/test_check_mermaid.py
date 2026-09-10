"""tools/check_mermaid.py's command-line path handling.

A mistyped or moved filename passed explicitly used to be silently dropped
(`[p for p in paths if p.is_file()]`) and reported as "checked 0 mermaid
block(s) in 0 file(s)" / "no GitHub-incompatible constructs found" with exit
code 0 — a fail-open result in a lint whose entire job is refusing rather
than passing on anything it did not actually check.

Run standalone:
    python tests/test_check_mermaid.py
"""

from __future__ import annotations

import io
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import check_mermaid  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def _run_main(argv: list[str]) -> tuple[int, str]:
    original_argv = sys.argv
    sys.argv = ["check_mermaid.py", *argv]
    out = io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(out):
            code = check_mermaid.main()
    finally:
        sys.argv = original_argv
    return code, out.getvalue()


def test_a_nonexistent_explicit_path_is_an_error_not_a_silent_pass() -> None:
    code, output = _run_main(["ARCHITECTURE-typo-does-not-exist.md"])
    assert code == 1, f"a missing file passed instead of erroring: {output!r}"
    assert "no such file" in output.lower()
    assert "no GitHub-incompatible constructs found" not in output


def test_an_existing_explicit_path_is_still_checked() -> None:
    code, output = _run_main([str(ROOT / "ARCHITECTURE.md")])
    assert code == 0
    assert "in 1 file(s)" in output


def test_a_mix_of_real_and_missing_paths_errors_on_the_missing_one() -> None:
    code, output = _run_main(
        [str(ROOT / "ARCHITECTURE.md"), "does-not-exist-either.md"]
    )
    assert code == 1
    assert "does-not-exist-either.md" in output


def test_no_arguments_still_falls_back_to_every_markdown_file() -> None:
    """The default (no-args) path is unaffected — only explicit paths change."""
    code, output = _run_main([])
    assert code == 0
    assert "file(s)" in output


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
