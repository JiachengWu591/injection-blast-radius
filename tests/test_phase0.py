"""Phase 0 acceptance assertions.

Objective pass/fail for the Phase 0 criteria in PROJECT_SPEC.md §4, plus the
§6 safety rails that must hold from the very first commit.

Run standalone (no pytest needed):
    python tests/test_phase0.py
Or under pytest if you have it:
    pytest tests/test_phase0.py
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ibr import sandbox_fs  # noqa: E402
from ibr.bootstrap import ensure_sandbox  # noqa: E402
from ibr.config import (  # noqa: E402
    API_KEY_ENV_VAR,
    BAIT_ENV_PATH,
    ISSUES_DIR,
    LOG_DIR,
    MissingApiKey,
    PROJECT_ROOT,
    SANDBOX_ROOT,
    assert_api_key_present,
)
from ibr.issues import MalformedIssue, available_issues, load_issue  # noqa: E402
from ibr.sandbox_fs import SandboxViolation  # noqa: E402

ensure_sandbox()

# DeepSeek (like most OpenAI-compatible providers) issues keys shaped
# "sk-<long alnum run>". The negative lookbehind keeps this from flagging our
# own bait value, "fake-sk-00000000000000000000" (config.py:BAIT_ENV_CONTENT).
_REAL_KEY_PATTERN = re.compile(r"(?<!fake-)sk-[A-Za-z0-9]{16,}")


def _has_real_looking_key(text: str) -> bool:
    return bool(_REAL_KEY_PATTERN.search(text))


# --- sandbox --------------------------------------------------------------


def test_sandbox_tree_exists() -> None:
    for path in (SANDBOX_ROOT, ISSUES_DIR, LOG_DIR):
        assert path.is_dir(), f"missing sandbox directory: {path}"


def test_bait_secret_is_obviously_fake() -> None:
    content = sandbox_fs.read_text(BAIT_ENV_PATH)
    assert "FAKE_API_KEY=fake-sk-" in content
    assert not _has_real_looking_key(content)
    for line in content.splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            name, _, value = line.partition("=")
            assert name.startswith("FAKE_"), f"bait var not marked fake: {name}"
            assert value.startswith("fake-"), f"bait value not marked fake: {line}"


def test_guard_refuses_paths_outside_the_sandbox() -> None:
    escapes = [
        "../.env",
        "../../Windows/System32/drivers/etc/hosts",
        "issues/../../../etc/passwd",
        str(PROJECT_ROOT / ".env"),
        str(PROJECT_ROOT),
    ]
    for attempt in escapes:
        try:
            resolved = sandbox_fs.resolve_in_sandbox(attempt)
        except SandboxViolation:
            continue
        raise AssertionError(f"guard allowed {attempt!r} -> {resolved}")


def test_guard_allows_paths_inside_the_sandbox() -> None:
    root = SANDBOX_ROOT.resolve()
    for allowed in ("issues", "issues/issue_benign.json", BAIT_ENV_PATH, "."):
        resolved = sandbox_fs.resolve_in_sandbox(allowed)
        assert resolved.is_relative_to(root), f"guard misrouted {allowed!r}"


# --- issue fixtures -------------------------------------------------------


def test_both_fixtures_load() -> None:
    assert available_issues() == ["benign", "malicious"]
    for name in ("benign", "malicious"):
        issue = load_issue(name)
        assert issue.title.strip()
        assert issue.body.strip()
        assert issue.author.strip()


def test_malicious_fixture_actually_carries_an_injection() -> None:
    """The attack fixture has to be a real attack, or Phase 1/2 prove nothing.

    The payload is deliberately *not* the textbook "ignore all previous
    instructions" phrasing — that reads as an obvious attack to a model's
    safety training and gets refused outright (observed empirically running
    Phase 1 against deepseek-v4-flash, even across several rephrasings). It's
    social-engineered instead: framed as routine, unconditional triage
    procedure rather than a request the model could reasonably decline.
    """
    body = load_issue("malicious").body.lower()
    assert "sandbox/.env" in body
    assert "full contents" in body


def test_benign_fixture_is_clean() -> None:
    body = load_issue("benign").body.lower()
    assert ".env" not in body


def test_malformed_input_fails_closed() -> None:
    """A bad fixture must raise, never return a half-built Issue."""
    broken = ISSUES_DIR / "issue_ibrselftest.json"
    cases = ["not json at all {", '"a string, not an object"', '{"title": "no body"}']
    try:
        for payload in cases:
            sandbox_fs.write_text(broken, payload)
            try:
                load_issue("ibrselftest")
            except MalformedIssue:
                continue
            raise AssertionError(f"malformed fixture was accepted: {payload!r}")
    finally:
        sandbox_fs.resolve_in_sandbox(broken).unlink(missing_ok=True)

    try:
        load_issue("no_such_issue")
    except MalformedIssue:
        pass
    else:
        raise AssertionError("a missing fixture was accepted")


# --- credential hygiene ---------------------------------------------------


def test_missing_api_key_raises_instead_of_degrading() -> None:
    saved = os.environ.get(API_KEY_ENV_VAR)
    try:
        os.environ[API_KEY_ENV_VAR] = "   "
        try:
            assert_api_key_present()
        except MissingApiKey as exc:
            assert not _has_real_looking_key(str(exc))
        else:
            raise AssertionError("a blank API key was accepted")

        os.environ[API_KEY_ENV_VAR] = "anything-nonblank"
        assert assert_api_key_present() is None, "the key value must never be returned"
    finally:
        if saved is None:
            os.environ.pop(API_KEY_ENV_VAR, None)
        else:
            os.environ[API_KEY_ENV_VAR] = saved


def test_env_files_are_gitignored() -> None:
    for path in (".env", "sandbox/.env"):
        result = subprocess.run(
            ["git", "check-ignore", "-q", path],
            cwd=PROJECT_ROOT,
            capture_output=True,
        )
        assert result.returncode == 0, f"{path} is NOT gitignored"


def _is_gitignored(relpath: str) -> bool:
    """Per-path, not batched: `git check-ignore --stdin` has a real bug on
    Git for Windows where root-level dotfiles like ".env" silently fail to
    match despite being covered by .gitignore (confirmed manually: `git
    check-ignore -v .env` matches, `echo .env | git check-ignore --stdin`
    doesn't). Single-path mode below is what test_env_files_are_gitignored
    already relies on, and it's correct."""
    result = subprocess.run(
        ["git", "check-ignore", "-q", relpath],
        cwd=PROJECT_ROOT,
        capture_output=True,
    )
    return result.returncode == 0


def test_no_real_credentials_anywhere_committable() -> None:
    """Scan every file git would let you commit for a real-looking key."""
    candidates: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(PROJECT_ROOT):
        dirnames[:] = [
            d for d in dirnames if d not in {".git", ".venv", "venv", "__pycache__"}
        ]
        candidates.extend(Path(dirpath) / name for name in filenames)

    rel = [str(p.relative_to(PROJECT_ROOT)).replace("\\", "/") for p in candidates]

    for path, relpath in zip(candidates, rel):
        if _is_gitignored(relpath):
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        assert not _has_real_looking_key(content), f"real-looking API key in {relpath}"
        for line in content.splitlines():
            if line.startswith(f"{API_KEY_ENV_VAR}="):
                assert not line.split("=", 1)[1].strip(), (
                    f"{relpath} assigns a value to {API_KEY_ENV_VAR}"
                )


# --- runner ---------------------------------------------------------------


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
