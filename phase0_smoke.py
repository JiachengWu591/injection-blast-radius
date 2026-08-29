"""Phase 0 smoke test — the foundation, end to end.

Proves three things, in order:

  1. the sandbox exists and the whitelist guard refuses to look outside it;
  2. the simulated GitHub issues load and print;
  3. the DeepSeek API is actually reachable with the configured model.

Any failure exits non-zero. Nothing here degrades to a mock — a broken step
must stop the run (PROJECT_SPEC.md §1.4).

Usage:
    python phase0_smoke.py
    python phase0_smoke.py --offline    # skip step 3
"""

from __future__ import annotations

import argparse
import sys
import textwrap
import time

import openai

from ibr import sandbox_fs
from ibr.bootstrap import ensure_sandbox
from ibr.config import (
    AUDIT_MODEL,
    BAIT_ENV_PATH,
    MissingApiKey,
    PROJECT_ROOT,
    SANDBOX_ROOT,
)
from ibr.issues import available_issues, load_issue
from ibr.llm import ping
from ibr.sandbox_fs import SandboxViolation

RULE = "─" * 72


def _quote(text: str) -> str:
    """Prefix every line, blank ones included, so quoted blocks stay obvious."""
    return textwrap.indent(text.rstrip(), "  | ", predicate=lambda _line: True)

# Paths that must be rejected by the guard. Kept here rather than only in the
# test suite so that running the smoke test demonstrates the boundary, not just
# asserts it.
ESCAPE_ATTEMPTS = (
    "../.env",
    "../../Windows/System32/drivers/etc/hosts",
    "issues/../../../etc/passwd",
    str(PROJECT_ROOT / ".env"),
)


def _heading(text: str) -> None:
    print(f"\n{RULE}\n{text}\n{RULE}")


def step_sandbox() -> None:
    _heading("1. Sandbox")
    ensure_sandbox()
    print(f"sandbox root : {SANDBOX_ROOT}")
    print(f"bait secret  : {BAIT_ENV_PATH}")
    print(_quote(sandbox_fs.read_text(BAIT_ENV_PATH)))

    print("\nwhitelist guard:")
    for attempt in ESCAPE_ATTEMPTS:
        try:
            resolved = sandbox_fs.resolve_in_sandbox(attempt)
        except SandboxViolation:
            print(f"  refused  {attempt}")
        else:
            raise SystemExit(
                f"FATAL: the sandbox guard allowed {attempt!r} -> {resolved}"
            )
    print(f"  allowed  issues/  ({sandbox_fs.resolve_in_sandbox('issues')})")


def step_issues() -> None:
    _heading("2. Simulated GitHub issues (local files, no GitHub API)")
    names = available_issues()
    if not names:
        raise SystemExit("FATAL: no issue fixtures found under sandbox/issues/")

    for name in names:
        issue = load_issue(name)
        print(f"\n[{name}] #{issue.issue_id} — {issue.title}")
        print(f"  author: {issue.author}")
        print(f"  source: {issue.source_path}")
        print(_quote(issue.body))


def step_live_call() -> None:
    _heading(f"3. Live API call ({AUDIT_MODEL})")
    started = time.perf_counter()
    result = ping(AUDIT_MODEL)
    elapsed_ms = (time.perf_counter() - started) * 1000
    print(f"  model returned : {result.model}")
    print(f"  reply          : {result.text!r}")
    print(f"  tokens         : in={result.input_tokens} out={result.output_tokens}")
    print(f"  latency        : {elapsed_ms:.0f} ms")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--offline",
        action="store_true",
        help="skip the live API call (steps 1 and 2 only)",
    )
    args = parser.parse_args()

    step_sandbox()
    step_issues()

    if args.offline:
        _heading("3. Live API call — SKIPPED (--offline)")
        return 0

    try:
        step_live_call()
    except MissingApiKey as exc:
        print(f"\nFAILED: {exc}", file=sys.stderr)
        return 1
    except openai.NotFoundError as exc:
        print(
            f"\nFAILED: the API rejected model id {AUDIT_MODEL!r} — {exc.message}\n"
            "Change AUDIT_MODEL/READER_MODEL in ibr/config.py.",
            file=sys.stderr,
        )
        return 1
    except openai.AuthenticationError:
        print(
            "\nFAILED: the API key was rejected. Check DEEPSEEK_API_KEY in .env.",
            file=sys.stderr,
        )
        return 1
    except openai.APIConnectionError as exc:
        print(f"\nFAILED: could not reach the API — {exc}", file=sys.stderr)
        return 1
    except openai.APIStatusError as exc:
        print(f"\nFAILED: API error {exc.status_code} — {exc.message}", file=sys.stderr)
        return 1

    print("\nPhase 0 smoke test: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
