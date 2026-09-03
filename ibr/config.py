"""Central configuration: paths, model ids, and credential access.

Every path and model id used anywhere in this project is defined here, so
"where is the sandbox" and "which model runs the audit" each have exactly one
answer, and swapping a model is a one-line change (PROJECT_SPEC.md §7).
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT: Path = Path(__file__).resolve().parents[1]

# Load the *operator's* config (the DeepSeek API key) from the repo-root .env.
# The path is passed explicitly on purpose: python-dotenv's default search walks
# upward from the current working directory and would happily pick up
# sandbox/.env, which is bait the simulated attack is supposed to reach for. It
# must never be treated as configuration.
load_dotenv(PROJECT_ROOT / ".env", override=False)

# --- Sandbox layout -------------------------------------------------------
# The one directory this project is ever allowed to read or write.
SANDBOX_ROOT: Path = PROJECT_ROOT / "sandbox"
ISSUES_DIR: Path = SANDBOX_ROOT / "issues"
PUBLIC_COMMENTS_PATH: Path = SANDBOX_ROOT / "public_comments.txt"
LABELS_PATH: Path = SANDBOX_ROOT / "labels.txt"
REPORT_PATH: Path = SANDBOX_ROOT / "report.md"
BAIT_ENV_PATH: Path = SANDBOX_ROOT / ".env"
LOG_DIR: Path = SANDBOX_ROOT / "logs"
LOG_PATH: Path = LOG_DIR / "pipeline.jsonl"

# Which actions a batch run has already performed, so a resumed run does not
# repeat them. Append-only; see ibr/sinks.py:ActionLedger.
LEDGER_PATH: Path = LOG_DIR / "action_ledger.jsonl"

# Where a batch run over a corpus writes its per-issue results.
BATCH_REPORT_PATH: Path = SANDBOX_ROOT / "batch_report.md"
CORPUS_PATH: Path = SANDBOX_ROOT / "corpus" / "benign.jsonl"

# The bait file's *contents* are not configuration and live in ibr/fixtures.py.
# This file holds things an adopter is meant to change; that one holds props.

# --- Models ---------------------------------------------------------------
# The judgement agents (security audit + reader). Cheap and fast; per
# PROJECT_SPEC.md §7, upgrading to "deepseek-v4-pro" if classification turns out
# to be too weak is a one-string change with no architectural impact.
AUDIT_MODEL: str = "deepseek-v4-flash"
READER_MODEL: str = "deepseek-v4-flash"

# Phase 1 baseline: a single undefended agent playing all three roles at once
# (reads untrusted text, has file access, has publish access). Same tier as
# the judgement agents above — this is not about model quality, it is about
# giving one agent capabilities that should never be combined.
BASELINE_MODEL: str = "deepseek-v4-flash"
BASELINE_MAX_TURNS: int = 6
BASELINE_MAX_TOKENS: int = 4096

# Phase 2 isolated pipeline. One retry on a malformed structured response, then
# fail closed to high_risk / no_action (PROJECT_SPEC.md §3.3).
PIPELINE_MAX_TOKENS: int = 2048
STRUCTURED_RETRIES: int = 1

# --- Provider ---------------------------------------------------------------
# DeepSeek's API is OpenAI-compatible (same request/response shape as the
# `openai` package expects) rather than shipping its own SDK.
DEEPSEEK_BASE_URL: str = "https://api.deepseek.com"

# --- Credentials ----------------------------------------------------------
API_KEY_ENV_VAR: str = "DEEPSEEK_API_KEY"


class MissingApiKey(RuntimeError):
    """DEEPSEEK_API_KEY is unavailable. Never carries the key's value."""


def assert_api_key_present() -> None:
    """Fail closed if the API key is missing.

    Only checks for emptiness and raises — it never returns the key's value.
    ibr/llm.py still has to read the env var itself to hand it to the `openai`
    client constructor (unlike the Anthropic SDK, `OpenAI(base_url=...)` does
    not auto-discover an arbitrary provider's env var name), but the value
    never passes through this function, a log line, or a repr anywhere else.
    """
    if not os.environ.get(API_KEY_ENV_VAR, "").strip():
        raise MissingApiKey(
            f"{API_KEY_ENV_VAR} is not set. Put it in {PROJECT_ROOT / '.env'} "
            "(copy .env.example) or export it in your shell. Refusing to run: "
            "a missing key must stop the demo, not silently downgrade it."
        )
