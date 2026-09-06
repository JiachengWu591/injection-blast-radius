"""Structured logging — JSON Lines, one record per pipeline stage.

PROJECT_SPEC.md §4 Phase 3. Every model call and tool call leaves a record
carrying the stage name, an input and output summary, how long it took, and
(for the security audit) the risk level. phase3_trace.py renders the result as
a tree.

Two properties this module is built to guarantee:

  * `reasoning_first` is computed from character offsets in the raw JSON the
    model actually emitted, not from the parsed dict. A dict would tell you
    which fields exist; only the raw text tells you which was *written* first,
    which is the whole point of putting reasoning ahead of the verdict
    (PROJECT_SPEC.md §3.1).
  * Nothing written here can contain the operator's API key. `scrub()` is a
    belt-and-braces pass over every field — the key is not supposed to reach
    this module at all, and this makes "not supposed to" into "cannot".
"""

from __future__ import annotations

import json
import os
import unicodedata
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from . import sandbox_fs
from .config import API_KEY_ENV_VAR, LOG_PATH

SUMMARY_LIMIT = 140


def new_run_id() -> str:
    return uuid.uuid4().hex[:8]


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def scrub(text: str) -> str:
    """Remove the operator's API key if it somehow appears. Never logs it."""
    key = os.environ.get(API_KEY_ENV_VAR, "").strip()
    if key and key in text:
        return text.replace(key, "<redacted:api-key>")
    return text


def _escape_control_characters(text: str) -> str:
    """Make a C0/C1 control character visible instead of letting it act.

    `str.split()` treats real whitespace (space, tab, newline, ...) as a
    separator, so `summarize` already removes those. It does not touch ESC
    (0x1b) or the other control characters that are not whitespace — an
    issue titled `\\x1b[1A\\x1b[2K...` carries a terminal escape sequence
    straight through `summarize` and into the JSON Lines log untouched, since
    none of it is whitespace and none of it is the operator's API key.
    `phase3_trace.py` then prints `input_summary` with no sanitisation of its
    own, so the sequence executes in the operator's terminal: `\\x1b[1A\\x1b[2K`
    moves the cursor up one line and erases it, letting issue text overwrite
    the stage line printed immediately above with a forged one. §4 makes this
    trace the artifact for seeing "what the content went through" — a title
    is supposed to be inert data there, same as the body.

    So every Unicode "Cc" character — including but not the same set as
    whitespace — is turned into its escaped form (`\\x1b`, four visible
    characters) rather than left able to act on whoever reads the summary.
    Elsewhere in this project the Reader's free text is logged through `!r`
    for the same reason; this is that same idea applied at the one place
    every stage's input and output summary already passes through, so a
    caller does not have to remember to do it themselves.
    """
    return "".join(
        char if unicodedata.category(char) != "Cc" else f"\\x{ord(char):02x}"
        for char in text
    )


def summarize(text: str, limit: int = SUMMARY_LIMIT) -> str:
    """Collapse whitespace, neutralise control characters, and truncate."""
    collapsed = _escape_control_characters(" ".join(scrub(text).split()))
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 1] + "…"


def reasoning_precedes(raw_json: str, verdict_field: str) -> bool | None:
    """Did the model write `reasoning` before `verdict_field`?

    Returns None when the question doesn't apply (no raw text, or a field is
    absent) so that "unknown" is never silently reported as "yes".
    """
    if not raw_json:
        return None
    reasoning_at = raw_json.find('"reasoning"')
    verdict_at = raw_json.find(f'"{verdict_field}"')
    if reasoning_at < 0 or verdict_at < 0:
        return None
    return reasoning_at < verdict_at


@dataclass(frozen=True)
class LogRecord:
    ts: str
    run_id: str
    architecture: str
    issue_id: str
    stage: str
    outcome: str
    duration_ms: float
    input_summary: str = ""
    output_summary: str = ""
    detail: str = ""
    risk_level: str | None = None
    reasoning_first: bool | None = None
    attempts: int | None = None
    # Zero rather than None when a stage made no call, so summing a run's cost
    # never has to special-case the short-circuit and the deterministic paths.
    input_tokens: int = 0
    output_tokens: int = 0

    def to_json(self) -> str:
        payload = asdict(self)
        for field_name in ("input_summary", "output_summary", "detail"):
            payload[field_name] = scrub(payload[field_name])
        return json.dumps(payload, ensure_ascii=False, sort_keys=False)


def append_records(records: list[LogRecord]) -> None:
    if not records:
        return
    sandbox_fs.append_text(
        LOG_PATH, "".join(record.to_json() + "\n" for record in records)
    )


def clear_log() -> None:
    sandbox_fs.write_text(LOG_PATH, "")


def load_records() -> list[dict]:
    """Read the log back. A malformed line is an error, not something to skip."""
    if not sandbox_fs.exists(LOG_PATH):
        return []
    records: list[dict] = []
    for number, line in enumerate(sandbox_fs.read_text(LOG_PATH).splitlines(), 1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"{LOG_PATH}: line {number} is not valid JSON: {exc}") from exc
    return records


def group_runs(records: list[dict]) -> list[tuple[str, list[dict]]]:
    """Group records by run_id, preserving first-appearance order."""
    grouped: dict[str, list[dict]] = {}
    for record in records:
        grouped.setdefault(record.get("run_id", "?"), []).append(record)
    return list(grouped.items())
