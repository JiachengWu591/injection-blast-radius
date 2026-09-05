"""Loading the simulated GitHub issues.

These are local JSON files under sandbox/issues/. No GitHub API is involved
anywhere in this project (PROJECT_SPEC.md §6) — the "issue" is a fixture and the
"public comment" is a text file.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from . import sandbox_fs
from .config import ISSUES_DIR

_REQUIRED_FIELDS = ("issue_id", "title", "author", "body")

# The one field of an issue that is not treated as untrusted downstream.
#
# `title` and `body` never leave the log and the Reader's summary of them never
# reaches a published action. `issue_id` does: `SandboxActionSink` interpolates
# it into the comment header and into every label line, and the output audit
# runs on the comment *body* before that, so the id is text from outside that
# reaches a published file with nothing between. On the label path there is no
# output audit at all, and the id is the whole variable part of the line.
#
# So it is constrained here rather than in `parse_issue`. A source is anything
# that returns an `Issue` — ARCHITECTURE.md invites a webhook source that
# builds the frozen dataclass directly and never sees the parser — and a rule
# only one of three construction paths enforces is not a structural rule. None
# of the 525 shipped corpus ids or any test id falls outside this class.
_ISSUE_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class MalformedIssue(RuntimeError):
    """An issue fixture did not match the expected shape. Always fatal."""


@dataclass(frozen=True)
class Issue:
    """One simulated GitHub issue.

    `body` is untrusted content by definition: in the threat model this project
    demonstrates, anyone on the internet can put anything in it. `issue_id` is
    equally untrusted and, unlike `body`, ends up in published output — so it
    is the one field with a shape.
    """

    issue_id: str
    title: str
    author: str
    body: str

    def __post_init__(self) -> None:
        if not _ISSUE_ID.match(self.issue_id):
            raise MalformedIssue(
                f"issue_id {self.issue_id!r} is not "
                f"{_ISSUE_ID.pattern}. The id is interpolated into published "
                "comment headers and label lines, so it is the one issue "
                "field with a shape. Fail closed rather than publish it."
            )

    @property
    def source_path(self) -> Path:
        return ISSUES_DIR / f"issue_{self.issue_id}.json"


def available_issues() -> list[str]:
    """Names of the issue fixtures on disk, e.g. ["benign", "malicious"]."""
    issues_dir = sandbox_fs.resolve_in_sandbox(ISSUES_DIR)
    if not issues_dir.is_dir():
        return []
    return sorted(
        path.stem.removeprefix("issue_")
        for path in issues_dir.glob("issue_*.json")
    )


def parse_issue(raw: str, *, origin: str) -> Issue:
    """Validate one JSON object into an Issue, or fail closed.

    Separate from any particular storage so every source shares one validator.
    A second source with its own slightly different checks is how a field that
    is a string in one path and an integer in another gets into the pipeline.

    Every failure mode raises. There is no "return None and let the caller
    decide" path, because the caller deciding is exactly how a malformed input
    turns into a skipped check.
    """
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MalformedIssue(f"{origin} is not valid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise MalformedIssue(
            f"{origin} must contain a JSON object, got {type(payload)}"
        )

    missing = [field for field in _REQUIRED_FIELDS if field not in payload]
    if missing:
        raise MalformedIssue(f"{origin} is missing required field(s): {missing}")

    wrong_type = [
        field for field in _REQUIRED_FIELDS if not isinstance(payload[field], str)
    ]
    if wrong_type:
        raise MalformedIssue(f"{origin} field(s) must be strings: {wrong_type}")

    return Issue(**{field: payload[field] for field in _REQUIRED_FIELDS})


def load_issue(name: str) -> Issue:
    """Load sandbox/issues/issue_<name>.json, or fail closed.

    Kept as a module-level function because every entry script and test calls
    it. `ibr/sources.py` is the same thing behind a protocol, for when the
    issues stop being fixtures on disk.
    """
    path = ISSUES_DIR / f"issue_{name}.json"
    if not sandbox_fs.exists(path):
        raise MalformedIssue(
            f"no such issue fixture: {name!r} (have: {available_issues()})"
        )
    return parse_issue(sandbox_fs.read_text(path), origin=str(path))
