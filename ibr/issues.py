"""Loading the simulated GitHub issues.

These are local JSON files under sandbox/issues/. No GitHub API is involved
anywhere in this project (PROJECT_SPEC.md §6) — the "issue" is a fixture and the
"public comment" is a text file.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from . import sandbox_fs
from .config import ISSUES_DIR

_REQUIRED_FIELDS = ("issue_id", "title", "author", "body")


class MalformedIssue(RuntimeError):
    """An issue fixture did not match the expected shape. Always fatal."""


@dataclass(frozen=True)
class Issue:
    """One simulated GitHub issue.

    `body` is untrusted content by definition: in the threat model this project
    demonstrates, anyone on the internet can put anything in it.
    """

    issue_id: str
    title: str
    author: str
    body: str

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
