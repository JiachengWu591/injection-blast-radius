"""Where issues come from.

The pipeline never loads an issue; it is handed one. That was already true
before this module existed — `run_isolated` and `run_baseline` both take an
`Issue`, not a name — which is why pointing this at real data needs a new
source and no changes to the defended path.

This module makes that seam explicit rather than incidental. `Issue` is a
frozen dataclass with four string fields, so anything that can produce one is a
valid source: a JSONL export, a database row, a webhook payload, a paginated
API.

What a source must not do is filter. An issue source that dropped
suspicious-looking input would be a fourth defence layer, unmeasured and
invisible, sitting where nobody would think to look for it. Screening is the
audit's job, and the audit is measured.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from . import sandbox_fs
from .config import ISSUES_DIR
from .issues import Issue, MalformedIssue, parse_issue


@runtime_checkable
class IssueSource(Protocol):
    """Somewhere issues can be read from.

    Structural, so an adopter's own class qualifies without importing anything
    from this package.
    """

    def load_issue(self, name: str) -> Issue:
        """Return one issue, or raise MalformedIssue. Never return a partial one."""

    def available_issues(self) -> list[str]:
        """Names this source can load, for listing and for tests."""


@dataclass(frozen=True)
class SandboxIssueSource:
    """The default: `sandbox/issues/issue_<name>.json`.

    Reads through sandbox_fs, so the whitelist covers issue loading too.
    """

    directory: Path = ISSUES_DIR

    def load_issue(self, name: str) -> Issue:
        path = self.directory / f"issue_{name}.json"
        if not sandbox_fs.exists(path):
            raise MalformedIssue(
                f"no such issue fixture: {name!r} (have: {self.available_issues()})"
            )
        return parse_issue(sandbox_fs.read_text(path), origin=str(path))

    def available_issues(self) -> list[str]:
        directory = sandbox_fs.resolve_in_sandbox(self.directory)
        if not directory.is_dir():
            return []
        return sorted(
            path.stem.removeprefix("issue_") for path in directory.glob("issue_*.json")
        )


@dataclass(frozen=True)
class JsonLinesIssueSource:
    """One issue per line, keyed by `issue_id`.

    Included because it is the shape most real exports arrive in, and because a
    second implementation is the only way to know the protocol is actually a
    protocol rather than a description of the first one.

    Deliberately reads through sandbox_fs like the default does. Pointing this
    at a path outside the sandbox is a decision that belongs to whoever is
    integrating, not a default this project ships.
    """

    path: Path

    def _records(self) -> dict[str, Issue]:
        found: dict[str, Issue] = {}
        text = sandbox_fs.read_text(self.path)
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            issue = parse_issue(line, origin=f"{self.path}:{number}")
            if issue.issue_id in found:
                raise MalformedIssue(
                    f"{self.path}:{number}: duplicate issue_id {issue.issue_id!r}"
                )
            found[issue.issue_id] = issue
        return found

    def load_issue(self, name: str) -> Issue:
        records = self._records()
        if name not in records:
            raise MalformedIssue(
                f"no issue {name!r} in {self.path} (have: {sorted(records)})"
            )
        return records[name]

    def available_issues(self) -> list[str]:
        if not sandbox_fs.exists(self.path):
            return []
        return sorted(self._records())


def write_jsonl(path: Path, issues: list[Issue]) -> Path:
    """Write issues in the format JsonLinesIssueSource reads.

    Here so the round trip is testable and so an adopter has a worked example
    of the expected shape rather than a prose description of it.
    """
    body = "".join(
        json.dumps(
            {
                "issue_id": issue.issue_id,
                "title": issue.title,
                "author": issue.author,
                "body": issue.body,
            },
            ensure_ascii=False,
        )
        + "\n"
        for issue in issues
    )
    return sandbox_fs.write_text(path, body)


DEFAULT_SOURCE: IssueSource = SandboxIssueSource()
