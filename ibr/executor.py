"""Executor — has the permissions, reads almost nothing.

PROJECT_SPEC.md §3.4. This module is the trusted side of the boundary. It
receives a validated ReaderOutput and decides what to do, subject to three
rules that are not negotiable:

  1. `suggested_action` is checked against a whitelist. Anything not in it —
     including the case where the Reader produced nothing at all — is
     no_action.
  2. `reasoning` and `summary` are never read here. Grep this file: the two
     attacker-controllable fields appear in exactly one place, the logging
     record, and never in a branch condition or an output string.
  3. Published text comes from COMMENT_TEMPLATES only. No model-generated text
     is concatenated into it, so there is no path by which issue content can
     reach the public surface, whatever the Reader was persuaded to say.

That is what makes this layer structural rather than probabilistic: a smarter
attack does not widen the set of reachable outcomes, because the set is
enumerated below.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import sandbox_fs
from .config import LABELS_PATH, PUBLIC_COMMENTS_PATH
from .output_audit import OutputAuditResult, audit_output
from .schemas import SUGGESTED_ACTIONS, ReaderOutput

# Every byte this system can ever publish, enumerated. Static text only — no
# interpolation of anything derived from the issue or from model output.
COMMENT_TEMPLATES: dict[str, str] = {
    "bug": (
        "Thanks for the report — this has been triaged as a **bug** and queued "
        "for a maintainer to reproduce.\n\n"
        "_Posted automatically by the triage assistant._"
    ),
    "question": (
        "Thanks for getting in touch — this has been triaged as a **question**. "
        "A maintainer will follow up, and the documentation may already cover "
        "it in the meantime.\n\n"
        "_Posted automatically by the triage assistant._"
    ),
    "feature_request": (
        "Thanks for the suggestion — this has been triaged as a **feature "
        "request** and added to the backlog for consideration.\n\n"
        "_Posted automatically by the triage assistant._"
    ),
    "unclear": (
        "Thanks for writing in. There isn't quite enough detail here to route "
        "this yet — could you add reproduction steps, expected versus actual "
        "behaviour, and your version?\n\n"
        "_Posted automatically by the triage assistant._"
    ),
}


@dataclass(frozen=True)
class ExecutorDecision:
    action_taken: str
    published_comment: str | None
    labels_added: tuple[str, ...]
    output_audit: OutputAuditResult | None
    note: str


def _no_action(note: str) -> ExecutorDecision:
    return ExecutorDecision(
        action_taken="no_action",
        published_comment=None,
        labels_added=(),
        output_audit=None,
        note=note,
    )


def _publish(issue_id: str, body: str) -> tuple[str | None, OutputAuditResult]:
    """Run the output audit, then write only if it comes back clean."""
    verdict = audit_output(body)
    if verdict.blocked:
        return None, verdict
    header = f"\n----- comment on issue #{issue_id} (isolated pipeline) -----\n"
    sandbox_fs.append_text(PUBLIC_COMMENTS_PATH, header + body.rstrip() + "\n")
    return body, verdict


def _add_label(issue_id: str, label: str) -> None:
    sandbox_fs.append_text(LABELS_PATH, f"issue #{issue_id}: {label}\n")


def execute(issue_id: str, reader_output: ReaderOutput | None) -> ExecutorDecision:
    """Decide and act. Every path that isn't an explicit success is no_action."""
    if reader_output is None:
        return _no_action("reader produced no valid output — failing closed")

    action = reader_output.suggested_action
    if action not in SUGGESTED_ACTIONS:
        # Unreachable via parse_reader_output, which already enforces the enum.
        # Kept because the whitelist must hold even if this function is ever
        # called with a value that skipped the parser.
        return _no_action(f"action {action!r} is not in the whitelist")

    match action:
        case "reply_comment":
            template = COMMENT_TEMPLATES.get(reader_output.issue_type)
            if template is None:
                return _no_action(
                    f"no template for issue_type {reader_output.issue_type!r}"
                )
            published, verdict = _publish(issue_id, template)
            if published is None:
                return ExecutorDecision(
                    action_taken="blocked_by_output_audit",
                    published_comment=None,
                    labels_added=(),
                    output_audit=verdict,
                    note=f"output audit blocked publication: {verdict.summary}",
                )
            return ExecutorDecision(
                action_taken="reply_comment",
                published_comment=published,
                labels_added=(),
                output_audit=verdict,
                note=f"published the {reader_output.issue_type!r} template",
            )

        case "label_bug":
            _add_label(issue_id, "bug")
            return ExecutorDecision(
                action_taken="label_bug",
                published_comment=None,
                labels_added=("bug",),
                output_audit=None,
                note="added label 'bug'",
            )

        case "label_question":
            _add_label(issue_id, "question")
            return ExecutorDecision(
                action_taken="label_question",
                published_comment=None,
                labels_added=("question",),
                output_audit=None,
                note="added label 'question'",
            )

        case _:
            return _no_action("action was no_action")
