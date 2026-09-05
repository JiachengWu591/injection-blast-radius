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

Where those outcomes land is a separate question, answered by `ibr/sinks.py`.
The executor no longer writes files itself; it hands the chosen action to a
sink. That keeps the three rules above independent of the destination, so
pointing this at a real issue tracker cannot weaken them by accident.
"""

from __future__ import annotations

from dataclasses import dataclass

from .output_audit import OutputAuditResult, audit_output
from .schemas import SUGGESTED_ACTIONS, ReaderOutput
from .sinks import DEFAULT_SINK, ActionSink

# Every byte of comment *body* this system can ever publish, enumerated. Static
# text only — nothing derived from the issue or from model output is
# interpolated into these strings.
#
# The precise claim, because the loose version of it was wrong. A published
# line is a template plus the sink's own framing, and that framing carries
# `issue_id`: `SandboxActionSink` writes `comment on issue #{issue_id}` above
# the body and `issue #{issue_id}: {label}` for a label. So the byte set below
# is closed, and the published line is closed only because `Issue.__post_init__`
# constrains the id to `[A-Za-z0-9._-]{1,64}`. Nothing model-generated reaches
# either — that part was always true — but "derived from the issue" was not.
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


def _publish(
    issue_id: str, body: str, sink: ActionSink
) -> tuple[str | None, OutputAuditResult]:
    """Run the output audit, then hand it to the sink only if it comes back clean.

    The audit runs here rather than inside the sink on purpose. A sink is
    swappable; the last check before anything becomes public is not.
    """
    verdict = audit_output(body)
    if verdict.blocked:
        return None, verdict
    sink.publish_comment(issue_id, body)
    return body, verdict


def execute(
    issue_id: str,
    reader_output: ReaderOutput | None,
    *,
    sink: ActionSink = DEFAULT_SINK,
) -> ExecutorDecision:
    """Decide and act. Every path that isn't an explicit success is no_action.

    `sink` is where the two possible actions land. It cannot influence the
    decision — it is passed the outcome, never consulted about it — so pointing
    this at a real issue tracker changes the destination and nothing else.
    """
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
            published, verdict = _publish(issue_id, template, sink)
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
            sink.add_label(issue_id, "bug")
            return ExecutorDecision(
                action_taken="label_bug",
                published_comment=None,
                labels_added=("bug",),
                output_audit=None,
                note="added label 'bug'",
            )

        case "label_question":
            sink.add_label(issue_id, "question")
            return ExecutorDecision(
                action_taken="label_question",
                published_comment=None,
                labels_added=("question",),
                output_audit=None,
                note="added label 'question'",
            )

        case _:
            return _no_action("action was no_action")
