"""Executor — has the permissions, reads almost nothing.

PROJECT_SPEC.md §3.4. This module is the trusted side of the boundary. It
receives a validated ReaderOutput and decides what to do, subject to three
rules that are not negotiable:

  1. `suggested_action` is checked against a whitelist. Anything not in it —
     including the case where the Reader produced nothing at all — is
     no_action.
  2. `reasoning` and `summary` are never read here. Grep this file: the two
     attacker-controllable fields do not appear here at all — this module
     never reads `ReaderOutput.reasoning` or `.summary`, in a branch
     condition, an output string, or anywhere else. (They do end up in a
     logging record, but that is `ibr/pipeline.py`'s `StageRecord`
     construction, a different module; this file has nothing of theirs to
     log.)
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
# The precise claim, because two looser versions of it were wrong in turn.
# A published line is a template plus the sink's own framing, and that
# framing carries `issue_id`: `SandboxActionSink` writes
# `comment on issue #{issue_id}` above the body and `issue #{issue_id}:
# {label}` for a label. So the byte set below is closed, but the *published
# line* is not, and `Issue.__post_init__`'s charset restriction
# (`[A-Za-z0-9._-]{1,64}`) admits some secret-shaped strings outright (an AWS
# access key id is exactly `AKIA` plus 16 uppercase-alphanumeric characters —
# entirely within that charset). `_publish` and `_add_label` below also audit
# `issue_id`, regex patterns only (see `audit_output`'s `scan_entropy`
# parameter for why), for that reason: not because the template can carry
# model output (it cannot), but because the id sitting next to it in the
# same published line can, and it is worth catching the id shapes a regex
# can name even though the charset restriction remains the only backstop for
# an arbitrary one a regex cannot.
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


def _merge_audits(
    body_verdict: OutputAuditResult, id_verdict: OutputAuditResult
) -> OutputAuditResult:
    return OutputAuditResult(
        blocked=body_verdict.blocked or id_verdict.blocked,
        findings=tuple(dict.fromkeys(body_verdict.findings + id_verdict.findings)),
    )


def _publish(
    issue_id: str, body: str, sink: ActionSink
) -> tuple[str | None, OutputAuditResult]:
    """Run the output audit, then hand it to the sink only if it comes back clean.

    The audit runs here rather than inside the sink on purpose. A sink is
    swappable; the last check before anything becomes public is not.

    Audits `issue_id` as well as `body`, not `body` alone. `body` is always a
    static template, so auditing it by itself would only ever see text that
    is already known clean — every concrete sink interpolates `issue_id`
    directly into the actual published line (see
    `SandboxActionSink.publish_comment`'s header), and that id is
    attacker-influenced (`ibr/issues.py`'s own docstring says so). Auditing
    the template alone let an id shaped like a known secret pattern (an AWS
    access key id, say) reach the public surface unaudited, before this
    check existed.

    `issue_id` is scanned with `scan_entropy=False` — regex patterns only.
    This is a partial defence and `audit_output`'s own docstring says so:
    entropy scanning cannot tell an ordinary hyphenated issue id from a
    same-length random secret (measured, they overlap), so running it here
    would routinely block completely ordinary ids without reliably catching
    a real one either. What this catches is an id shaped like one of the
    known regex patterns; an arbitrary high-entropy id that matches none of
    them still passes, exactly as it did before this function existed — the
    charset restriction on `Issue.__post_init__` remains the structural
    backstop for that residual case, not this scan.
    """
    body_verdict = audit_output(body)
    id_verdict = audit_output(issue_id, scan_entropy=False)
    verdict = _merge_audits(body_verdict, id_verdict)
    if verdict.blocked:
        return None, verdict
    sink.publish_comment(issue_id, body)
    return body, verdict


def _add_label(
    issue_id: str, label: str, sink: ActionSink
) -> tuple[str | None, OutputAuditResult]:
    """Mirror of `_publish` for the label path, which had no audit at all.

    `label` is always one of the fixed action-set labels, but `issue_id` is
    not, and `SandboxActionSink.add_label` interpolates it directly into the
    published line exactly as `publish_comment` does — the same gap, on a
    path that previously called the sink with no audit whatsoever. See
    `_publish` for why `issue_id` is scanned with `scan_entropy=False`, and
    what that does and does not catch.
    """
    label_verdict = audit_output(label)
    id_verdict = audit_output(issue_id, scan_entropy=False)
    verdict = _merge_audits(label_verdict, id_verdict)
    if verdict.blocked:
        return None, verdict
    sink.add_label(issue_id, label)
    return label, verdict


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
            added, verdict = _add_label(issue_id, "bug", sink)
            if added is None:
                return ExecutorDecision(
                    action_taken="blocked_by_output_audit",
                    published_comment=None,
                    labels_added=(),
                    output_audit=verdict,
                    note=f"output audit blocked publication: {verdict.summary}",
                )
            return ExecutorDecision(
                action_taken="label_bug",
                published_comment=None,
                labels_added=(added,),
                output_audit=verdict,
                note="added label 'bug'",
            )

        case "label_question":
            added, verdict = _add_label(issue_id, "question", sink)
            if added is None:
                return ExecutorDecision(
                    action_taken="blocked_by_output_audit",
                    published_comment=None,
                    labels_added=(),
                    output_audit=verdict,
                    note=f"output audit blocked publication: {verdict.summary}",
                )
            return ExecutorDecision(
                action_taken="label_question",
                published_comment=None,
                labels_added=(added,),
                output_audit=verdict,
                note="added label 'question'",
            )

        case _:
            return _no_action("action was no_action")
