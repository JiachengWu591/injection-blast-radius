"""Run a corpus through the isolated pipeline, once, resumably.

The demo runs six scenarios. Pointing this at real data means running hundreds
of issues, and that changes which failures matter. A run that takes twenty
minutes will be interrupted; a run that costs money must not repeat work it has
already paid for; and an issue that errors must not be silently folded in with
the issues that were deliberately left alone.

That last one is the reason this module exists rather than a for-loop at a call
site. This project has had the same bug twice — a failed audit counted as a
detection, an API error reported as "the model declined" — and both times the
cause was a failure path and a decision path producing the same value. So
`IssueOutcome.status` separates them by construction: `acted`, `no_action`, and
`failed` are three answers, and nothing here can turn the third into either of
the first two.

What this does NOT do is decide anything about an issue. Every decision is
still `run_isolated`'s, made by the same audit, Reader, boundary and Executor
as a single run. This is a loop with a ledger.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

import openai

from .config import AUDIT_MODEL, READER_MODEL
from .issues import Issue
from .pipeline import PipelineResult, run_isolated
from .sinks import DEFAULT_SINK, ActionSink, DanglingIntent

DEFAULT_CONCURRENCY = 8


@dataclass(frozen=True)
class IssueOutcome:
    """What happened to one issue. Three statuses, never two."""

    issue_id: str
    status: str
    """`acted`, `no_action`, or `failed`. Never inferred from another field."""
    action: str
    risk_level: str | None
    stratum: str
    duration_ms: float
    input_tokens: int
    output_tokens: int
    stages: tuple[str, ...] = ()
    error: str | None = None
    published: str | None = None
    labels: tuple[str, ...] = ()
    log_write_error: str | None = None
    """Set when the pipeline's own trace log could not be written for this
    issue — a disk-full or held-file-handle `OSError`, from `ibr/pipeline.py`.

    Deliberately separate from `error`, which is reserved for `status ==
    "failed"`. `action` and `status` above are already final and correct when
    this is set: `execute()` had already run, published or not, before the
    trace write was even attempted, so a broken log write must not read as
    the action never having happened — see `ibr/pipeline.py`'s `_emit_log`.
    """
    audit_completed: bool = True
    """False when `risk_level` is the fail-closed default, not a verdict.

    This project has shipped "a failed call read as a decision" twice before
    — see the module docstring — and `_outcome_from` dropping this exact field
    from `AuditVerdict` was a third instance: an audit timeout or connection
    error fails closed to `action="no_action"`, `risk_level="high_risk"`
    inside `run_isolated` without raising, so it never reached the `except`
    clauses below. Read only through `blocked_by_audit`, never compared
    directly — see there for why.
    """

    @property
    def blocked_by_audit(self) -> bool:
        """The audit short-circuited, so the Reader never saw the issue.

        `suspicious` passes through — only `high_risk` stops the pipeline — so
        this is not "the audit was suspicious", it is "the audit refused". And
        only when the audit call itself completed: a timeout or connection
        error also fails closed to `high_risk` (PROJECT_SPEC.md §1.4), and
        without `audit_completed` an outage during `batch_dry_run.py` rendered
        as a 100% false-positive rate against whatever issues were in flight —
        reproduced, not hypothetical: one patched timeout on an ordinary bug
        report printed `blocked by the audit: 1 (100.0%)`, `errors: 0`, exit 0.
        """
        return (
            self.status == "no_action"
            and self.risk_level == "high_risk"
            and self.audit_completed
        )

    @property
    def audit_call_failed(self) -> bool:
        """The audit never rendered a verdict — an outage, not a finding.

        Same shape as `blocked_by_audit` but the other half of the split:
        this is the bucket `blocked_by_audit` now excludes. Reported
        separately rather than folded into `BatchReport.failed`, because the
        pipeline did complete and correctly chose `no_action` — nothing here
        is the "an exception escaped `run_isolated`" case those are for.
        """
        return (
            self.status == "no_action"
            and self.risk_level == "high_risk"
            and not self.audit_completed
        )


@dataclass
class BatchReport:
    outcomes: list[IssueOutcome] = field(default_factory=list)
    skipped_already_done: list[str] = field(default_factory=list)
    wall_seconds: float = 0.0

    @property
    def failed(self) -> list[IssueOutcome]:
        return [o for o in self.outcomes if o.status == "failed"]

    @property
    def acted(self) -> list[IssueOutcome]:
        return [o for o in self.outcomes if o.status == "acted"]

    @property
    def blocked(self) -> list[IssueOutcome]:
        return [o for o in self.outcomes if o.blocked_by_audit]

    @property
    def audit_call_failures(self) -> list[IssueOutcome]:
        """Audit calls that never completed. Not a verdict, so not in `blocked`."""
        return [o for o in self.outcomes if o.audit_call_failed]

    @property
    def log_write_failures(self) -> list[IssueOutcome]:
        """Runs whose trace log write failed. `action`/`status` are still
        correct for these — see `IssueOutcome.log_write_error`."""
        return [o for o in self.outcomes if o.log_write_error]

    @property
    def input_tokens(self) -> int:
        return sum(o.input_tokens for o in self.outcomes)

    @property
    def output_tokens(self) -> int:
        return sum(o.output_tokens for o in self.outcomes)

    def by_stratum(self) -> dict[str, list[IssueOutcome]]:
        grouped: dict[str, list[IssueOutcome]] = {}
        for outcome in self.outcomes:
            grouped.setdefault(outcome.stratum, []).append(outcome)
        return grouped

    def cost_usd(self, input_per_million: float, output_per_million: float) -> float:
        """Rates are a parameter because they are the provider's to change.

        Hard-coding a price is how a cost report starts quietly lying: the
        number keeps rendering long after the rate moved.
        """
        return (
            self.input_tokens / 1_000_000 * input_per_million
            + self.output_tokens / 1_000_000 * output_per_million
        )


def _tokens_already_spent(exc: Exception) -> tuple[int, int]:
    """Real API spend `run_isolated` had already accumulated before `exc` escaped.

    `ibr/pipeline.py`'s `_execute_tracking_partial_result` attaches the
    partial `PipelineResult` to any exception `execute()` lets through (an
    attribute set on the instance, not a typed field — the exception's type
    belongs to whatever actually raised it, not to this module). By the time
    that happens the audit call, and usually the Reader call too, have
    already run and been billed: without this, `one()`'s failure branches
    reported `0, 0` tokens for a run that had genuinely spent real money, and
    `BatchReport.cost_usd()` undercounted every batch that resumed into a
    dangling intent. Falls back to `0, 0` when nothing was attached (an
    exception raised before either LLM call, or from something that never
    went through `run_isolated`).
    """
    partial = getattr(exc, "partial_result", None)
    if partial is None:
        return 0, 0
    return (
        sum(s.input_tokens for s in partial.stages),
        sum(s.output_tokens for s in partial.stages),
    )


def _outcome_from(
    result: PipelineResult, issue: Issue, stratum: str, duration_ms: float
) -> IssueOutcome:
    decision = result.decision
    action = result.action_taken
    return IssueOutcome(
        issue_id=issue.issue_id,
        # A run that completed and chose nothing is not a run that broke.
        status="acted" if action != "no_action" else "no_action",
        action=action,
        risk_level=result.audit.risk_level if result.audit else None,
        stratum=stratum,
        duration_ms=duration_ms,
        input_tokens=sum(s.input_tokens for s in result.stages),
        output_tokens=sum(s.output_tokens for s in result.stages),
        stages=tuple(s.stage for s in result.stages),
        published=decision.published_comment if decision else None,
        labels=decision.labels_added if decision else (),
        log_write_error=result.log_write_error,
        # Carried through explicitly rather than left to default True: an
        # audit call that timed out is `no_action` / `high_risk` exactly like
        # a genuine refusal, and only this field tells the two apart.
        audit_completed=result.audit.completed if result.audit else True,
    )


def run_batch(
    issues: list[tuple[Issue, str]],
    *,
    sink: ActionSink = DEFAULT_SINK,
    client: openai.OpenAI | None = None,
    audit_model: str = AUDIT_MODEL,
    reader_model: str = READER_MODEL,
    concurrency: int = DEFAULT_CONCURRENCY,
    already_done: frozenset[str] = frozenset(),
    progress: object = None,
) -> BatchReport:
    """Run every (issue, stratum) pair through the isolated pipeline.

    `already_done` is the resume mechanism at the issue level, above the
    ledger's action level. The ledger stops a duplicate *action*; this stops a
    duplicate *call*, which is what costs money. Both exist because they fail
    differently: skipping a call saves money, skipping an action prevents a
    double post.

    An issue that raises is recorded as `failed` and the batch continues. That
    is not a fail-open: nothing was published for it, and the caller gets the
    error. Aborting the whole run on one bad issue would be worse — it turns
    one unparseable record into no measurement at all.
    """
    report = BatchReport()
    started_all = time.perf_counter()

    pending = [(i, s) for i, s in issues if i.issue_id not in already_done]
    report.skipped_already_done = [
        i.issue_id for i, _ in issues if i.issue_id in already_done
    ]

    def one(pair: tuple[Issue, str]) -> IssueOutcome:
        issue, stratum = pair
        started = time.perf_counter()
        try:
            result = run_isolated(
                issue,
                client=client,
                audit_model=audit_model,
                reader_model=reader_model,
                sink=sink,
            )
        except DanglingIntent as exc:
            # The one error that must not be retried automatically. An action
            # was started and never confirmed, and only a person can look at
            # the destination and say which.
            input_tokens, output_tokens = _tokens_already_spent(exc)
            return IssueOutcome(
                issue_id=issue.issue_id,
                status="failed",
                action="no_action",
                risk_level=None,
                stratum=stratum,
                duration_ms=(time.perf_counter() - started) * 1000,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                error=f"dangling intent, needs a human: {exc}",
            )
        except Exception as exc:  # noqa: BLE001 - one bad issue must not end the run
            input_tokens, output_tokens = _tokens_already_spent(exc)
            return IssueOutcome(
                issue_id=issue.issue_id,
                status="failed",
                action="no_action",
                risk_level=None,
                stratum=stratum,
                duration_ms=(time.perf_counter() - started) * 1000,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                error=f"{type(exc).__name__}: {exc}",
            )
        return _outcome_from(
            result, issue, stratum, (time.perf_counter() - started) * 1000
        )

    if concurrency <= 1:
        for index, pair in enumerate(pending, 1):
            report.outcomes.append(one(pair))
            if callable(progress):
                progress(index, len(pending))
    else:
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            for index, outcome in enumerate(pool.map(one, pending), 1):
                report.outcomes.append(outcome)
                if callable(progress):
                    progress(index, len(pending))

    report.wall_seconds = time.perf_counter() - started_all
    return report
