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

    @property
    def blocked_by_audit(self) -> bool:
        """The audit short-circuited, so the Reader never saw the issue.

        `suspicious` passes through — only `high_risk` stops the pipeline — so
        this is not "the audit was suspicious", it is "the audit refused".
        """
        return self.status == "no_action" and self.risk_level == "high_risk"


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
            return IssueOutcome(
                issue_id=issue.issue_id,
                status="failed",
                action="no_action",
                risk_level=None,
                stratum=stratum,
                duration_ms=(time.perf_counter() - started) * 1000,
                input_tokens=0,
                output_tokens=0,
                error=f"dangling intent, needs a human: {exc}",
            )
        except Exception as exc:  # noqa: BLE001 - one bad issue must not end the run
            return IssueOutcome(
                issue_id=issue.issue_id,
                status="failed",
                action="no_action",
                risk_level=None,
                stratum=stratum,
                duration_ms=(time.perf_counter() - started) * 1000,
                input_tokens=0,
                output_tokens=0,
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
