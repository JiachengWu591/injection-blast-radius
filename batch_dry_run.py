"""Run the benign corpus through the isolated pipeline, publishing nothing.

    python batch_dry_run.py --limit 20   # 20 real issues, costs money
    python batch_dry_run.py              # all 165, costs money

There is deliberately no --replay. A cassette records one exchange for one
issue and its fingerprint is checked, so a recording cannot drive a different
issue — the first version of this script tried, and the replay machinery
refused three times, correctly. Offline coverage of the runner lives in
tests/test_batch.py, which drives it from the issue its cassette was actually
recorded against and from stub clients for the failure paths.

This is the thing DryRunSink exists for. Against real data the first question
is not "does it work" but "what would it have done" — and the only way to
answer that is to run the real pipeline, record every action it chose, and
publish none of them.

What the output is for: every row is one ordinary issue and the action the
system chose for it. A row that says `no_action` with `high_risk` is the audit
refusing a legitimate bug report, which is a false positive and a cost a
deployment pays in lost reports. Reviewing those rows by eye is how you find
out whether the labelling was right before trusting any rate computed from it.

Nothing here is written to a public surface. The sink records and discards, and
tests/test_batch.py asserts that it wrote nothing.
"""

from __future__ import annotations

import argparse
import sys
from ibr import sandbox_fs
from ibr.batch import BatchReport, run_batch
from ibr.bootstrap import ensure_sandbox
from ibr.config import (
    BATCH_REPORT_PATH,
    LABELS_PATH,
    PUBLIC_COMMENTS_PATH,
)
from ibr.sinks import DryRunSink
from ibr.sources import load_labelled_corpus

# deepseek-v4-flash, USD per million tokens. A parameter rather than a
# constant baked into the report, because it is the provider's to change and a
# stale rate keeps rendering as if it were current.
INPUT_USD_PER_M = 0.27
OUTPUT_USD_PER_M = 1.10


def render(report: BatchReport) -> str:
    lines: list[str] = []
    rule = "─" * 96
    lines.append(rule)
    lines.append(
        f"{'issue':<38} {'stratum':<22} {'action':<16} {'audit':<11} {'ms':>6}"
    )
    lines.append(rule)
    for outcome in report.outcomes:
        marker = "!" if outcome.status == "failed" else " "
        lines.append(
            f"{marker}{outcome.issue_id[:37]:<37} "
            f"{outcome.stratum:<22} "
            f"{outcome.action:<16} "
            f"{(outcome.risk_level or '-'):<11} "
            f"{outcome.duration_ms:>6.0f}"
        )
    lines.append(rule)

    total = len(report.outcomes)
    blocked = report.blocked
    lines.append("")
    lines.append(f"issues run                     : {total}")
    lines.append(f"actions the system would take  : {len(report.acted)}")
    lines.append(
        f"blocked by the audit           : {len(blocked)}"
        + (f"  ({len(blocked) / total:.1%})" if total else "")
    )
    lines.append(f"errors (not decisions)         : {len(report.failed)}")
    if report.skipped_already_done:
        lines.append(
            f"skipped, already done          : {len(report.skipped_already_done)}"
        )

    if blocked:
        lines.append("")
        lines.append("Blocked — these are the false-positive candidates:")
        for outcome in blocked:
            lines.append(f"  [{outcome.stratum}] {outcome.issue_id}")

    if report.failed:
        lines.append("")
        lines.append("Errors — no action was taken for these, and none is implied:")
        for outcome in report.failed:
            lines.append(f"  {outcome.issue_id}: {outcome.error}")

    lines.append("")
    lines.append(
        f"tokens: {report.input_tokens} in, {report.output_tokens} out"
    )
    if report.input_tokens or report.output_tokens:
        cost = report.cost_usd(INPUT_USD_PER_M, OUTPUT_USD_PER_M)
        lines.append(
            f"cost  : ${cost:.4f} at ${INPUT_USD_PER_M}/${OUTPUT_USD_PER_M} "
            "per million in/out"
        )
        if total:
            lines.append(f"        ${cost / total:.5f} per issue")
    lines.append(f"wall  : {report.wall_seconds:.1f}s")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        "--limit", type=int, default=0, help="run only the first N issues"
    )
    parser.add_argument(
        "--concurrency", type=int, default=8, help="parallel pipeline runs"
    )
    args = parser.parse_args()

    ensure_sandbox()
    corpus = load_labelled_corpus()
    if args.limit:
        corpus = corpus[: args.limit]

    before = (
        sandbox_fs.read_text(PUBLIC_COMMENTS_PATH),
        sandbox_fs.read_text(LABELS_PATH),
    )

    sink = DryRunSink()

    def show(done: int, total: int) -> None:
        if total and (done % 10 == 0 or done == total):
            print(f"  {done}/{total}", file=sys.stderr)

    print(f"Running {len(corpus)} issues (this makes real API calls)…\n")
    report = run_batch(
        corpus, sink=sink, concurrency=args.concurrency, progress=show
    )

    print(render(report))

    after = (
        sandbox_fs.read_text(PUBLIC_COMMENTS_PATH),
        sandbox_fs.read_text(LABELS_PATH),
    )
    if after != before:
        print(
            "\nFAILED: a dry run changed a public surface. That is a defect in "
            "the sink, not a demo outcome.",
            file=sys.stderr,
        )
        return 1
    print(
        f"\n{len(sink.comments)} comment(s) and {len(sink.labels)} label(s) "
        "were recorded and discarded. Nothing was published."
    )

    sandbox_fs.write_text(
        BATCH_REPORT_PATH,
        "# Dry run over the benign corpus\n\n```\n"
        + render(report)
        + "\n```\n",
    )
    print(f"Report: {BATCH_REPORT_PATH}")

    # An error is not a decision, so it does not get to pass quietly.
    return 1 if report.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
