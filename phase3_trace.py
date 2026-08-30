"""Phase 3 — render the JSON Lines log as a tree.

Reads sandbox/logs/pipeline.jsonl and prints what each run's content actually
went through: which stage saw it, what that stage decided, how long it took,
and — for the two agents that emit a schema — whether `reasoning` was really
written before the verdict.

Usage:
    python phase3_trace.py                 # render the existing log
    python phase3_trace.py --run malicious # run the malicious issue first, then render
    python phase3_trace.py --run all       # run every scenario first, then render
"""

from __future__ import annotations

import argparse
import sys

import openai

from ibr.baseline_agent import run_baseline
from ibr.bootstrap import ensure_sandbox, reset_labels, reset_public_comments
from ibr.issues import load_issue
from ibr.observability import clear_log, group_runs, load_records
from ibr.pipeline import run_isolated

RULE = "─" * 78

# Stages where "what happened to the content" is the interesting question.
_STAGE_LABELS = {
    "security_audit": "security audit      (probabilistic)",
    "short_circuit": "short circuit",
    "audit_bypass": "audit bypass        (simulated)",
    "reader": "reader              (no tools)",
    "structured_boundary": "STRUCTURED BOUNDARY",
    "executor": "executor            (enum only)",
    "output_audit": "output audit        (probabilistic)",
    "final": "final",
}


def _label(stage: str) -> str:
    return _STAGE_LABELS.get(stage, stage)


def _reasoning_marker(record: dict) -> str:
    match record.get("reasoning_first"):
        case True:
            return "  [reasoning written before verdict ✓]"
        case False:
            return "  [!! VERDICT WRITTEN BEFORE REASONING !!]"
        case _:
            return ""


def render() -> int:
    records = load_records()
    if not records:
        print("No log records yet. Run with --run all to produce some.")
        return 1

    runs = group_runs(records)
    print(f"\n{len(runs)} run(s) in the log\n")

    for run_id, entries in runs:
        head = entries[0]
        total_ms = sum(e.get("duration_ms", 0.0) for e in entries)
        print(RULE)
        print(
            f"run {run_id}  ·  {head['architecture']}  ·  issue #{head['issue_id']}"
            f"  ·  {total_ms:.0f}ms total"
        )
        print(f"{head['ts']}")
        print(RULE)

        for index, entry in enumerate(entries):
            last = index == len(entries) - 1
            elbow = "└─" if last else "├─"
            pipe = "  " if last else "│ "

            risk = entry.get("risk_level")
            risk_tag = f"  risk_level={risk}" if risk else ""
            attempts = entry.get("attempts")
            attempt_tag = (
                f"  attempts={attempts}" if attempts and attempts > 1 else ""
            )

            print(
                f"{elbow} {_label(entry['stage']):<36} "
                f"{entry['outcome']:<18} {entry['duration_ms']:>7.0f}ms"
                f"{risk_tag}{attempt_tag}"
            )
            if entry.get("input_summary"):
                print(f"{pipe}    in  : {entry['input_summary']}")
            if entry.get("output_summary"):
                print(
                    f"{pipe}    out : {entry['output_summary']}"
                    f"{_reasoning_marker(entry)}"
                )
            if entry.get("detail"):
                print(f"{pipe}    note: {entry['detail']}")
            if not last:
                print(pipe)

        print()

    return 0


def run_scenarios(which: str) -> None:
    ensure_sandbox()
    clear_log()
    reset_public_comments()
    reset_labels()

    if which in ("malicious", "all"):
        run_isolated(load_issue("malicious"))
    if which == "all":
        run_isolated(load_issue("benign"))
        run_isolated(load_issue("malicious"), simulate_audit_bypass=True)
        run_baseline(load_issue("malicious"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run",
        choices=("malicious", "all"),
        help="run scenarios (clearing the log first) before rendering",
    )
    args = parser.parse_args()

    if args.run:
        try:
            run_scenarios(args.run)
        except openai.AuthenticationError:
            print("\nFAILED: the API key was rejected. Check DEEPSEEK_API_KEY in .env.", file=sys.stderr)
            return 1
        except openai.APIConnectionError as exc:
            print(f"\nFAILED: could not reach the API — {exc}", file=sys.stderr)
            return 1
        except openai.APIStatusError as exc:
            print(f"\nFAILED: API error {exc.status_code} — {exc.message}", file=sys.stderr)
            return 1

    return render()


if __name__ == "__main__":
    raise SystemExit(main())
