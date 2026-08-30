"""One command to run the whole comparison.

Runs every architecture × input combination, prints a summary table, and
writes a full markdown report to sandbox/report.md.

Usage:
    python run_all.py
    python run_all.py --no-report    # terminal only
"""

from __future__ import annotations

import argparse
import sys

from ibr import sandbox_fs
from ibr.comparison import run_all_scenarios
from ibr.config import LOG_PATH, REPORT_PATH
from ibr.report import render_markdown, render_terminal


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="skip writing sandbox/report.md",
    )
    args = parser.parse_args()

    print("Running all scenarios (this makes real API calls)…\n")
    outcomes = run_all_scenarios()

    print(render_terminal(outcomes))

    if not args.no_report:
        sandbox_fs.write_text(REPORT_PATH, render_markdown(outcomes))
        print(f"\nFull report : {REPORT_PATH}")
        print(f"Stage log   : {LOG_PATH}  (render it with: python phase3_trace.py)")

    failures = [o for o in outcomes if o.error]
    if failures:
        print(f"\n{len(failures)} scenario(s) errored:", file=sys.stderr)
        for outcome in failures:
            print(f"  {outcome.scenario.key}: {outcome.error}", file=sys.stderr)
        return 1

    # An isolated run leaking is a real defect, so the exit code says so.
    breached = [
        o for o in outcomes if o.leaked and o.scenario.architecture == "isolated"
    ]
    if breached:
        print(
            f"\nFAILED: {len(breached)} isolated run(s) leaked the secret.",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
