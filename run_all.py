"""One command to run the whole comparison.

Runs every architecture × input combination, prints a summary table, and
writes a full markdown report to sandbox/report.md.

Usage:
    python run_all.py               # live: real API calls, needs a key
    python run_all.py --replay      # recorded exchanges: no key, no network
    python run_all.py --no-report   # terminal only
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, cast

from ibr import report, sandbox_fs
from ibr.bootstrap import ensure_sandbox
from ibr.comparison import SCENARIOS, Outcome, run_all_scenarios, run_scenario
from ibr.config import LOG_PATH, REPORT_PATH
from ibr.observability import clear_log


def run_from_cassettes() -> list[Outcome]:
    """Drive the real scenarios from recorded responses.

    Uses `run_scenario` rather than `run_scenario_sampled`: sampling re-runs
    until something leaks, and each extra attempt would ask the cassette for
    interactions that were never recorded. One cassette, one run.

    Every cassette is asserted fully consumed. If the code starts making fewer
    calls than were recorded, that is either a lost code path or a stale
    recording, and this stops rather than quietly showing a partial scenario.
    """
    # The cassette player lives next to the recordings it plays, and is
    # imported here rather than at module level so the live path does not
    # depend on tests/ existing at all. Reused rather than reimplemented in
    # ibr/: a second fingerprint check would drift, and a replay that stops
    # verifying the request shows you something other than the code you read.
    sys.path.insert(0, str(Path(__file__).resolve().parent / "tests"))
    import replay

    ensure_sandbox()
    clear_log()
    available = set(replay.available())

    outcomes: list[Outcome] = []
    for scenario in SCENARIOS:
        if scenario.deterministic:
            outcomes.append(run_scenario(scenario))
            continue
        if scenario.key not in available:
            raise SystemExit(
                f"no cassette for scenario {scenario.key!r}. Record one with "
                "`python tests/record_cassettes.py` (needs a key), or run "
                "without --replay."
            )
        client = replay.load(scenario.key)
        # Same cast the replay tests use: ReplayClient is a stand-in for
        # openai.OpenAI, structurally compatible for the one call this project
        # makes but not an instance of it.
        outcomes.append(run_scenario(scenario, client=cast("Any", client)))
        client.assert_fully_consumed()
    return outcomes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--replay",
        action="store_true",
        help="replay recorded exchanges instead of calling the API "
        "(no key, no network, identical every time)",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="skip writing sandbox/report.md",
    )
    args = parser.parse_args()

    if args.replay:
        print("Replaying recorded exchanges (no API calls, no key needed)…\n")
        provenance = report.REPLAY
        outcomes = run_from_cassettes()
    else:
        print("Running all scenarios (this makes real API calls)…\n")
        provenance = report.LIVE
        outcomes = run_all_scenarios()

    print(report.render_terminal(outcomes, provenance=provenance))

    if not args.no_report:
        sandbox_fs.write_text(
            REPORT_PATH, report.render_markdown(outcomes, provenance=provenance)
        )
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
