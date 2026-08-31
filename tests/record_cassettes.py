"""Record the API exchanges that tests/test_replay.py replays.

Needs a real key and spends a little money. Run it when a prompt, a model id,
or a tool definition changes — the replay tests will tell you, by name, when
that has happened.

    python tests/record_cassettes.py
    python tests/record_cassettes.py --only isolated_malicious

Recordings are committed. They are small, they contain only the fields this
project reads, and the only "secret" anywhere near them is the fixed
`fake-sk-…` placeholder.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import openai  # noqa: E402

from ibr.baseline_agent import run_baseline  # noqa: E402
from ibr.bootstrap import ensure_sandbox, reset_labels, reset_public_comments  # noqa: E402
from ibr.issues import load_issue  # noqa: E402
from ibr.llm import build_client  # noqa: E402
from ibr.pipeline import run_isolated  # noqa: E402
from tests.replay import RecordingClient, save  # noqa: E402


def _isolated(name: str, *, bypass: bool) -> Callable[[RecordingClient], None]:
    def run(client: RecordingClient) -> None:
        reset_public_comments()
        reset_labels()
        run_isolated(
            load_issue(name),
            client=cast("Any", client),
            simulate_audit_bypass=bypass,
        )

    return run


def _baseline(name: str) -> Callable[[RecordingClient], None]:
    def run(client: RecordingClient) -> None:
        reset_public_comments()
        run_baseline(load_issue(name), client=cast("Any", client))

    return run


# Chosen for coverage of the paths the offline suite cannot reach: the four
# pipeline stages, the short-circuit, the bypass branch, and the baseline's
# multi-turn tool loop including a read_file that succeeds.
SCENARIOS: dict[str, Callable[[RecordingClient], None]] = {
    "isolated_benign": _isolated("benign", bypass=False),
    "isolated_malicious": _isolated("malicious", bypass=False),
    "isolated_malicious_bypassed": _isolated("malicious", bypass=True),
    "baseline_benign": _baseline("benign"),
    "baseline_malicious": _baseline("malicious"),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--only", help="comma-separated cassette names instead of all of them"
    )
    args = parser.parse_args()

    wanted = (
        [n.strip() for n in args.only.split(",")] if args.only else list(SCENARIOS)
    )
    unknown = [n for n in wanted if n not in SCENARIOS]
    if unknown:
        print(
            f"FAILED: unknown cassette(s) {unknown}; have {list(SCENARIOS)}",
            file=sys.stderr,
        )
        return 1

    ensure_sandbox()
    print(f"Recording {len(wanted)} cassette(s) against the real API…\n")

    for name in wanted:
        recorder = RecordingClient(build_client(timeout=120.0))
        try:
            SCENARIOS[name](recorder)
        except openai.APIError as exc:
            print(f"  {name}: FAILED — {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        if not recorder.interactions:
            print(f"  {name}: FAILED — no API calls were made", file=sys.stderr)
            return 1
        path = save(name, recorder)
        print(f"  {name}: {len(recorder.interactions)} interaction(s) -> {path.name}")

    print("\nDone. Run `python tests/test_replay.py` to check they replay.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
