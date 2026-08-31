"""Run every check that must pass before pushing.

This exists because relying on memory failed. The offline suite had been
verified in a clean git worktree — no `.env`, matching what CI sees — several
times by hand, and then three new assertions felt small enough to skip it for.
They needed an API key to prove they needed no API key, passed locally, and
broke CI. The check that would have caught it was the one that got skipped
because it was a step to remember rather than a step to run.

So: one command. Adding a check here is how it stops being optional.

    python verify.py                 # everything CI runs, plus the clean-checkout pass
    python verify.py --live          # also the assertions that call the real API
    python verify.py --skip-clean    # faster loop while iterating; not before pushing

The clean-checkout pass is the one that cannot be replaced by running the tests
normally. A developer machine has a `.env`; CI does not. Any test that quietly
depends on a key passes here and fails there, and no amount of care substitutes
for running it without one.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PYTHON = sys.executable

OFFLINE_SUITES = (
    ("tests/test_phase0.py", ()),
    ("tests/test_phase2.py", ("--offline",)),
    ("tests/test_phase3.py", ("--offline",)),
    ("tests/test_phase4.py", ("--offline",)),
    ("tests/test_attack_corpus.py", ("--offline",)),
    ("tests/test_variance.py", ("--offline",)),
    ("tests/test_suppressions.py", ()),
    ("tests/test_replay.py", ()),
)

LIVE_SUITES = (
    ("tests/test_phase1.py", ()),
    ("tests/test_variance.py", ()),
)

COVERAGE_GATED = "ibr/schemas.py,ibr/executor.py,ibr/sandbox_fs.py,ibr/config.py"


class Reporter:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.skipped: list[str] = []

    def run(self, label: str, argv: list[str], *, cwd: Path = ROOT) -> bool:
        print(f"  {label} … ", end="", flush=True)
        started = time.perf_counter()
        result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True)
        elapsed = time.perf_counter() - started
        if result.returncode == 0:
            print(f"ok ({elapsed:.1f}s)")
            return True
        print(f"FAILED ({elapsed:.1f}s)")
        tail = (result.stdout + result.stderr).strip().splitlines()
        for line in tail[-14:]:
            print(f"      {line}")
        self.failures.append(label)
        return False

    def skip(self, label: str, why: str) -> None:
        print(f"  {label} … skipped ({why})")
        self.skipped.append(f"{label}: {why}")


def static_checks(report: Reporter) -> None:
    print("\nStatic analysis")
    report.run("ruff", [PYTHON, "-m", "ruff", "check", "."])
    report.run("mypy", [PYTHON, "-m", "mypy"])


def offline_with_coverage(report: Reporter) -> None:
    print("\nOffline assertions (with coverage)")
    coverage_file = ROOT / ".coverage"
    coverage_file.unlink(missing_ok=True)
    for script, extra in OFFLINE_SUITES:
        report.run(
            script,
            [
                PYTHON,
                "-m",
                "coverage",
                "run",
                "--append",
                "--source=ibr",
                script,
                *extra,
            ],
        )
    report.run(
        f"coverage == 100% on {COVERAGE_GATED.count(',') + 1} security modules",
        [
            PYTHON,
            "-m",
            "coverage",
            "report",
            f"--include={COVERAGE_GATED}",
            "--fail-under=100",
        ],
    )


def clean_checkout(report: Reporter) -> None:
    """Run the offline suite where no `.env` exists, as CI does.

    Uses a git worktree of HEAD plus the working tree's own files copied over,
    so uncommitted changes are covered too — checking only HEAD would verify
    the wrong thing right before a push.
    """
    print("\nClean checkout (no .env, as CI sees it)")
    if not shutil.which("git"):
        report.skip("clean checkout", "git not found")
        return

    target = ROOT / ".verify-clean"
    subprocess.run(
        ["git", "worktree", "remove", str(target), "--force"],
        cwd=ROOT,
        capture_output=True,
    )
    created = subprocess.run(
        ["git", "worktree", "add", "--detach", str(target), "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if created.returncode != 0:
        report.skip("clean checkout", created.stderr.strip()[:120])
        return

    try:
        tracked = subprocess.run(
            ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout.split()
        for rel in tracked:
            source = ROOT / rel
            if not source.is_file():
                continue
            destination = target / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

        if (target / ".env").exists():
            print("      .env leaked into the worktree; the pass would be void")
            report.failures.append("clean checkout: .env present")
            return

        for script, extra in OFFLINE_SUITES:
            report.run(
                f"{script} (no key)",
                [PYTHON, script, *extra],
                cwd=target,
            )
    finally:
        subprocess.run(
            ["git", "worktree", "remove", str(target), "--force"],
            cwd=ROOT,
            capture_output=True,
        )
        subprocess.run(["git", "worktree", "prune"], cwd=ROOT, capture_output=True)


def live_checks(report: Reporter) -> None:
    print("\nLive assertions (real API calls, costs money)")
    for script, extra in LIVE_SUITES:
        report.run(f"{script} (live)", [PYTHON, script, *extra])
    print("\nLive pipeline smoke")
    report.run("phase2_isolated.py --scene 2", [PYTHON, "phase2_isolated.py", "--scene", "2"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--live",
        action="store_true",
        help="also run the assertions that call the real API",
    )
    parser.add_argument(
        "--skip-clean",
        action="store_true",
        help="skip the clean-checkout pass (faster loop; not before pushing)",
    )
    args = parser.parse_args()

    report = Reporter()
    static_checks(report)
    offline_with_coverage(report)
    if args.skip_clean:
        report.skip("clean checkout", "--skip-clean")
    else:
        clean_checkout(report)
    if args.live:
        live_checks(report)

    print("\n" + "─" * 68)
    if report.failures:
        print(f"FAILED — {len(report.failures)} check(s):")
        for failure in report.failures:
            print(f"  • {failure}")
        return 1

    print("All checks passed.")
    for skipped in report.skipped:
        print(f"  skipped: {skipped}")
    if not args.live:
        print(
            "\nNote: the live assertions did not run. They cover the retry loop,\n"
            "the multi-turn baseline, and the real pipeline. Use --live before\n"
            "pushing a change to ibr/llm.py, ibr/pipeline.py or ibr/baseline_agent.py."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
