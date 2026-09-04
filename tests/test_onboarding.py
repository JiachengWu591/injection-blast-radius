"""The claim that a stranger can run this in one command.

README.md says `mise run demo` works on an empty machine with no API key. That
is a promise about somebody else's laptop, so most of it cannot be asserted
here — what can be is that the command exists, that the thing it runs works
without a key, and that what it prints does not overstate what happened.

The last of those is the one that matters. A replayed run exercises the real
code path but no model decides anything during it, and a report that read as a
live result would be the project claiming evidence it does not have — the same
mistake as counting a failed audit as a detection.

Run standalone:
    python tests/test_onboarding.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ROOT = Path(__file__).resolve().parents[1]
MISE_TOML = ROOT / "mise.toml"

# Tasks README.md tells a reader to run, and whether each needs a key. A task
# renamed without updating the README is a broken first impression, which is
# the one that costs a reader.
DOCUMENTED_TASKS = {
    "demo": False,
    "demo:live": True,
    "trace": False,
    "test": False,
    "full": False,
    "matrix": True,
    "fp-rate": True,
    "dry-run": True,
    "corpus:real": True,
    "fp-rate:real": True,
}


def _config() -> dict:
    return tomllib.loads(MISE_TOML.read_text(encoding="utf-8"))


def test_mise_pins_an_exact_python() -> None:
    """">=3.12" would let a reader's machine pick something else.

    The point of a one-command demo is that the reader gets the result, not a
    debugging session about their interpreter.
    """
    tools = _config()["tools"]
    assert tools["python"] == "3.12", f"python is not pinned: {tools['python']!r}"
    assert "uv" in tools


def test_every_documented_task_exists() -> None:
    tasks = _config()["tasks"]
    missing = sorted(name for name in DOCUMENTED_TASKS if name not in tasks)
    assert not missing, (
        f"README.md documents mise task(s) that mise.toml does not define: "
        f"{missing}"
    )


def test_the_readmes_document_the_one_command_start() -> None:
    for name in ("README.md", "README.zh-CN.md"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "mise run demo" in text, f"{name} never shows the one-command start"
        assert "mise.toml" in text, f"{name} does not point at mise.toml"


def test_the_keyless_tasks_do_not_call_the_api() -> None:
    """A task advertised as needing no key must not reach for one.

    Checked against the command, not against a run: `attack_matrix.py` costs
    real money, so this asserts on what each task is wired to execute.
    """
    tasks = _config()["tasks"]
    live_scripts = {
        "run_all.py",
        "attack_matrix.py",
        "false_positive_rate.py",
        "batch_dry_run.py",
        "tools/fetch_real_corpus.py",
        "audit_variance.py",
        "model_comparison.py",
        "phase0_smoke.py",
        "phase1_baseline.py",
        "phase2_isolated.py",
    }
    for name, needs_key in DOCUMENTED_TASKS.items():
        if needs_key:
            continue
        commands = tasks[name].get("run", [])
        if isinstance(commands, str):
            commands = [commands]
        for command in commands:
            for script in live_scripts:
                if script not in command:
                    continue
                assert "--replay" in command, (
                    f"task {name!r} runs {script} without --replay but is "
                    "documented as needing no API key"
                )


def test_the_replay_report_never_claims_a_live_run() -> None:
    """The honesty gate on the keyless demo.

    If REPLAY ever rendered LIVE's wording, a reader would be told that rows
    generated from disk were "a real run against a real model". Asserted on the
    rendered text rather than the constant, because the rendering is what a
    reader sees.
    """
    from ibr.comparison import SCENARIOS, Outcome
    from ibr.report import LIVE, REPLAY, render_markdown, render_terminal

    outcomes = [Outcome(scenario=SCENARIOS[0], action="no_action")]

    replayed = render_markdown(outcomes, provenance=REPLAY)
    assert "real run against a real model" not in replayed
    assert "replay of a recorded exchange" in replayed
    assert "not a live run" in replayed
    # And it must say what the replay cannot show, not just what it is.
    assert "one recorded sample" in replayed

    live = render_markdown(outcomes, provenance=LIVE)
    assert "real run against a real model" in live
    assert "replay" not in live.split("## What was tested")[0].lower()

    terminal = render_terminal(outcomes, provenance=REPLAY)
    assert terminal.splitlines()[0].startswith("REPLAY")
    assert not render_terminal(outcomes, provenance=LIVE).startswith("REPLAY")


def test_the_replay_demo_runs_with_no_key_and_no_network() -> None:
    """The actual promise: this command works on a machine with nothing set up.

    Run as a subprocess with the key stripped from the environment, because
    importing the pipeline in-process would inherit whatever this machine has
    configured — and "works on my machine, which has a key" is exactly the
    failure this is meant to rule out.
    """
    env = {k: v for k, v in os.environ.items() if k != "DEEPSEEK_API_KEY"}
    result = subprocess.run(
        [sys.executable, "run_all.py", "--replay", "--no-report"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
    )
    assert result.returncode == 0, (
        f"`run_all.py --replay` failed with no key:\n{result.stdout}\n{result.stderr}"
    )
    assert "REPLAY" in result.stdout, "the replay run did not announce itself"

    # The headline result has to actually be in there, or the demo shows a
    # reader a table that makes no argument.
    assert "baseline runs that leaked the secret : 1" in result.stdout
    assert "isolated runs that leaked the secret : 0" in result.stdout


def main() -> int:
    tests = [
        (name, fn)
        for name, fn in sorted(globals().items())
        if name.startswith("test_") and callable(fn)
    ]
    failures = 0
    for name, fn in tests:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - the runner reports, never hides
            failures += 1
            print(f"FAIL  {name}\n        {type(exc).__name__}: {exc}")
        else:
            print(f"pass  {name}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
