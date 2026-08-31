"""Install a pre-push hook that runs verify.py.

Optional and local — git hooks are not version-controlled, so this cannot be
imposed on a contributor. It exists because the failure it prevents was not a
knowledge problem: the clean-checkout pass was known, documented, and skipped
anyway because it was a step to remember rather than a step that ran.

    python tools/install_hooks.py
    python tools/install_hooks.py --uninstall

The hook runs the offline checks only. The live ones cost money, so they stay a
deliberate `python verify.py --live`.
"""

from __future__ import annotations

import argparse
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MARKER = "# installed by tools/install_hooks.py"

HOOK = f"""#!/bin/sh
{MARKER}
#
# Runs the same checks CI runs, plus the clean-checkout pass that CI cannot
# skip and a developer machine can. Bypass with `git push --no-verify` when you
# genuinely mean to.
set -e
echo "pre-push: running verify.py"
"{sys.executable}" "{ROOT / 'verify.py'}"
"""


def hooks_dir() -> Path | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--git-path", "hooks"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    path = Path(result.stdout.strip())
    return path if path.is_absolute() else ROOT / path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uninstall", action="store_true")
    args = parser.parse_args()

    directory = hooks_dir()
    if directory is None:
        print("not a git repository, or git is unavailable", file=sys.stderr)
        return 1
    directory.mkdir(parents=True, exist_ok=True)
    hook = directory / "pre-push"

    if args.uninstall:
        if hook.exists() and MARKER in hook.read_text(encoding="utf-8"):
            hook.unlink()
            print(f"removed {hook}")
        else:
            print("no hook of ours installed; leaving anything else alone")
        return 0

    if hook.exists() and MARKER not in hook.read_text(encoding="utf-8"):
        print(
            f"{hook} exists and was not written by this script. Refusing to "
            "overwrite it — merge the two by hand.",
            file=sys.stderr,
        )
        return 1

    hook.write_text(HOOK, encoding="utf-8", newline="\n")
    hook.chmod(hook.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print(f"installed {hook}")
    print("  runs: python verify.py  (offline checks + clean-checkout pass)")
    print("  bypass once with: git push --no-verify")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
