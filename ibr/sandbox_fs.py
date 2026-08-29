"""Whitelisted filesystem access — the sandbox boundary.

Every read and write in this project goes through this module. It is what makes
"the demo can only touch ./sandbox" a property of the code (PROJECT_SPEC.md §6)
rather than a promise in the README.

This is the *outer* guard. It is not the structural boundary the project is
about — that one lives in the Executor's enum whitelist in a later phase. This
guard only bounds which bytes on disk are reachable at all.
"""

from __future__ import annotations

from pathlib import Path

from .config import SANDBOX_ROOT

_ENCODING = "utf-8"


class SandboxViolation(RuntimeError):
    """A path resolved to somewhere outside the sandbox. Always fatal."""


def resolve_in_sandbox(path: str | Path) -> Path:
    """Resolve `path` and prove it lands inside the sandbox, or raise.

    Resolution happens *before* the containment check, not after: `..` segments,
    symlinks, and short 8.3-style Windows names are all collapsed first.
    Checking the raw string instead would let `issues/../../../secrets` through.
    Relative paths are interpreted against the sandbox root, never the CWD.
    """
    root = SANDBOX_ROOT.resolve()
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()
    if not resolved.is_relative_to(root):
        raise SandboxViolation(
            f"refusing to touch {path!r}: resolves to {resolved}, outside {root}"
        )
    return resolved


def ensure_dir(path: str | Path) -> Path:
    target = resolve_in_sandbox(path)
    target.mkdir(parents=True, exist_ok=True)
    return target


def exists(path: str | Path) -> bool:
    return resolve_in_sandbox(path).exists()


def read_text(path: str | Path) -> str:
    """Read a sandbox file as UTF-8.

    The encoding is explicit everywhere in this module: on Windows the default
    would be the ANSI codepage, which silently mangles anything non-ASCII and
    would make the demo's behaviour depend on the operator's locale.
    """
    return resolve_in_sandbox(path).read_text(encoding=_ENCODING)


def write_text(path: str | Path, content: str) -> Path:
    target = resolve_in_sandbox(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    # newline="" keeps "\n" as written instead of translating to CRLF, so the
    # artifacts this demo produces are byte-identical across platforms.
    with target.open("w", encoding=_ENCODING, newline="") as handle:
        handle.write(content)
    return target


def append_text(path: str | Path, content: str) -> Path:
    target = resolve_in_sandbox(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding=_ENCODING, newline="") as handle:
        handle.write(content)
    return target
