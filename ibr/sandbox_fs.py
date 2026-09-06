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
    """A path resolved somewhere it must not, or to something that isn't a
    plain file in the sandbox. Always fatal."""


# Windows resolves these names to hardware/pseudo devices no matter which
# directory they appear in, and regardless of extension: `sandbox/COM1` opens a
# serial port, not a file in sandbox/. Containment alone therefore isn't enough
# — the resolved path can sit inside the sandbox while the I/O goes somewhere
# else entirely. Reading COM1 on a machine with a serial port can block
# indefinitely, which an attacker-supplied path reaches directly through the
# baseline agent's read_file tool.
#
# Checked on every platform, not just Windows: the corpus and fixtures are
# shared, and a guard that only holds on some machines is worse than none
# because it makes the machines where it fails the surprising ones.
_WINDOWS_DEVICE_NAMES = frozenset(
    {"con", "prn", "aux", "nul", "conin$", "conout$"}
    | {f"com{n}" for n in range(1, 10)}
    | {f"lpt{n}" for n in range(1, 10)}
)


def resolve_in_sandbox(path: str | Path) -> Path:
    """Resolve `path` and prove it lands inside the sandbox, or raise.

    Resolution happens *before* the containment check, not after: `..` segments,
    symlinks, and short 8.3-style Windows names are all collapsed first.
    Checking the raw string instead would let `issues/../../../secrets` through.
    Relative paths are interpreted against the sandbox root, never the CWD.
    """
    root = SANDBOX_ROOT.resolve()
    try:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = root / candidate
        resolved = candidate.resolve()
    except (OSError, ValueError) as exc:
        # One failure mode, not two. Resolution can raise ValueError for a name
        # the OS refuses outright — an embedded null byte is the reachable case,
        # and a model can put one in a tool argument. Callers catch
        # SandboxViolation; a second exception type escapes their handler and
        # aborts the run instead of being reported back to the model, which is
        # both worse behaviour and a fail-open shape of failure.
        raise SandboxViolation(
            f"refusing to touch {path!r}: the path cannot be resolved ({exc})"
        ) from exc

    if not resolved.is_relative_to(root):
        raise SandboxViolation(
            f"refusing to touch {path!r}: resolves to {resolved}, outside {root}"
        )

    # Containment is necessary but not sufficient — see _WINDOWS_DEVICE_NAMES.
    # The stem is what matters: CON.txt is the console device too.
    for part in resolved.relative_to(root).parts:
        if _names_reserved_device(part):
            raise SandboxViolation(
                f"refusing to touch {path!r}: {part!r} names a reserved device, "
                "which the OS routes away from the sandbox directory"
            )
    return resolved


def _names_reserved_device(part: str) -> bool:
    """Does this path component name a Windows device, under any spelling?

    `part.split(".")[0].lower() in _WINDOWS_DEVICE_NAMES` was the whole check
    for a while, and it missed two spellings Windows treats identically to the
    plain name: a trailing space or dot (`"nul "`, `"con."` — the Win32 layer
    strips both before the name ever reaches the filesystem), and a trailing
    colon (`"nul:"` — a colon starts a stream selector, or, for a DOS device
    name, is accepted directly; either way the device opened is the same one).
    `Path.resolve()` does not strip any of these, so a component that reads as
    contained can still route to a device once the OS opens it — one attacker-
    supplied `read_file` argument away, through the baseline's tool call, and
    unbounded (`nul` returns instantly; `com1` on a machine with a serial port
    can block forever, since nothing in this package puts a timeout on a local
    read).

    So every spelling collapses to the same stem before comparison: strip
    trailing spaces and dots (in either order — done together, since Windows
    strips them as a combined run), then take the text before a colon, then
    before a literal dot.
    """
    stripped = part.rstrip(" .")
    stem = stripped.split(":", 1)[0].split(".")[0]
    return stem.lower() in _WINDOWS_DEVICE_NAMES


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
