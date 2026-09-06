"""Where the executor's actions go.

The executor decides *what* to do; a sink is *where it lands*. Separating them
is what lets this architecture be pointed at something other than
`sandbox/public_comments.txt` without touching the part that has to be trusted.

Note what a sink is not allowed to be: a place where the decision gets
reconsidered. Sinks receive an already-chosen action and a body that is already
one of the four templates. A sink that filtered, rewrote, or vetoed would be a
second decision point, and the whole claim of this project is that there is
exactly one — the `match` statement in `ibr/executor.py`.

`DryRunSink` exists because the first thing anyone sensible does against real
data is look at what *would* have happened. Build a real sink on top of it
rather than beside it: run in dry-run until the recorded actions look right,
then swap.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Protocol, runtime_checkable

from . import sandbox_fs
from .config import LABELS_PATH, LEDGER_PATH, PUBLIC_COMMENTS_PATH


def utc_now() -> str:
    """Local to this module so `sinks` keeps depending on nothing above it.

    `observability` has the same one-liner. Importing it here would put a
    layer-2 module's logger inside the sink protocol's own module, and
    `test_dependency_layers_have_not_inverted` would be right to object.
    """
    return datetime.now(UTC).isoformat(timespec="milliseconds")


@runtime_checkable
class ActionSink(Protocol):
    """The two things the executor can cause to happen in the world.

    Structural, not inherited: anything with these two methods qualifies, so
    an adopter does not have to import from this package to integrate.
    """

    def publish_comment(self, issue_id: str, body: str) -> None:
        """Make `body` publicly visible on the issue.

        `body` is always one of the executor's static templates. A sink must
        publish it as given.
        """

    def add_label(self, issue_id: str, label: str) -> None:
        """Attach `label` to the issue. Always from the fixed action set."""


@dataclass(frozen=True)
class SandboxActionSink:
    """The default: append to the simulated public surfaces under sandbox/.

    Every write goes through sandbox_fs, so the whitelist applies to the
    executor's own output as well as to anything an agent asks to read.
    """

    surface: str = "isolated pipeline"

    def publish_comment(self, issue_id: str, body: str) -> None:
        header = f"\n----- comment on issue #{issue_id} ({self.surface}) -----\n"
        sandbox_fs.append_text(PUBLIC_COMMENTS_PATH, header + body.rstrip() + "\n")

    def add_label(self, issue_id: str, label: str) -> None:
        sandbox_fs.append_text(LABELS_PATH, f"issue #{issue_id}: {label}\n")


@dataclass(frozen=True)
class RecordedAction:
    kind: str  # "comment" | "label"
    issue_id: str
    payload: str


@dataclass
class DryRunSink:
    """Records what would have happened and writes nothing.

    The point of running against real data first in dry-run is not caution for
    its own sake — it is that the recorded actions are reviewable, and a review
    of "what this would have posted" is the only cheap way to find out that a
    template reads badly on a real issue, or that the action distribution is
    wrong, before anyone sees it.
    """

    actions: list[RecordedAction] = field(default_factory=list)

    def publish_comment(self, issue_id: str, body: str) -> None:
        self.actions.append(RecordedAction("comment", issue_id, body))

    def add_label(self, issue_id: str, label: str) -> None:
        self.actions.append(RecordedAction("label", issue_id, label))

    @property
    def comments(self) -> list[RecordedAction]:
        return [a for a in self.actions if a.kind == "comment"]

    @property
    def labels(self) -> list[RecordedAction]:
        return [a for a in self.actions if a.kind == "label"]


DEFAULT_SINK: ActionSink = SandboxActionSink()


# --- Idempotency ------------------------------------------------------------
#
# ARCHITECTURE.md listed this as something the architecture does not give you:
# "Running the same issue twice posts twice. A real sink needs a dedupe key."
# Running a batch over real data is what makes that stop being a footnote — a
# 165-issue run that dies at 120 has to be resumable, and resuming must not
# re-post the first 120.
#
# The first half of that sentence is still true of the default path and the
# second half is not, so ARCHITECTURE.md now says "idempotency is opt-in" and
# names this class. What stayed deliberate: wrapping is the adopter's call,
# because the default sink writes to `sandbox/` where a duplicate costs
# nothing, and a ledger that nobody asked for is a file nobody knows to clean
# up.


class DanglingIntent(RuntimeError):
    """An action was started and never confirmed. Refusing to guess."""


@dataclass(frozen=True)
class ActionKey:
    """What makes two actions the same action.

    The body is hashed rather than stored: it is one of four static templates,
    so the hash is short and comparing it catches the case that matters — the
    same issue, the same action, but different text, which is a different
    action and must not be deduplicated away.
    """

    issue_id: str
    kind: str
    digest: str

    @classmethod
    def of(cls, kind: str, issue_id: str, payload: str) -> ActionKey:
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
        return cls(issue_id=issue_id, kind=kind, digest=digest)

    def __str__(self) -> str:
        return f"{self.kind}:{self.issue_id}:{self.digest}"


@dataclass
class ActionLedger:
    """Append-only record of which actions have been performed.

    Two phases per action, not one, because the single-phase versions are both
    wrong. Recording only before the sink runs marks an action done that may
    never have happened; recording only after loses the record if the process
    dies mid-call, and the retry posts twice. So an `intent` line goes down
    first and a `done` line after, and a resumed run that finds an intent with
    no `done` **refuses** rather than choosing which failure to risk.

    That refusal is the fail-closed rule applied to the one place in this
    project that has a side effect outside the process (PROJECT_SPEC.md §1.4).
    An operator resolves it by looking at the destination and calling
    `confirm` or `discard`, which is a decision a person should make.

    One ledger, one file, deliberately not sharded the way `SampleStore` is:
    idempotency needs a single source of truth per action key, and any shard
    combination being fine is exactly the property this class cannot have.
    `run_batch`'s `concurrency>1` path shares one `ActionLedger` instance
    across every `ThreadPoolExecutor` worker — the same object, the same
    `self.path` — which is precisely the scenario `_lock` below exists for:
    `_heal_torn_tail` reads the whole file, decides, and sometimes rewrites it
    with a truncating `write_text`, and two threads racing that sequence
    unlocked can have one thread's stale read overwrite the other's
    already-appended record, silently. Reproduced before this lock existed:
    thread A's `intend()` completes and appears in `state()`, thread B's own
    `_append` (using a read captured before A's write) then calls
    `write_text` and the key disappears from the file entirely.

    The lock is in-process only, which is what `run_batch`'s own concurrency
    model is — one process, many threads sharing one object. It does not
    reach across processes, and it does not close the separate, disclosed
    limitation that two callers can still race a `check()` against an
    `intend()` for the *same* key (ARCHITECTURE.md already states the append
    itself carries no ordering guarantee beyond one call being atomic); it
    closes the data-loss and stale-read window `_heal_torn_tail`'s rewrite
    introduced.

    That window was originally closed for `_append` only. A second review
    found `state()` (and therefore `check()`) reading straight past it
    unlocked: `_heal_torn_tail`'s rewrite truncates the whole file before
    writing the new content, so a `check()` for one key landing in that gap
    could see the file empty or partial and report an unrelated,
    already-`done` key as `fresh` — reachable through
    `IdempotentSink._once` on every single action, not only while healing.
    `state()` takes `_lock` too now, for exactly that reason.
    """

    path: Path = LEDGER_PATH
    _lock: Lock = field(default_factory=Lock, repr=False, compare=False)

    def _lines(self) -> list[dict[str, str]]:
        if not sandbox_fs.exists(self.path):
            return []
        text = sandbox_fs.read_text(self.path)
        lines = text.splitlines()
        # A torn last line is a crash mid-append and is recoverable; a torn
        # line anywhere else means the file was corrupted by something other
        # than an interrupted write, and guessing which actions happened is
        # exactly what this class exists not to do.
        #
        # "Last" alone is not the test. `_append` writes one complete
        # `json + "\n"` per call, so a file ending in a newline contains only
        # whole records — a malformed line in a terminated file is damage, even
        # when it happens to be last. The first version of this method checked
        # position only, which silently dropped exactly the case the class is
        # for: a `done` line lost to corruption leaves an intent that reads as
        # never-attempted, and the resumed run publishes a second time. Under
        # the rule below that same file raises and an operator decides.
        #
        # `ibr/variance.py`'s SampleStore settled this first and states the
        # reasoning at `_load`; this is the same rule, not a second one.
        may_be_mid_write = bool(text) and not text.endswith("\n")
        entries: list[dict[str, str]] = []
        for number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                if may_be_mid_write and number == len(lines):
                    continue
                raise DanglingIntent(
                    f"{self.path}:{number} is not valid JSON. The ledger says "
                    "which actions have already been taken; a corrupted one "
                    "cannot be repaired by inference."
                ) from None
            entries.append(entry)
        return entries

    def state(self) -> dict[str, str]:
        """Latest phase per action key. Later lines win, which is what makes
        `confirm` and `discard` work by appending rather than rewriting.

        Takes `_lock`, the same one `_append` holds across its heal-then-write
        sequence: `_heal_torn_tail`'s rewrite branch truncates the whole file
        on open and only writes the new content afterward, so an unlocked
        read landing in that gap could see the file empty or partial and
        report an unrelated, already-`done` key as `fresh` — a real
        duplicate-action risk through `check()`, not just a stale read. A
        second review reproduced exactly that before this lock covered
        `state()` too; see `test_state_and_check_also_wait_for_the_ledger_lock`.
        """
        with self._lock:
            latest: dict[str, str] = {}
            for entry in self._lines():
                key = entry.get("key", "")
                phase = entry.get("phase", "")
                if key and phase:
                    latest[key] = phase
            return latest

    def _heal_torn_tail(self) -> None:
        """Terminate an unterminated last line before writing, one way or another.

        `_lines()` accepts an unterminated, unparsable last line as a crash
        mid-append and skips it on read — the whole point of the class. But
        `sandbox_fs.append_text` opens in append mode and writes at EOF with
        no terminator of its own, so the *next* write, whatever it is, lands
        glued onto that fragment instead of starting a fresh line. Once that
        happens the merged line is fully terminated and permanently
        unparsable, and `_lines()` no longer tolerates it: every future
        `state()` and `check()`, for every key, raises `DanglingIntent`. That
        next write is usually the operator's own remedy — `check()` tells
        them to call `confirm()` or `discard()` — so the documented fix for a
        dangling intent was the thing that bricked the ledger. Verified by
        reproducing the crash, the resume, and the brick before this existed.

        Two cases, told apart by whether the trailing fragment actually
        parses. Genuinely torn — discard it, before any write. Safe to: it
        never finished, so it carries no information `_lines()` could already
        recover, and the state it would have recorded is exactly the decision
        this call is about to make explicitly (`intend`, `done`, `confirm`, or
        `discard`). Complete but merely missing its trailing byte — keep it
        and just add the newline; discarding a finished record because of one
        lost byte would be a second way to lose data, not a fix for the first.
        Either way, the file ends in a newline before the new record is
        written, which is the invariant `append_text` depends on to never
        merge two records into one line.
        """
        if not sandbox_fs.exists(self.path):
            return
        text = sandbox_fs.read_text(self.path)
        if not text or text.endswith("\n"):
            return  # nothing pending, or already terminated
        head, _, tail = text.rpartition("\n")
        try:
            json.loads(tail)
        except json.JSONDecodeError:
            # Genuinely torn: discard the fragment. `append_text` opens at
            # EOF with no separator of its own, so leaving it in place would
            # corrupt the *next* write either way — glued onto a fragment
            # that will never parse, or (see below) onto a complete record
            # that would then read as one malformed line instead of two
            # valid ones.
            sandbox_fs.write_text(self.path, f"{head}\n" if head else "")
        else:
            # Complete record — only the trailing newline byte was lost, and
            # `_lines()` already parses that fine on its own. Nothing to
            # discard, but the next append still needs a separator, or it
            # would glue onto this line and corrupt it too.
            sandbox_fs.write_text(self.path, f"{text}\n")

    def _append(self, key: ActionKey, phase: str) -> None:
        # Heal-then-append has to be one atomic step from every other
        # caller's point of view: `_heal_torn_tail` can rewrite the whole
        # file, and two threads racing that rewrite is exactly how one
        # thread's already-appended record used to vanish. See the class
        # docstring; this lock is what makes that reproduction no longer
        # reproduce.
        with self._lock:
            self._heal_torn_tail()
            sandbox_fs.append_text(
                self.path,
                json.dumps(
                    {"key": str(key), "phase": phase, "ts": utc_now()},
                    ensure_ascii=False,
                    sort_keys=True,
                )
                + "\n",
            )

    def check(self, key: ActionKey) -> str:
        """"fresh", "done", or raise on a dangling intent."""
        phase = self.state().get(str(key), "fresh")
        if phase == "intent":
            raise DanglingIntent(
                f"action {key} was started and never confirmed. Look at the "
                "destination, then call ActionLedger.confirm(key) if it landed "
                "or .discard(key) if it did not. Refusing to guess: retrying "
                "risks a duplicate, skipping risks losing the action."
            )
        return "done" if phase == "done" else "fresh"

    def intend(self, key: ActionKey) -> None:
        self._append(key, "intent")

    def done(self, key: ActionKey) -> None:
        self._append(key, "done")

    def confirm(self, key: ActionKey) -> None:
        """Operator decision: the action did land. Do not repeat it."""
        self._append(key, "done")

    def discard(self, key: ActionKey) -> None:
        """Operator decision: the action did not land. It may be retried."""
        self._append(key, "discarded")


@dataclass
class IdempotentSink:
    """Wraps a sink so the same action cannot be performed twice.

    A decorator rather than a base class, so it composes with whatever an
    adopter actually writes: `IdempotentSink(inner=MyGitHubSink())`.

    Note the direction of the failure mode this introduces. Skipping a
    duplicate **narrows** what the system does, so it cannot widen the set of
    reachable actions and the structural claim is untouched. Every skip is
    recorded on `skipped` rather than swallowed, because a run that quietly did
    nothing looks exactly like a run that quietly worked.
    """

    inner: ActionSink = DEFAULT_SINK
    ledger: ActionLedger = field(default_factory=ActionLedger)
    skipped: list[ActionKey] = field(default_factory=list)
    performed: list[ActionKey] = field(default_factory=list)

    def _once(self, kind: str, issue_id: str, payload: str) -> bool:
        key = ActionKey.of(kind, issue_id, payload)
        if self.ledger.check(key) == "done":
            self.skipped.append(key)
            return False
        self.ledger.intend(key)
        return True

    def _settle(self, kind: str, issue_id: str, payload: str) -> None:
        key = ActionKey.of(kind, issue_id, payload)
        self.ledger.done(key)
        self.performed.append(key)

    def publish_comment(self, issue_id: str, body: str) -> None:
        if not self._once("comment", issue_id, body):
            return
        self.inner.publish_comment(issue_id, body)
        self._settle("comment", issue_id, body)

    def add_label(self, issue_id: str, label: str) -> None:
        if not self._once("label", issue_id, label):
            return
        self.inner.add_label(issue_id, label)
        self._settle("label", issue_id, label)
