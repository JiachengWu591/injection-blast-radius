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

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from . import sandbox_fs
from .config import LABELS_PATH, PUBLIC_COMMENTS_PATH


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
