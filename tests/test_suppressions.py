"""Every type-checker suppression must be registered with a reason.

This exists because of a specific incident. A `# type: ignore[call-overload]`
was added to `ibr/llm.py` to quiet mypy after a genuine fix. Because it sat on
the whole call expression, it collapsed the response object to `Any` and
switched off type checking for everything derived from it — concealing a
`.function` access on an SDK union whose non-function member lacks that
attribute. That was the *same* defect already fixed in `ibr/baseline_agent.py`,
hidden a second time by the comment written to tidy up after fixing it. It went
unnoticed for four commits.

The lesson is not "avoid suppressions". Some are correct: the openai package
types its message and tool parameters as TypedDict unions, and this project
builds them as plain dicts because conversations are assembled dynamically.
The lesson is that a suppression is a *deliberate reduction in checking*, and
adding one should cost the same as any other deliberate act: writing down what
is being given up and why.

So the inventory below is the contract. Adding a suppression fails this test
until it is registered; removing one fails until it is deregistered. Neither
can happen quietly.

Run standalone:
    python tests/test_suppressions.py
"""

from __future__ import annotations

import re
import sys
import tokenize
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "sandbox", "assets"}

# (file, mypy error code) -> (how many, why it is acceptable)
#
# The rationale is the point of the entry. "mypy complains" is not a rationale;
# what is being given up, and why that is safe, is.
REGISTERED: dict[tuple[str, str], tuple[int, str]] = {
    ("ibr/baseline_agent.py", "arg-type"): (
        2,
        "openai types `messages` and `tools` as TypedDict unions. The baseline "
        "conversation is assembled at runtime — assistant turns come back from "
        "model_dump(), tool results are appended in a loop — so satisfying the "
        "TypedDicts would mean casting at every append for no runtime benefit. "
        "Per-argument, so the response object keeps its real type and the rest "
        "of the loop stays checked. That last part is the whole lesson: a "
        "call-level ignore here would silently disable checking downstream.",
    ),
    ("audit_variance.py", "arg-type"): (
        1,
        "The subject list is built as heterogeneous tuples of "
        "(key, name, is_malicious, Issue) and destructured at the call site, so "
        "the Issue arrives typed as `object`. Narrow, local, and the value is "
        "immediately passed to a function that does type-check its parameter.",
    ),
}

_DIRECTIVE_RE = re.compile(r"#\s*type:\s*ignore(?:\[([A-Za-z0-9\-,\s]*)\])?")


def _python_files() -> list[Path]:
    found: list[Path] = []
    for path in ROOT.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        found.append(path)
    return sorted(found)


def _found_suppressions() -> tuple[dict[tuple[str, str], int], list[str]]:
    """Collect (file, code) -> count, plus any bare ignores with no code.

    Tokenised rather than grepped. This file and ibr/llm.py both discuss
    suppressions at length in prose, and a text scan counts that prose as
    suppressions — the first version of this test failed on its own docstring.
    Only real COMMENT tokens can carry a directive, and tokenize is what knows
    the difference between a comment and a string that looks like one.
    """
    counts: dict[tuple[str, str], int] = {}
    bare: list[str] = []
    for path in _python_files():
        rel = path.relative_to(ROOT).as_posix()
        with path.open("rb") as handle:
            for token in tokenize.tokenize(handle.readline):
                if token.type != tokenize.COMMENT:
                    continue
                comment = token.string.strip()
                # A directive is the entire comment (optionally followed by
                # more comment text). Prose that merely mentions the phrase
                # mid-sentence is not one.
                match = _DIRECTIVE_RE.match(comment)
                if not match:
                    continue
                codes = match.group(1)
                if not codes:
                    bare.append(f"{rel}:{token.start[0]}")
                    continue
                for code in (c.strip() for c in codes.split(",") if c.strip()):
                    counts[(rel, code)] = counts.get((rel, code), 0) + 1
    return counts, bare


def test_no_bare_type_ignore() -> None:
    """A codeless ignore suppresses every error on the line, present and future."""
    _, bare = _found_suppressions()
    assert not bare, (
        "bare `# type: ignore` (no error code) at: "
        + ", ".join(bare)
        + ". Name the specific code so the suppression cannot widen silently."
    )


def test_every_suppression_is_registered() -> None:
    found, _ = _found_suppressions()

    unregistered = sorted(k for k in found if k not in REGISTERED)
    assert not unregistered, (
        "type-checker suppressions not registered in tests/test_suppressions.py: "
        + ", ".join(f"{f} [{c}]" for f, c in unregistered)
        + ". Add an entry saying what checking is given up and why it is safe."
    )

    stale = sorted(k for k in REGISTERED if k not in found)
    assert not stale, (
        "registered suppressions that no longer exist: "
        + ", ".join(f"{f} [{c}]" for f, c in stale)
        + ". Remove the entry so the inventory stays honest."
    )

    for key, (expected, _why) in REGISTERED.items():
        actual = found[key]
        assert actual == expected, (
            f"{key[0]} has {actual} `{key[1]}` suppression(s), registry says "
            f"{expected}. Update the count and the rationale together — a new "
            "suppression should not inherit an old justification."
        )


def test_every_rationale_says_something() -> None:
    """"mypy complains" is not a reason."""
    for (path, code), (_count, why) in REGISTERED.items():
        assert len(why) > 120, f"{path} [{code}]: rationale too thin to review"
        lowered = why.lower()
        assert "mypy" not in lowered or "because" in lowered or "so " in lowered, (
            f"{path} [{code}]: rationale restates the error instead of "
            "explaining why the suppression is safe"
        )


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

    found, _ = _found_suppressions()
    print(f"\n{sum(found.values())} suppression(s) across {len(found)} site group(s)")
    print(f"{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
