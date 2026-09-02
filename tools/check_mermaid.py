"""Lint the mermaid diagrams for constructs GitHub's renderer rejects.

Why a hand-written lint rather than mermaid's own parser: mermaid is a
JavaScript library, and making `python verify.py` depend on node would break
the one thing the setup promises — one command, no extra toolchain. So this
checks the specific things that have actually gone wrong, and says plainly what
it cannot check.

**What this finds:** constructs that render differently, or not at all, under
the configuration GitHub uses (`securityLevel: 'strict'`, which turns off
`htmlLabels`), plus the structural mistakes that make a block unparseable —
an unbalanced fence, a node id that collides with a mermaid keyword, an
unquoted label containing a character mermaid treats as syntax.

**What this cannot find:** whether the diagram parses. That needs mermaid
itself. To check parsing for real, run the JavaScript parser once:

    npm install mermaid@11 jsdom
    node tools/check_mermaid.mjs ARCHITECTURE.md ARCHITECTURE.zh-CN.md

Run standalone:
    python tools/check_mermaid.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Words mermaid's flowchart grammar reserves. A node called `end` is the
# classic way to make a diagram silently stop rendering.
RESERVED_IDS = frozenset(
    {"end", "graph", "subgraph", "class", "classDef", "click", "style", "flowchart"}
)

# HTML that only works when htmlLabels is on. GitHub renders with
# securityLevel 'strict', which turns it off, so these reach the reader as
# literal text — "<b>report</b>" in the middle of a box. `<br/>` is the
# exception: mermaid converts it to a line break itself, either way.
HTML_LABEL_TAGS = re.compile(r"</?(?!br\s*/?>)[a-zA-Z][^<>]*>")

# Same reasoning: entity references are resolved by the HTML label path.
HTML_ENTITY = re.compile(r"&[a-zA-Z]+;|&#\d+;")


class DiagramProblem(Exception):
    """A diagram construct that will not survive GitHub's renderer."""


def _blocks(text: str) -> list[tuple[int, str, str]]:
    """Every fenced mermaid block as (line number, language, body)."""
    found: list[tuple[int, str, str]] = []
    for match in re.finditer(r"```(mermaid)\n(.*?)```", text, re.S):
        line_no = text[: match.start()].count("\n") + 1
        found.append((line_no, match.group(1), match.group(2)))
    return found


def _label_free(body: str) -> str:
    """The block with quoted labels blanked, so label text is not scanned."""
    return re.sub(r'"[^"]*"', '""', body)


def _without_annotations(body: str) -> str:
    """Blank out `<<interface>>` and friends before looking for HTML.

    `<<frozen>>` is mermaid's own annotation syntax for a classDiagram, not
    markup — but the inner `<frozen>` looks exactly like an HTML tag to a
    regex, which is how the first version of this lint reported six problems
    that were all correct code.
    """
    return re.sub(r"<<[^<>]*>>", "", body)


def problems_in(body: str, *, where: str) -> list[str]:
    found: list[str] = []

    # 1. HTML that needs htmlLabels.
    markup = _without_annotations(body)
    for tag in sorted(set(HTML_LABEL_TAGS.findall(markup))):
        found.append(
            f"{where}: {tag!r} only renders when htmlLabels is on, and GitHub "
            "renders with securityLevel 'strict', which turns it off. It will "
            "reach the reader as literal text. Use plain text, or <br/>, which "
            "mermaid handles itself."
        )
    for entity in sorted(set(HTML_ENTITY.findall(markup))):
        found.append(
            f"{where}: the entity {entity!r} is resolved by the HTML label "
            "path, which GitHub disables. Write the character directly."
        )

    # 2. A style value containing a space. Some builds split declarations on
    #    whitespace, so `stroke-dasharray:4 3` becomes two broken halves.
    for declaration in re.findall(r"classDef\s+\S+\s+(.*)", body):
        for pair in declaration.split(","):
            if ":" in pair and " " in pair.split(":", 1)[1].strip():
                found.append(
                    f"{where}: the style {pair.strip()!r} has a space in its "
                    "value. Use a single-value form so no parser has to guess "
                    "where the declaration ends."
                )

    # 3. Node ids that collide with the grammar.
    stripped = _label_free(body)
    for node_id in re.findall(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\[", stripped, re.M):
        if node_id in RESERVED_IDS:
            found.append(
                f"{where}: {node_id!r} is a mermaid keyword, so a node with "
                "that id makes the block unparseable. Rename it."
            )

    # 4. Unquoted labels. Everything this project draws carries punctuation, so
    #    the rule is simply that every label is quoted — a `(` or `,` in a bare
    #    label is a parse error rather than a rendering nuisance.
    for bare in re.findall(r"\[(?!\")[^\]\n]*[(),:;][^\]\n]*\]", body):
        found.append(
            f"{where}: the label {bare!r} is unquoted but contains punctuation "
            'mermaid parses as syntax. Wrap it in double quotes.'
        )

    return found


def check(paths: list[Path]) -> int:
    problems: list[str] = []
    checked = 0
    for path in paths:
        text = path.read_text(encoding="utf-8")

        # An odd number of fences means one block swallowed the rest of the
        # document, which renders as a wall of grey rather than an error.
        if text.count("```") % 2:
            problems.append(f"{path.name}: an unbalanced ``` fence")

        for line_no, _language, body in _blocks(text):
            kind = body.strip().split("\n")[0].strip()
            checked += 1
            problems.extend(
                problems_in(body, where=f"{path.name}:{line_no} ({kind})")
            )

    print(f"checked {checked} mermaid block(s) in {len(paths)} file(s)")
    for problem in problems:
        print(f"  {problem}")
    if problems:
        print(f"\n{len(problems)} problem(s)")
        return 1
    print("no GitHub-incompatible constructs found")
    print("(this does not prove they parse — see the module docstring)")
    return 0


def main() -> int:
    paths = [Path(a) for a in sys.argv[1:]] or sorted(ROOT.glob("*.md"))
    return check([p for p in paths if p.is_file()])


if __name__ == "__main__":
    raise SystemExit(main())
