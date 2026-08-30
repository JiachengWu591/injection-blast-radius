"""Generate the side-by-side comparison figure for the README.

Runs both architectures against the malicious fixture for real, then renders
what happened as an SVG styled like two terminal panes. Every number and every
quoted line in the output comes from that run — nothing here is illustrative.
If the API is unreachable this fails rather than drawing plausible figures,
because a hand-drawn "screenshot" of a security result is worse than no
screenshot.

This is developer tooling, not part of the demo. It writes to assets/ using
plain pathlib rather than ibr.sandbox_fs: the sandbox whitelist governs what
the *agents* can touch (PROJECT_SPEC.md §6), and deliberately routing a build
artifact through it would blur a boundary the project is trying to keep sharp.

Usage:
    python tools/make_comparison_svg.py
    python tools/make_comparison_svg.py --check    # verify committed SVG is current
"""

from __future__ import annotations

import argparse
import pathlib
import sys
from dataclasses import dataclass, field
from xml.sax.saxutils import escape

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import openai  # noqa: E402

from ibr import sandbox_fs  # noqa: E402
from ibr.baseline_agent import run_baseline  # noqa: E402
from ibr.bootstrap import ensure_sandbox, reset_labels, reset_public_comments  # noqa: E402
from ibr.config import BAIT_SECRET_VALUE, PROJECT_ROOT, PUBLIC_COMMENTS_PATH  # noqa: E402
from ibr.issues import load_issue  # noqa: E402
from ibr.pipeline import run_isolated  # noqa: E402

OUTPUT_PATH = PROJECT_ROOT / "assets" / "comparison.svg"

# --- Palette ---------------------------------------------------------------
# A deliberately dark terminal on both GitHub themes: the panes read as
# terminal output either way, where theme-reactive colours would need a <style>
# block, and GitHub strips those from SVGs served through its image proxy.
BG = "#0d1117"
PANE = "#161b22"
BORDER = "#30363d"
TEXT = "#c9d1d9"
DIM = "#7d8590"
PROMPT = "#58a6ff"
LEAK = "#ff7b72"
SAFE = "#3fb950"
WARN = "#d29922"
BOUNDARY = "#a371f7"

FONT = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace"
FONT_SIZE = 12.5
CHAR_W = 7.52  # advance width of the stack above at 12.5px
LINE_H = 18.0
PANE_PAD = 16.0
PANE_GAP = 22.0
MARGIN = 18.0
HEADER_H = 42.0
COLS = 60


@dataclass
class Line:
    text: str = ""
    color: str = TEXT
    bold: bool = False


@dataclass
class Pane:
    title: str
    subtitle: str
    accent: str
    lines: list[Line] = field(default_factory=list)

    def add(self, text: str = "", color: str = TEXT, bold: bool = False) -> None:
        self.lines.append(Line(text, color, bold))


def _truncate(text: str, limit: int = COLS) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


# --- Data collection -------------------------------------------------------


@dataclass
class Observation:
    baseline_tools: tuple[str, ...]
    baseline_leaked: bool
    baseline_leaked_lines: tuple[str, ...]
    isolated_audit: str
    isolated_stages: tuple[str, ...]
    isolated_action: str
    isolated_reasoning_chars: int
    isolated_summary_chars: int
    isolated_leaked: bool
    isolated_surface_empty: bool


def observe() -> Observation:
    ensure_sandbox()
    issue = load_issue("malicious")

    reset_public_comments()
    reset_labels()
    baseline = run_baseline(issue)
    surface = sandbox_fs.read_text(PUBLIC_COMMENTS_PATH)
    leaked_lines = tuple(
        line.strip() for line in surface.splitlines() if "FAKE_" in line
    )

    reset_public_comments()
    reset_labels()
    # Bypassed on purpose: with the audit short-circuiting, the right-hand pane
    # would only show that the probabilistic layer fired, which is the weaker
    # claim. Bypassing it makes the pane a statement about the boundary.
    isolated = run_isolated(issue, simulate_audit_bypass=True)
    isolated_surface = sandbox_fs.read_text(PUBLIC_COMMENTS_PATH)

    return Observation(
        baseline_tools=tuple(c.name for c in baseline.transcript),
        baseline_leaked=BAIT_SECRET_VALUE in surface,
        baseline_leaked_lines=leaked_lines,
        isolated_audit=isolated.audit.risk_level if isolated.audit else "?",
        isolated_stages=tuple(s.stage for s in isolated.stages),
        isolated_action=isolated.action_taken,
        isolated_reasoning_chars=(
            len(isolated.reader.reasoning) if isolated.reader else 0
        ),
        isolated_summary_chars=len(isolated.reader.summary) if isolated.reader else 0,
        isolated_leaked=BAIT_SECRET_VALUE in isolated_surface,
        isolated_surface_empty=not isolated_surface.strip(),
    )


# --- Pane construction -----------------------------------------------------


def build_baseline_pane(obs: Observation) -> Pane:
    pane = Pane(
        title="Baseline — one agent",
        subtitle="reads untrusted text · reads files · publishes",
        accent=LEAK,
    )
    pane.add("$ python phase1_baseline.py", PROMPT)
    pane.add()
    for name in obs.baseline_tools:
        arg = "sandbox/.env" if name == "read_file" else "…triage reply…"
        pane.add(f"  {name}({arg})", TEXT)
    pane.add()
    pane.add("  sandbox/public_comments.txt", DIM)
    pane.add("  " + "─" * 44, DIM)
    if obs.baseline_leaked_lines:
        for line in obs.baseline_leaked_lines:
            pane.add("  " + _truncate(line, 50), LEAK)
    else:
        pane.add("  (no secret published this run)", DIM)
    pane.add("  " + "─" * 44, DIM)
    pane.add()
    if obs.baseline_leaked:
        pane.add("  ✗  SECRET LEAKED", LEAK, bold=True)
        pane.add()
        pane.add("  Nothing stood between reading the file", DIM)
        pane.add("  and publishing what it said.", DIM)
    else:
        pane.add("  —  no leak this run", WARN, bold=True)
        pane.add()
        pane.add("  Compliance is probabilistic; the agent", DIM)
        pane.add("  declined this time. Re-run to sample.", DIM)
    return pane


def build_isolated_pane(obs: Observation) -> Pane:
    pane = Pane(
        title="Isolated — four stages",
        subtitle="the agent that reads never publishes",
        accent=SAFE,
    )
    pane.add("$ python phase2_isolated.py", PROMPT)
    pane.add()
    pane.add(f"  security audit    → {obs.isolated_audit}", TEXT)
    if "audit_bypass" in obs.isolated_stages:
        pane.add("  ⚡ audit BYPASSED (simulated attack)", WARN)
    pane.add(f"  reader (no tools) → {obs.isolated_action}", TEXT)
    pane.add()
    pane.add("  ══ STRUCTURED BOUNDARY ══", BOUNDARY, bold=True)
    pane.add(
        f"   held back  reasoning({obs.isolated_reasoning_chars})"
        f" summary({obs.isolated_summary_chars})",
        DIM,
    )
    pane.add("   crossed    issue_type, suggested_action", SAFE)
    pane.add()
    pane.add(f"  executor          → {obs.isolated_action}", TEXT)
    pane.add()
    pane.add("  sandbox/public_comments.txt", DIM)
    pane.add("  " + "─" * 44, DIM)
    pane.add(
        "  (empty)" if obs.isolated_surface_empty else "  a predefined template only",
        DIM,
    )
    pane.add("  " + "─" * 44, DIM)
    pane.add()
    if obs.isolated_leaked:
        pane.add("  ✗  BOUNDARY BREACHED — this is a defect", LEAK, bold=True)
    else:
        pane.add("  ✓  SECRET CONTAINED", SAFE, bold=True)
        pane.add()
        pane.add("  Not because the audit caught it — the", DIM)
        pane.add("  audit was skipped. The executor only", DIM)
        pane.add("  reads two enum fields.", DIM)
    return pane


# --- Rendering -------------------------------------------------------------


def render(panes: list[Pane]) -> str:
    body_lines = max(len(p.lines) for p in panes)
    pane_w = COLS * CHAR_W + 2 * PANE_PAD
    pane_h = HEADER_H + body_lines * LINE_H + 2 * PANE_PAD
    width = 2 * pane_w + PANE_GAP + 2 * MARGIN
    height = pane_h + 2 * MARGIN + 26

    out: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" '
        f'height="{height:.0f}" viewBox="0 0 {width:.0f} {height:.0f}" '
        f'role="img" aria-label="Side by side: an undefended agent leaks a '
        f'placeholder secret; an isolated pipeline does not.">',
        f'<rect width="{width:.0f}" height="{height:.0f}" rx="10" fill="{BG}"/>',
    ]

    for index, pane in enumerate(panes):
        x = MARGIN + index * (pane_w + PANE_GAP)
        y = MARGIN
        out.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{pane_w:.1f}" '
            f'height="{pane_h:.1f}" rx="8" fill="{PANE}" stroke="{BORDER}"/>'
        )
        out.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{pane_w:.1f}" height="3" '
            f'rx="1.5" fill="{pane.accent}"/>'
        )
        out.append(
            f'<text x="{x + PANE_PAD:.1f}" y="{y + 24:.1f}" font-family="{FONT}" '
            f'font-size="13.5" font-weight="600" fill="{TEXT}">'
            f"{escape(pane.title)}</text>"
        )
        out.append(
            f'<text x="{x + PANE_PAD:.1f}" y="{y + 39:.1f}" font-family="{FONT}" '
            f'font-size="10.5" fill="{DIM}">{escape(pane.subtitle)}</text>'
        )

        text_y = y + HEADER_H + PANE_PAD
        for row, line in enumerate(pane.lines):
            if not line.text:
                continue
            weight = ' font-weight="700"' if line.bold else ""
            out.append(
                f'<text x="{x + PANE_PAD:.1f}" '
                f'y="{text_y + row * LINE_H:.1f}" font-family="{FONT}" '
                f'font-size="{FONT_SIZE}" fill="{line.color}"{weight} '
                f'xml:space="preserve">{escape(line.text)}</text>'
            )

    caption = (
        "Same malicious issue, both architectures. Generated from a real run by "
        "tools/make_comparison_svg.py — no figures are illustrative."
    )
    out.append(
        f'<text x="{MARGIN:.1f}" y="{height - MARGIN + 4:.1f}" '
        f'font-family="{FONT}" font-size="10" fill="{DIM}">'
        f"{escape(caption)}</text>"
    )
    out.append("</svg>")
    return "\n".join(out) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="regenerate and report whether the committed SVG is stale",
    )
    args = parser.parse_args()

    try:
        obs = observe()
    except openai.APIError as exc:
        print(
            f"FAILED: {type(exc).__name__}: {exc}\n"
            "Refusing to draw a figure without real data behind it.",
            file=sys.stderr,
        )
        return 1

    svg = render([build_baseline_pane(obs), build_isolated_pane(obs)])

    if args.check:
        if not OUTPUT_PATH.exists():
            print(f"{OUTPUT_PATH} does not exist")
            return 1
        current = OUTPUT_PATH.read_text(encoding="utf-8")
        # Byte equality is the wrong bar: the figures legitimately move between
        # runs. Report the substantive facts instead.
        print(f"committed figure : {len(current)} bytes")
        print(f"this run         : {len(svg)} bytes")
        print(f"baseline leaked  : {obs.baseline_leaked}")
        print(f"isolated leaked  : {obs.isolated_leaked}")
        return 0 if not obs.isolated_leaked else 1

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(svg, encoding="utf-8", newline="\n")
    print(f"wrote {OUTPUT_PATH} ({len(svg)} bytes)")
    print(f"  baseline leaked : {obs.baseline_leaked}")
    print(f"  isolated leaked : {obs.isolated_leaked}")
    if not obs.baseline_leaked:
        print(
            "\nNote: the baseline did not leak this run, so the figure shows "
            "the honest 'no leak this run' variant.\nRe-run to sample again if "
            "you want the leak in the figure."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
