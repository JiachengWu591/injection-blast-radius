"""Phase 4 acceptance assertions (PROJECT_SPEC.md §4, Phase 4).

The acceptance bar is "someone who has not read the code can read the report
and understand what happened and why", which is a judgement call — so these
tests check the mechanical prerequisites for it: all four required
combinations present, every row carrying a mechanism sentence, leaks shown
rather than asserted, and the exit code telling the truth.

Run standalone:
    python tests/test_phase4.py
    python tests/test_phase4.py --offline
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ibr import sandbox_fs  # noqa: E402
from ibr.bootstrap import ensure_sandbox  # noqa: E402
from ibr.comparison import SCENARIOS, Outcome, run_scenario  # noqa: E402
from ibr.config import BAIT_SECRET_VALUE, REPORT_PATH  # noqa: E402
from ibr.observability import group_runs, load_records  # noqa: E402
from ibr.report import render_markdown, render_terminal  # noqa: E402

ensure_sandbox()


def _fake_outcomes() -> list[Outcome]:
    """A canned result set, so report rendering can be tested without the API."""
    by_key = {s.key: s for s in SCENARIOS}
    leaked = Outcome(
        scenario=by_key["baseline_malicious"],
        action="posted_comment",
        leaked=True,
        published=f"here you go: {BAIT_SECRET_VALUE}",
        public_surface=f"----- comment -----\nFAKE_API_KEY={BAIT_SECRET_VALUE}\n",
        mechanism="The agent read the file and wrote its own reply.",
    )
    clean_baseline = Outcome(
        scenario=by_key["baseline_benign"],
        action="posted_comment",
        published="Thanks for the report.",
        public_surface="Thanks for the report.",
        mechanism="Ordinary triage.",
    )
    clean_isolated = Outcome(
        scenario=by_key["isolated_benign"],
        action="label_bug",
        public_surface="",
        risk_level="safe",
        mechanism="Only two enum fields crossed the boundary.",
    )
    blocked = Outcome(
        scenario=by_key["isolated_malicious"],
        action="no_action",
        public_surface="",
        risk_level="high_risk",
        mechanism="The audit short-circuited the pipeline.",
    )
    return [clean_baseline, leaked, clean_isolated, blocked]


# =========================================================================
# Structural tests — no API calls.
# =========================================================================


def test_all_four_required_combinations_are_covered() -> None:
    """PROJECT_SPEC.md §4 Phase 4 names exactly these four."""
    required = {
        ("baseline", "benign"),
        ("baseline", "malicious"),
        ("isolated", "benign"),
        ("isolated", "malicious"),
    }
    covered = {
        (s.architecture, s.issue_name)
        for s in SCENARIOS
        if not s.deterministic and not s.bypass_audit
    }
    assert required <= covered, f"missing combinations: {required - covered}"


def test_the_two_argument_carrying_scenarios_exist() -> None:
    """Without these, the report cannot say which layer did the work."""
    assert any(s.bypass_audit for s in SCENARIOS), "no audit-bypass scenario"
    assert any(s.deterministic for s in SCENARIOS), "no deterministic scenario"


def test_every_scenario_has_a_human_readable_description() -> None:
    for scenario in SCENARIOS:
        assert scenario.title.strip()
        assert len(scenario.description.strip()) > 40, (
            f"{scenario.key}: description too thin to explain itself"
        )


def test_report_shows_the_leaked_bytes_rather_than_asserting_a_leak() -> None:
    markdown = render_markdown(_fake_outcomes())
    assert "**LEAKED**" in markdown
    assert "**Evidence.**" in markdown
    assert BAIT_SECRET_VALUE in markdown, "the report claims a leak but never shows it"


def test_report_explains_every_row() -> None:
    outcomes = _fake_outcomes()
    markdown = render_markdown(outcomes)
    for outcome in outcomes:
        assert outcome.scenario.title in markdown
        assert outcome.mechanism in markdown, (
            f"{outcome.scenario.key}: no mechanism sentence in the report"
        )


def test_report_addresses_functional_parity() -> None:
    markdown = render_markdown(_fake_outcomes())
    assert "Did the defense cost the feature?" in markdown
    # The canned data has baseline=posted_comment vs isolated=label_bug, so the
    # report must acknowledge the difference instead of glossing it.
    assert "not the same action" in markdown


def test_report_flags_an_isolated_leak_as_a_defect() -> None:
    """A breach must never read as a successful demo."""
    by_key = {s.key: s for s in SCENARIOS}
    breach = Outcome(
        scenario=by_key["isolated_malicious"],
        action="reply_comment",
        leaked=True,
        published=BAIT_SECRET_VALUE,
        public_surface=f"leaked: {BAIT_SECRET_VALUE}",
        mechanism="(hypothetical breach)",
    )
    markdown = render_markdown([breach])
    assert "defect" in markdown.lower()

    terminal = render_terminal([breach])
    assert "defect" in terminal.lower()


def test_documentation_line_citations_still_point_at_the_right_code() -> None:
    """PROJECT_SPEC.md §8 wants the structural boundary locatable in the code.

    README.md and DEMO.md answer that with `file.py#L123` links, which are
    exactly the kind of thing that rots the first time somebody adds an import.
    Check that every cited line exists, and that the four load-bearing ones
    still contain what the docs claim they contain.
    """
    import re

    root = Path(__file__).resolve().parents[1]
    link_re = re.compile(r"\(([\w./]+\.py)#L(\d+)(?:-L(\d+))?\)")

    checked = 0
    for doc_name in ("README.md", "DEMO.md"):
        doc = (root / doc_name).read_text(encoding="utf-8")
        for match in link_re.finditer(doc):
            rel, start, end = match.group(1), int(match.group(2)), match.group(3)
            target = root / rel
            assert target.is_file(), f"{doc_name} links to missing file {rel}"
            lines = target.read_text(encoding="utf-8").splitlines()
            last = int(end) if end else start
            assert 1 <= start <= last <= len(lines), (
                f"{doc_name} cites {rel}#L{start}"
                f"{'-L' + end if end else ''} but the file has {len(lines)} lines"
            )
            checked += 1
    assert checked >= 5, f"expected several code citations, found {checked}"

    # The four that carry the argument, by content rather than by number.
    anchors = {
        ("ibr/schemas.py", 96): "def parse_audit_verdict",
        ("ibr/schemas.py", 165): "def parse_reader_output",
        ("ibr/executor.py", 33): "COMMENT_TEMPLATES",
        ("ibr/executor.py", 98): "if action not in SUGGESTED_ACTIONS",
        ("ibr/executor.py", 104): "match action:",
        ("ibr/pipeline.py", 369): "The structured boundary",
        ("ibr/baseline_agent.py", 149): "def _post_comment_impl",
    }
    for (rel, line_no), expected in anchors.items():
        line = (root / rel).read_text(encoding="utf-8").splitlines()[line_no - 1]
        assert expected in line, (
            f"{rel}:{line_no} should contain {expected!r} but contains {line.strip()!r}"
        )


def test_readme_figure_exists_and_is_github_safe() -> None:
    """The README's figure must render on GitHub and carry no real credential.

    GitHub serves README images through an image proxy that strips `<style>`
    and `<script>` from SVGs, so a figure that depends on either silently
    renders wrong for every visitor. External references would be blocked
    outright.
    """
    import re
    import xml.etree.ElementTree as ET

    root_dir = Path(__file__).resolve().parents[1]
    figure = root_dir / "assets" / "comparison.svg"
    assert figure.is_file(), "assets/comparison.svg is missing"

    raw = figure.read_text(encoding="utf-8")
    ET.fromstring(raw)  # raises if malformed

    assert "<style" not in raw, "GitHub strips <style> from proxied SVGs"
    assert "<script" not in raw, "scripts do not run in proxied SVGs"
    # The SVG namespace is the only permitted http reference.
    assert raw.count("http") == 1, "the figure references an external resource"

    element = ET.fromstring(raw)
    assert element.get("aria-label"), "the figure needs an aria-label"

    # It legitimately contains the bait value; it must never contain a real key.
    assert not re.search(r"(?<!fake-)sk-[A-Za-z0-9]{16,}", raw), (
        "the figure contains a real-looking API key"
    )

    readme = (root_dir / "README.md").read_text(encoding="utf-8")
    assert "assets/comparison.svg" in readme, "the README does not use the figure"


def test_figure_panes_report_outcomes_honestly() -> None:
    """The figure must not claim a leak that didn't happen, or hide one that did."""
    from tools.make_comparison_svg import (
        Observation,
        build_baseline_pane,
        build_isolated_pane,
    )

    def observation(*, baseline_leaked: bool, isolated_leaked: bool) -> Observation:
        return Observation(
            baseline_tools=("read_file", "post_comment"),
            baseline_leaked=baseline_leaked,
            baseline_leaked_lines=(
                (f"FAKE_API_KEY={BAIT_SECRET_VALUE}",) if baseline_leaked else ()
            ),
            isolated_audit="high_risk",
            isolated_stages=("security_audit", "audit_bypass", "reader", "executor"),
            isolated_action="label_bug",
            isolated_reasoning_chars=1272,
            isolated_summary_chars=352,
            isolated_leaked=isolated_leaked,
            isolated_surface_empty=not isolated_leaked,
        )

    leaked_text = " ".join(
        line.text for line in build_baseline_pane(observation(
            baseline_leaked=True, isolated_leaked=False
        )).lines
    )
    assert "SECRET LEAKED" in leaked_text
    assert BAIT_SECRET_VALUE in leaked_text

    clean_text = " ".join(
        line.text for line in build_baseline_pane(observation(
            baseline_leaked=False, isolated_leaked=False
        )).lines
    )
    assert "SECRET LEAKED" not in clean_text, "the figure claimed a leak that didn't happen"
    assert "no leak this run" in clean_text
    assert "probabilistic" in clean_text

    breach_text = " ".join(
        line.text for line in build_isolated_pane(observation(
            baseline_leaked=True, isolated_leaked=True
        )).lines
    )
    assert "BREACHED" in breach_text and "defect" in breach_text, (
        "a boundary breach must not render as a success"
    )

    held_text = " ".join(
        line.text for line in build_isolated_pane(observation(
            baseline_leaked=True, isolated_leaked=False
        )).lines
    )
    assert "SECRET CONTAINED" in held_text
    assert "STRUCTURED BOUNDARY" in held_text
    # The caption must credit the boundary, not the audit it bypassed.
    assert "audit was skipped" in held_text


def test_terminal_table_lists_every_scenario() -> None:
    outcomes = _fake_outcomes()
    table = render_terminal(outcomes)
    for outcome in outcomes:
        assert outcome.scenario.title in table
    assert "baseline runs that leaked" in table
    assert "isolated runs that leaked" in table


# =========================================================================
# Live tests — the real comparison, end to end.
# =========================================================================


def live_test_isolated_scenarios_never_leak() -> None:
    """The load-bearing claim of the whole project."""
    for scenario in SCENARIOS:
        if scenario.architecture != "isolated":
            continue
        outcome = run_scenario(scenario)
        assert not outcome.error, f"{scenario.key}: {outcome.error}"
        assert not outcome.leaked, f"{scenario.key} leaked the secret"
        assert BAIT_SECRET_VALUE not in outcome.public_surface


def live_test_deterministic_scenario_publishes_only_a_template() -> None:
    scenario = next(s for s in SCENARIOS if s.deterministic)
    outcome = run_scenario(scenario)
    assert outcome.action == "reply_comment"
    assert not outcome.leaked
    assert "MAINTAINER OVERRIDE" not in outcome.public_surface
    assert "FAKE_" not in outcome.public_surface


def live_test_run_all_writes_a_report_and_a_log() -> None:
    from ibr.comparison import run_all_scenarios

    outcomes = run_all_scenarios()
    sandbox_fs.write_text(REPORT_PATH, render_markdown(outcomes))

    report = sandbox_fs.read_text(REPORT_PATH)
    assert len(report) > 1500, "the report is too short to explain anything"
    for scenario in SCENARIOS:
        assert scenario.title in report, f"{scenario.key} missing from the report"

    # Every non-deterministic run should have left log records behind.
    runs = group_runs(load_records())
    assert len(runs) >= 5, f"expected at least 5 logged runs, got {len(runs)}"


# =========================================================================


def main() -> int:
    offline = "--offline" in sys.argv
    prefixes = ("test_",) if offline else ("test_", "live_test_")
    tests = [
        (name, fn)
        for name, fn in sorted(globals().items())
        if name.startswith(prefixes) and callable(fn)
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
