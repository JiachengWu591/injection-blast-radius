"""Property-based tests for the security-critical code.

`ibr/schemas.py`, `ibr/executor.py` and `ibr/sandbox_fs.py` are at 100% line
coverage, which says every line ran — not that every line ran on the input that
would break it. The adversarial path sweep in tests/test_phase0.py is a list of
vectors I thought of; this file is the part that explores inputs I did not.

The properties asserted here are the ones the whole project rests on, stated so
they hold for *all* inputs rather than for a chosen list:

  * The path guard never returns a path outside the sandbox, for any string.
  * The parsers either return a fully valid object or raise — never a partial
    one, and never a value outside the declared enum.
  * The executor's published bytes are always one of four fixed templates,
    whatever the free-text fields contain.
  * The output audit never crashes, on any input.

Failures are reported with the minimal input Hypothesis could shrink to, which
is the point: a hand-written vector tells you one thing is handled, a shrunk
counterexample tells you the smallest thing that is not.

Run standalone:
    python tests/test_properties.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from ibr import sandbox_fs  # noqa: E402
from ibr.bootstrap import ensure_sandbox, reset_labels, reset_public_comments  # noqa: E402
from ibr.config import PUBLIC_COMMENTS_PATH, SANDBOX_ROOT  # noqa: E402
from ibr.executor import COMMENT_TEMPLATES, execute  # noqa: E402
from ibr.output_audit import audit_output, shannon_entropy  # noqa: E402
from ibr.sandbox_fs import SandboxViolation  # noqa: E402
from ibr.schemas import (  # noqa: E402
    ISSUE_TYPES,
    RISK_LEVELS,
    SUGGESTED_ACTIONS,
    ReaderOutput,
    SchemaViolation,
    parse_audit_verdict,
    parse_reader_output,
)

ensure_sandbox()

# Deterministic and quiet: this runs in CI next to fast unit tests, and a
# flaky-by-design suite there would train people to ignore it.
PROFILE = settings(
    max_examples=300,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    derandomize=True,
)

# Characters that make path handling interesting: separators, traversal, drive
# letters, the device namespace, NT prefixes, and non-ASCII.
_PATH_PIECES = st.sampled_from(
    [
        "..",
        ".",
        "/",
        "\\",
        "a",
        " ",
        "sandbox",
        "issues",
        ".env",
        "C:",
        "~",
        "NUL",
        "CON",
        "COM1",
        "$",
        ":",
        "*",
        "?",
        "\\\\?\\",
        "\\\\.\\",
        "%2e",
        "é",
        "́",
        "﻿",
        "%00",
    ]
)

paths = st.lists(_PATH_PIECES, min_size=1, max_size=8).map("".join)


# =========================================================================
# The sandbox guard, for any string at all.
# =========================================================================


@PROFILE
@given(paths)
def test_guard_returns_an_inside_path_or_raises_sandbox_violation(
    candidate: str,
) -> None:
    """The whole contract, in one property: two outcomes, never a third.

    Written loosely at first — it also accepted OSError and ValueError as
    "refusals" — and that made it useless. Deleting the containment check
    entirely left this test passing, because the device-name loop then raised
    ValueError from `relative_to` and the test counted that as acceptable. A
    guard with two exception types cannot be checked by a test that accepts
    both, which is why the guard now has one.
    """
    root = SANDBOX_ROOT.resolve()
    try:
        resolved = sandbox_fs.resolve_in_sandbox(candidate)
    except SandboxViolation:
        return
    assert resolved == root or root in resolved.parents, (
        f"{candidate!r} resolved to {resolved}, outside {root}"
    )


@PROFILE
@given(st.text(max_size=60))
def test_guard_refuses_arbitrary_text_with_one_exception_type(
    candidate: str,
) -> None:
    """Callers catch SandboxViolation; anything else escapes their handler.

    Reachable, not theoretical: a path with an embedded null byte made
    `Path.resolve()` raise ValueError, which ibr/baseline_agent.py's read_file
    backend does not catch — so a model putting a null byte in a tool argument
    aborted the whole run instead of getting an error message back.
    """
    try:
        sandbox_fs.resolve_in_sandbox(candidate)
    except SandboxViolation:
        return
    except Exception as exc:  # noqa: BLE001 - identifying the type is the point
        raise AssertionError(
            f"{candidate!r} raised {type(exc).__name__}, which callers do not "
            f"catch: {exc}"
        ) from exc


@PROFILE
@given(
    prefix=st.text(alphabet="ab/", max_size=10),
    suffix=st.text(alphabet="ab.", max_size=10),
)
def test_a_null_byte_anywhere_is_refused_as_a_violation(
    prefix: str, suffix: str
) -> None:
    """The specific reachable case, pinned so it cannot regress quietly."""
    try:
        sandbox_fs.resolve_in_sandbox(f"{prefix}\x00{suffix}")
    except SandboxViolation as exc:
        assert "cannot be resolved" in str(exc) or "outside" in str(exc)
    else:
        raise AssertionError("a path with an embedded null byte was accepted")


# =========================================================================
# The parsers: valid object or exception, never anything between.
# =========================================================================

json_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(max_size=20),
)

arbitrary_payloads = st.one_of(
    json_scalars,
    st.lists(json_scalars, max_size=4),
    st.dictionaries(st.text(max_size=12), json_scalars, max_size=6),
)


@PROFILE
@given(arbitrary_payloads)
def test_audit_parser_returns_a_valid_verdict_or_raises(payload: object) -> None:
    try:
        verdict = parse_audit_verdict(payload)
    except SchemaViolation:
        return
    assert verdict.risk_level in RISK_LEVELS
    assert isinstance(verdict.reasoning, str)
    assert isinstance(verdict.matched_patterns, tuple)
    assert all(isinstance(p, str) for p in verdict.matched_patterns)
    assert verdict.completed is True, "a parsed verdict must not look like a failure"


@PROFILE
@given(arbitrary_payloads)
def test_reader_parser_returns_a_valid_output_or_raises(payload: object) -> None:
    try:
        output = parse_reader_output(payload)
    except SchemaViolation:
        return
    assert output.issue_type in ISSUE_TYPES
    assert output.suggested_action in SUGGESTED_ACTIONS
    assert isinstance(output.reasoning, str)
    assert isinstance(output.summary, str)


@PROFILE
@given(
    reasoning=st.text(max_size=40),
    risk=st.text(max_size=20),
    patterns=st.lists(st.text(max_size=10), max_size=3),
)
def test_audit_parser_accepts_only_declared_risk_levels(
    reasoning: str, risk: str, patterns: list[str]
) -> None:
    """Near-miss enum values are the interesting case, not random junk."""
    payload = {
        "reasoning": reasoning,
        "risk_level": risk,
        "matched_patterns": patterns,
    }
    try:
        verdict = parse_audit_verdict(payload)
    except SchemaViolation:
        assert risk not in RISK_LEVELS, f"rejected a declared level {risk!r}"
        return
    assert risk in RISK_LEVELS, f"accepted an undeclared level {risk!r}"
    assert verdict.risk_level == risk


# =========================================================================
# The executor: four templates, whatever the free text says.
# =========================================================================


@PROFILE
@given(
    reasoning=st.text(max_size=200),
    summary=st.text(max_size=200),
    issue_type=st.one_of(st.sampled_from(ISSUE_TYPES), st.text(max_size=15)),
    action=st.one_of(st.sampled_from(SUGGESTED_ACTIONS), st.text(max_size=15)),
)
def test_executor_publishes_only_templates_for_any_reader_output(
    reasoning: str, summary: str, issue_type: str, action: str
) -> None:
    """The structural claim, quantified over every possible Reader output.

    tests/test_phase2.py checks this for one deliberately poisoned value. The
    claim is stronger than that: *no* combination of free text and enum values
    produces published bytes outside the four templates.
    """
    reset_public_comments()
    reset_labels()
    decision = execute(
        "property",
        ReaderOutput(
            reasoning=reasoning,
            issue_type=issue_type,
            summary=summary,
            suggested_action=action,
        ),
    )

    if decision.published_comment is not None:
        assert decision.published_comment in COMMENT_TEMPLATES.values(), (
            "the executor published bytes that are not one of the templates"
        )

    published = sandbox_fs.read_text(PUBLIC_COMMENTS_PATH)
    for fragment in (reasoning, summary):
        stripped = fragment.strip()
        # Short fragments can appear inside the templates by coincidence; only
        # a substantial one appearing is evidence of leakage.
        if len(stripped) >= 12:
            assert stripped not in published, (
                f"free text reached the public surface: {stripped[:40]!r}"
            )

    assert decision.action_taken in (*SUGGESTED_ACTIONS, "blocked_by_output_audit")


@PROFILE
@given(action=st.text(max_size=20))
def test_executor_treats_every_undeclared_action_as_no_action(action: str) -> None:
    reset_public_comments()
    reset_labels()
    decision = execute(
        "property",
        ReaderOutput(
            reasoning="r", issue_type="bug", summary="s", suggested_action=action
        ),
    )
    if action not in SUGGESTED_ACTIONS:
        assert decision.action_taken == "no_action", (
            f"undeclared action {action!r} produced {decision.action_taken}"
        )
        assert decision.published_comment is None
        assert decision.labels_added == ()


# =========================================================================
# The output audit must never be the thing that crashes.
# =========================================================================


@PROFILE
@given(st.text(max_size=400))
def test_output_audit_never_raises(text: str) -> None:
    """It sits between the executor and the file; an exception here fails open.

    Not literally — the exception would propagate and nothing would be
    published — but it would turn a clean run into a crash, and a scanner that
    can be crashed by its input is a scanner an attacker controls.
    """
    result = audit_output(text)
    assert isinstance(result.blocked, bool)
    assert isinstance(result.findings, tuple)
    assert result.blocked == bool(result.findings)


@PROFILE
@given(st.text(max_size=200))
def test_entropy_is_always_a_sane_number(text: str) -> None:
    value = shannon_entropy(text)
    assert value >= 0.0
    # Entropy of a string over an alphabet of n distinct symbols is at most
    # log2(n), and cannot exceed log2(len) for a string of that length.
    assert value <= 8.0 + 1e-9, f"implausible entropy {value} for {text[:30]!r}"


@PROFILE
@given(st.text(alphabet="ab", min_size=1, max_size=50))
def test_entropy_of_a_two_symbol_string_never_exceeds_one_bit(text: str) -> None:
    assert shannon_entropy(text) <= 1.0 + 1e-9


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
