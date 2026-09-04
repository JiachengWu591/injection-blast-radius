"""The fetcher's own logic, offline.

Everything here is a decision the fetcher makes before any network or model
call, so it can be checked without either. Three things are worth pinning.

**The retry category.** Three runs died to three different transient network
failures, each escaping an `except` clause that listed the ones I had thought
of rather than the category they belong to. This asserts the category, and
asserts that a programming error still escapes it — retrying a typo three
times and then reporting a short corpus would turn a bug into a quiet
data-quality problem.

**The id namespace.** Issue numbers are unique within a repository, not across
them.

**The drop policy.** The point of splitting one review question into four was
that naming a third party is not disqualifying. If that ever becomes
disqualifying again, the corpus silently loses whatever made each repository
different, and only this assertion would say so.

Run standalone:
    python tests/test_fetch_real.py
"""

from __future__ import annotations

import http.client
import json
import sys
import urllib.error
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.fetch_real_corpus import (  # noqa: E402
    DEFAULT_REPOS,
    DROP_ON,
    REVIEW_SCHEMA,
    TRANSIENT,
    Candidate,
    Drop,
    count_causes,
    render_causes,
)


def _candidate(repo: str = "pandas-dev/pandas", number: int = 68009) -> Candidate:
    return Candidate(
        number=number, title="t", author="someone", body="b", repo=repo
    )


# --- the retry category ----------------------------------------------------


def test_every_transient_failure_seen_so_far_is_covered() -> None:
    """Each of these killed a run before it was in the tuple."""
    seen = [
        TimeoutError("read timed out"),          # 30s timeout on a large page
        http.client.RemoteDisconnected("bye"),   # mid-run, page 16
        http.client.IncompleteRead(b""),         # after 753 kB, escaped the clause
        ConnectionResetError("reset"),
        urllib.error.URLError("dns"),
        json.JSONDecodeError("truncated", "", 0),  # a half-delivered page
    ]
    for exc in seen:
        assert isinstance(exc, TRANSIENT), (
            f"{type(exc).__name__} is not in the retry category, so one of "
            "these would end a long fetch instead of being retried"
        )


def test_a_programming_error_is_not_treated_as_transient() -> None:
    """The reason this is a tuple and not `except Exception`.

    A typo in the URL builder would otherwise be retried three times and then
    reported as "a short corpus is reported as short" — a bug laundered into a
    data-quality note.
    """
    for exc in (AttributeError("typo"), TypeError("bad arg"), KeyError("k")):
        assert not isinstance(exc, TRANSIENT), (
            f"{type(exc).__name__} would be retried and then silently swallowed"
        )


# --- the id namespace ------------------------------------------------------


def test_corpus_ids_are_namespaced_by_repository() -> None:
    pandas = _candidate("pandas-dev/pandas", 68009)
    vscode = _candidate("microsoft/vscode", 68009)

    assert pandas.slug == "pandas"
    assert pandas.corpus_id == "real-pandas-68009"
    assert pandas.corpus_id != vscode.corpus_id, (
        "the same issue number in two repositories produced the same id, which "
        "would merge them into one subject in the sample store"
    )


# --- the drop policy -------------------------------------------------------


def test_naming_a_third_party_is_not_a_reason_to_drop() -> None:
    """What the four-way split was for.

    A single `identifies_someone` boolean dropped genuine bug reports for
    naming a vendor, which is how one repository reached a 25.6% drop rate
    against another's 6.2%. Naming an API you call identifies nobody; naming
    your own employer does.
    """
    dropping = {flag for flag, _ in DROP_ON}
    assert "identifies_person" in dropping
    assert "promotional" in dropping
    assert "ties_reporter_to_organisation" in dropping
    assert "names_third_party" not in dropping, (
        "merely naming a third party is disqualifying again, which removes "
        "exactly what makes each repository different"
    )


def test_the_review_asks_the_four_questions_separately() -> None:
    """One boolean carrying three jobs is how the bias got in."""
    required = set(REVIEW_SCHEMA["required"])
    assert {
        "identifies_person",
        "ties_reporter_to_organisation",
        "promotional",
        "ordinary_issue",
    } <= required
    assert "identifies_someone" not in required, (
        "the merged question is back; it conflated spam, real handles and "
        "vendor names under one flag"
    )
    # And reasoning before the verdicts, as everywhere else in this project.
    assert REVIEW_SCHEMA["required"][0] == "reasoning"


def test_the_default_spread_covers_more_than_one_kind_of_repository() -> None:
    """Four samples of "an ordinary issue", not four times as much of one.

    Raising n narrows an interval. Spread is what says the interval was
    measured on a population worth generalising from, and PROJECT_SPEC.md §8
    recorded "real means real pandas" as the limitation this answers.
    """
    assert len(DEFAULT_REPOS) >= 4
    assert len({r.split("/")[0] for r in DEFAULT_REPOS}) >= 4, (
        "the default repositories share owners, so they are unlikely to be "
        "four different kinds of issue tracker"
    )
    for repo, why in DEFAULT_REPOS.items():
        assert len(why) > 20, f"{repo}: no stated reason for being in the spread"


# --- the drop report ------------------------------------------------------


def _drops() -> list[Drop]:
    """The shape the real run actually produced: mostly multi-cause drops."""
    return [
        Drop("real-x-1", ("promotional, not an issue", "not an ordinary issue"), ""),
        Drop("real-x-2", ("identifies a person", "promotional, not an issue"), ""),
        Drop("real-x-3", ("identifies a person",), ""),
    ]


def test_causes_are_counted_per_cause_not_per_combination() -> None:
    """The breakdown has to add up to something a reader can act on.

    Counting the joined string gave one row per *combination*: on the real run
    "identifies a person" was spread across four rows summing to 8, the biggest
    of which read 4. The total was right and every cause in it understated.
    """
    counts = count_causes(_drops())

    assert counts["identifies a person"] == 2
    assert counts["promotional, not an issue"] == 2
    assert counts["not an ordinary issue"] == 1
    assert "identifies a person; promotional, not an issue" not in counts, (
        "a combination is being counted as if it were a cause, so each real "
        "cause is split across rows and every one of them reads low"
    )


def test_the_report_prints_the_per_issue_count_it_can_be_confused_with() -> None:
    """Columns sum past the drop count, so the drop count must be on screen.

    3 issues, 5 causes. Without the `issues dropped` row a reader adds the
    column and concludes 5 issues were dropped out of 90.
    """
    table = render_causes({"a/b": count_causes(_drops())}, {"a/b": 3})

    assert "issues dropped" in table
    assert table.rstrip().endswith("3"), (
        "the per-issue drop count is missing from the table, leaving the "
        "column sum (5) as the only number a reader can add up"
    )
    assert "overlap" in table.splitlines()[0], (
        "nothing on screen warns that one issue can appear under several causes"
    )


def test_a_cause_absent_from_one_repository_is_still_a_row_there() -> None:
    """Ragged rows are how a difference between repositories hides.

    The finding this whole report exists for is "one repository drops issues
    for reasons the others do not". That is only visible if every cause is a
    row in every column, blank where it did not happen.
    """
    table = render_causes(
        {
            "spam/heavy": count_causes(_drops()),
            "quiet/repo": count_causes([Drop("real-y-1", ("identifies a person",), "")]),
        },
        {"spam/heavy": 3, "quiet/repo": 1},
    )
    promotional = [
        line for line in table.splitlines() if line.startswith("promotional")
    ]
    assert len(promotional) == 1
    assert "·" in promotional[0], (
        "the repository with no promotional drops has no cell in that row, so "
        "the reader cannot see that the difference is a zero and not a gap"
    )


def test_an_empty_breakdown_says_so_instead_of_heading_an_empty_table() -> None:
    """A clean run has to be distinguishable from a report that didn't render.

    Without this, zero drops print the heading "Why issues were dropped" over
    a table with no rows — which looks like a bug in the report rather than a
    repository that dropped nothing.
    """
    assert render_causes({"a/b": count_causes([])}, {"a/b": 0}) == (
        "No issues were dropped."
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
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
