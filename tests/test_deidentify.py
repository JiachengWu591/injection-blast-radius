"""The de-identifier, tested in both directions.

It has to remove what it claims to remove, and it has to leave alone the things
that merely look like identifiers — a decorator, a version string, a traceback
path. Over-scrubbing is not the safe direction here: the whole reason to use
real issues is that their prose is real, and a de-identifier that mangles
tracebacks produces data no more real than the synthetic corpus it replaced.

The assertion that matters most is the last one. `residual_risks()` must stay
non-empty, because the moment this module reads as complete, PROJECT_SPEC.md
§6.1's authorisation is being relied on for more than it grants.

Run standalone:
    python tests/test_deidentify.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.deidentify import (  # noqa: E402
    deidentify,
    pseudonym,
    residual_risks,
    scrub,
)


def test_the_author_field_always_goes() -> None:
    result = deidentify(
        issue_id="1", title="Crash", author="sarah-chen-dev", body="boom"
    )
    assert result.author != "sarah-chen-dev"
    assert result.author.startswith("reporter-")
    assert "author" in result.removed


def test_the_same_handle_maps_to_the_same_pseudonym() -> None:
    """A real backlog has repeat reporters, and flattening them all to one
    name would change the shape of the data the measurement runs on."""
    assert pseudonym("octocat") == pseudonym("octocat")
    assert pseudonym("octocat") != pseudonym("hubot")


def test_emails_and_mentions_go() -> None:
    text = "Ping @mtorres or mail s.chen@acmecorp.io for the logs."
    clean, removed = scrub(text)
    assert "s.chen@acmecorp.io" not in clean
    assert "@mtorres" not in clean
    assert "[email]" in clean
    assert set(removed) >= {"email", "mention"}
    # The mention becomes a stable pseudonym rather than vanishing, so the
    # sentence still reads as addressing somebody.
    assert "@reporter-" in clean


def test_home_directories_lose_the_account_name() -> None:
    for raw, name in (
        ("/Users/sarahchen/work/config.yaml", "sarahchen"),
        ("/home/jbloggs/.config/app.toml", "jbloggs"),
        (r"C:\Users\Mira T\Reports\out.parquet", "Mira"),
    ):
        clean, removed = scrub(raw)
        assert name not in clean, f"{name!r} survived in {clean!r}"
        assert "[user]" in clean
        assert "home_path" in removed


def test_urls_keep_the_host_and_lose_the_path() -> None:
    """"There was a link here" is information a triage model reacts to; the
    path and query are where the identifying parts live."""
    clean, removed = scrub("See https://github.com/acme/private-repo/issues/12")
    assert "private-repo" not in clean
    assert "github.com" in clean
    assert "[path]" in clean
    assert "url" in removed


def test_a_bare_host_survives_without_a_path_stub() -> None:
    clean, _ = scrub("Docs at https://pandas.pydata.org")
    assert clean.endswith("pandas.pydata.org")
    assert "[path]" not in clean


def test_a_quoted_reply_header_goes() -> None:
    text = "On Tue, 3 Sep 2026 at 14:02, Sarah Chen wrote:\n> the old message"
    clean, removed = scrub(text)
    assert "Sarah Chen" not in clean
    assert "quote_header" in removed


# --- the other direction: things that must survive untouched ---------------


def test_a_python_decorator_is_not_a_mention() -> None:
    """Real issues are full of code. `@property` is not a person."""
    code = "@property\ndef frame(self):\n    @staticmethod\n    pass"
    clean, removed = scrub(code)
    assert clean == code, f"a decorator was scrubbed: {clean!r}"
    assert removed == []


def test_a_traceback_survives() -> None:
    """The most common content in a real bug report, and the easiest to ruin.

    Site-packages paths carry no account name, so nothing here should change —
    a de-identifier that rewrites tracebacks produces data no more real than
    the synthetic corpus it was brought in to replace.
    """
    trace = (
        'Traceback (most recent call last):\n'
        '  File "/opt/venv/lib/python3.12/site-packages/pandas/core/frame.py",'
        ' line 4102, in __getitem__\n'
        "    indexer = self.columns._get_indexer_strict(key, 'columns')[1]\n"
        "KeyError: 'total_amount'"
    )
    clean, removed = scrub(trace)
    assert clean == trace, f"the traceback changed: {clean!r}"
    assert removed == []


def test_version_strings_and_emails_are_told_apart() -> None:
    for benign in (
        "pandas 2.1.3 on python 3.12",
        "numpy>=1.26,<2",
        "installed via pip install 'pandas[all]'",
        "the a@b thing is not an email",
    ):
        clean, removed = scrub(benign)
        assert "email" not in removed, f"{benign!r} was read as an email"


def test_scrubbing_is_idempotent_in_text_and_in_audit_trail() -> None:
    """Re-scrubbing must change nothing and must claim nothing.

    The fetcher is resumable and may re-process a record, so the text has to be
    stable. The `removed` list has to be too: `/home/[user]/x` still *matches*
    the home-path rule, and a match-based audit trail reported a removal that
    never happened — a small lie in exactly the record that exists to be
    trusted.
    """
    once, first_pass = scrub("mail me at a.b@c.io about @octocat and /home/jo/x")
    assert set(first_pass) == {"email", "mention", "home_path"}

    twice, second_pass = scrub(once)
    assert once == twice, f"a second pass changed the text: {twice!r}"
    assert second_pass == [], (
        f"a second pass claims to have removed {second_pass}, but the text is "
        "unchanged. `removed` is the record of what was taken out of a real "
        "issue and it has to be true."
    )


def test_nothing_is_removed_from_text_that_carries_no_identifiers() -> None:
    plain = "Sorting is case-sensitive and the docs do not say so."
    clean, removed = scrub(plain)
    assert clean == plain
    assert removed == []


def test_the_residual_risks_are_named_and_not_empty() -> None:
    """The load-bearing assertion.

    PROJECT_SPEC.md §6.1 authorises this on the condition that its limits are
    stated. If this list ever empties, the module reads as complete and the
    authorisation is being relied on for more than it grants.
    """
    risks = residual_risks()
    assert len(risks) >= 4
    joined = " ".join(risks).lower()
    assert "prose" in joined, "the un-scrubbable case must be named explicitly"
    for risk in risks:
        assert len(risk) > 20, f"too vague to be a warning: {risk!r}"


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
