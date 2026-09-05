"""The benign corpus is a control group, so its properties have to hold.

`sandbox/corpus/benign.jsonl` is the input to the false-positive measurement:
165 fictional issues a maintainer would triage without concern, stratified by
how much each one superficially resembles an attack.

Everything here guards one of two claims.

**It must be genuinely benign**, because the measurement counts every block as
a false positive. One real injection hiding in here would be counted as the
audit wrongly blocking a legitimate report, which is the opposite of the truth.

**It must be genuinely fictional** (PROJECT_SPEC.md §6): no real credentials,
no real people, no real products. The corpus was generated, then reviewed
stratum by stratum — and that review was inconsistent, because each stratum was
seen by a different reviewer with no view of the whole. It flagged `corvid-cli`
in one stratum and passed it in five others. These assertions are what replaces
that judgement with something that holds across the whole file.

Run standalone:
    python tests/test_corpus.py
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ibr.fixtures import BAIT_SECRET_VALUE  # noqa: E402
from ibr.issues import Issue, parse_issue  # noqa: E402
from ibr.output_audit import audit_output  # noqa: E402
from ibr.sources import JsonLinesIssueSource  # noqa: E402
from tools.deidentify import NOT_A_HANDLE, credential_shaped  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "sandbox" / "corpus" / "benign.jsonl"

# The strata, and why each exists. False positives do not happen on bland
# issues; they happen on ordinary issues that trip a screener's heuristics, so
# the corpus is deliberately weighted toward those.
STRATA = {
    "plain": "nothing that resembles an attack — the floor",
    "mentions_config": "legitimately discusses .env, environment variables, config precedence",
    "quotes_secret_shaped": "legitimately pastes a credential-shaped string",
    "discusses_injection": "prompt injection as subject matter, quoted not issued",
    "imperative_to_humans": "commands and urgency, aimed at maintainers",
    "non_english": "six languages, some mixed with English tracebacks",
    "edge_shape": "benign content in awkward shapes — empty, enormous, malformed",
}

# The one invented product family. Everything in the corpus is a blastdemo*
# thing, which turns "no real products are named" from a judgement repeated per
# stratum into one check over the whole file.
PRODUCT_ROOT = "blastdemo"

# Roots a reviewer identified as plausibly real. A regression guard for names
# that already got in once, not a general proof — whether an invented name
# collides with some real product is not mechanically decidable, and this
# cannot tell you about the next one.
KNOWN_REAL_ROOTS = ("corvid", "orchard", "sparrow", "yamlish", "quillmark")

# Credential-shaped: one definition, imported rather than restated.
# `tools/deidentify.py` owns it because that is the module which has to act on
# it, and two copies of "this looks like a key" would drift — the copy that
# drifted being the one deciding whether a real credential reached disk.
#
# Two policies over the one definition. The synthetic corpus may carry
# credential shapes when the line says `fake`, because the
# `quotes_secret_shaped` stratum exists to paste them on purpose. The real
# corpus is allowed none at all.
#
# Deliberately not a generic high-entropy sweep: the synthetic corpus contains
# a base64 cache-file header on purpose, and an entropy scanner would flag it
# where a maintainer would not.


def _credential_shaped(text: str) -> list[str]:
    return credential_shaped(text)


# An author is a handle, never a plausible full name.
HANDLE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}$")


def _records() -> list[dict]:
    assert CORPUS.is_file(), f"missing corpus: {CORPUS}"
    return [
        json.loads(line)
        for line in CORPUS.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_the_corpus_is_valid_pipeline_input() -> None:
    """Every record must survive the same validator the pipeline uses.

    Not a separate schema check: the corpus is read through
    `JsonLinesIssueSource`, so if `parse_issue` would reject a record then the
    measurement would die partway through a paid run.
    """
    records = _records()
    assert len(records) >= 150, f"corpus has shrunk to {len(records)}"

    for number, record in enumerate(records, 1):
        issue = parse_issue(json.dumps(record), origin=f"benign.jsonl:{number}")
        assert isinstance(issue, Issue)
        assert issue.body.strip(), f"{record['issue_id']}: empty body"

    source = JsonLinesIssueSource(Path("corpus/benign.jsonl"))
    loaded = source.available_issues()
    assert len(loaded) == len(records), (
        f"the source loads {len(loaded)} issues but the file has {len(records)}"
    )


def test_every_issue_id_is_unique() -> None:
    """The sample store keys on the issue id, so a collision would silently
    merge two issues' verdicts into one subject."""
    ids = [r["issue_id"] for r in _records()]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    assert not duplicates, f"duplicate issue_id(s): {duplicates}"


def test_every_stratum_is_declared_and_populated() -> None:
    """A stratum that quietly emptied would take its part of the answer with it."""
    records = _records()
    counts: dict[str, int] = {}
    for record in records:
        stratum = record.get("stratum", "")
        assert stratum in STRATA, (
            f"{record['issue_id']}: stratum {stratum!r} is not one of "
            f"{sorted(STRATA)}"
        )
        counts[stratum] = counts.get(stratum, 0) + 1

    missing = sorted(set(STRATA) - set(counts))
    assert not missing, f"stratum/strata with no issues: {missing}"
    thin = {k: n for k, n in counts.items() if n < 15}
    assert not thin, (
        f"stratum/strata too thin to say anything about: {thin}. Each one gets "
        "its own rate, and a rate over ten issues has an interval too wide to "
        "read."
    )


def test_every_issue_says_why_it_is_benign() -> None:
    """The label is a claim, and a claim needs to be reviewable.

    If the audit blocks one of these, the first question is whether the issue
    really was benign. Answering that requires the reason to be written down at
    the time, not reconstructed afterwards.
    """
    for record in _records():
        why = record.get("why_benign", "")
        assert len(why.strip()) > 20, (
            f"{record['issue_id']}: why_benign is too thin to review ({why!r})"
        )


def test_no_credential_shaped_string_lacks_a_fake_marker() -> None:
    """PROJECT_SPEC.md §6: every secret must be an obvious placeholder.

    The `quotes_secret_shaped` stratum exists to paste credential-shaped
    strings on purpose, so this is the assertion that keeps that stratum from
    becoming a place where something real could hide.
    """
    offenders: list[str] = []
    for record in _records():
        text = f"{record['title']}\n{record['body']}"
        for blob in _credential_shaped(text):
            line = next((ln for ln in text.splitlines() if blob in ln), blob)
            if "fake" in line.lower():
                continue
            offenders.append(
                f"{record['issue_id']}: {blob[:50]!r} in {line.strip()[:70]!r}"
            )

    assert not offenders, (
        "credential-shaped string(s) with no fake marker on the line:\n  "
        + "\n  ".join(offenders)
    )


def test_the_bait_secret_never_appears_in_the_corpus() -> None:
    """The single most damaging thing that could be in here.

    `BAIT_SECRET_VALUE` is how every leak check in the project decides that
    something leaked. A control-group issue containing it would make the
    baseline agent "leak" merely by quoting the issue back, and would break the
    isolated pipeline's clean record for a reason that has nothing to do with
    the boundary.
    """
    for record in _records():
        haystack = f"{record['title']}\n{record['body']}"
        assert BAIT_SECRET_VALUE not in haystack, (
            f"{record['issue_id']} contains BAIT_SECRET_VALUE"
        )


def test_no_author_looks_like_a_real_person() -> None:
    """§6 forbids real personal information, so authors are handles."""
    offenders = [
        f"{r['issue_id']}: {r['author']!r}"
        for r in _records()
        if not HANDLE.match(r["author"])
    ]
    assert not offenders, (
        "author(s) that are not handle-shaped:\n  " + "\n  ".join(offenders)
    )


def test_the_documented_rates_use_the_real_denominators() -> None:
    """Every `k/n` the docs quote for a stratum must use that stratum's size.

    The numerators are observations from live runs and no test can re-derive
    them — model behaviour is not reproducible offline, which is the whole
    reason those numbers are measured rather than asserted. The denominators
    are different: they are the corpus composition. Regenerate the corpus with
    24 issues in a stratum the docs say has 22, and every rate quoted for it
    becomes wrong while still reading as authoritative.

    So this pins the half that can be checked, and says plainly that it is the
    half — a passing run here does not mean the rates are current.
    """
    counts: dict[str, int] = {}
    for record in _records():
        counts[record["stratum"]] = counts.get(record["stratum"], 0) + 1
    total = sum(counts.values())

    fraction = re.compile(r"\b(\d+)/(\d+)\b")
    problems: list[str] = []

    for doc_name in ("README.md", "README.zh-CN.md"):
        text = (ROOT / doc_name).read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), 1):
            named = [s for s in counts if s in line]
            if len(named) != 1:
                # A line naming several strata (or none) has no single
                # denominator to check against.
                continue
            stratum = named[0]
            for numerator, denominator in fraction.findall(line):
                if int(denominator) in (int(numerator), total):
                    continue  # k/k or k/165 — not a per-stratum rate
                if int(denominator) != counts[stratum]:
                    problems.append(
                        f"{doc_name}:{number} quotes {numerator}/{denominator} "
                        f"for `{stratum}`, which holds {counts[stratum]} issues"
                    )

    assert not problems, "stale denominator(s):\n  " + "\n  ".join(problems)

    # And the corpus-wide denominator, checked by presence rather than by
    # sweeping every large number in the file. The first version of this did
    # sweep, and flagged 200, 2395 and 2400 — the attack experiment's
    # denominators, which have nothing to do with this corpus. Grow the corpus
    # and `/165` stops being the right denominator; requiring the current one
    # to appear catches that without an opinion about unrelated measurements.
    for doc_name in ("README.md", "README.zh-CN.md"):
        text = (ROOT / doc_name).read_text(encoding="utf-8")
        assert f"/{total}" in text, (
            f"{doc_name} never quotes a rate out of {total}, the corpus size. "
            "Either the corpus changed and the documented rates are stale, or "
            "the measurement is no longer reported."
        )


def test_only_the_invented_product_family_is_named() -> None:
    """One product family, so the property is checkable over the whole file.

    The generated corpus named three plausibly-real packages, and the review
    caught them in one stratum while missing the same name in five others —
    each stratum had its own reviewer and none of them saw the whole. This is
    what a per-stratum judgement gets replaced with.
    """
    text = CORPUS.read_text(encoding="utf-8").lower()
    found = {root: text.count(root) for root in KNOWN_REAL_ROOTS if root in text}
    assert not found, (
        f"plausibly-real product root(s) back in the corpus: {found}. "
        f"Every invented product is a {PRODUCT_ROOT}* name."
    )
    assert PRODUCT_ROOT in text, "the corpus names no product at all"


# --- the real corpus -------------------------------------------------------
#
# `sandbox/corpus/real.jsonl` holds de-identified text from real issues across
# four repositories, authorised by PROJECT_SPEC.md §6.1. It is gitignored, so it
# is absent on a fresh clone and in CI — these assertions skip when it is
# missing and are strict when it is present.
#
# They check the *output*, not the de-identifier. tests/test_deidentify.py
# tests the function; this catches the record that never went through it.

REAL_CORPUS = ROOT / "sandbox" / "corpus" / "real.jsonl"

REAL_AUTHOR = re.compile(r"^reporter-[0-9a-f]{6}$")
ANY_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
NAMED_HOME = re.compile(r"(?i)(?:/home/|/Users/|\\Users\\)(?!\[user\])[^/\\\s]+")


def _real_records() -> list[dict] | None:
    if not REAL_CORPUS.is_file():
        return None
    return [
        json.loads(line)
        for line in REAL_CORPUS.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_the_real_corpus_is_gitignored() -> None:
    """The copyright and privacy decision, made checkable.

    §6.1 turns on the real text never entering git: issue prose is copyright
    its author and the repository's licence does not cover it, and git history
    is permanent while de-identification is not complete. Delete the ignore
    rule and both of those reverse silently on the next `git add -A`.
    """
    inside_repo = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        cwd=ROOT,
        capture_output=True,
    )
    if inside_repo.returncode != 0:
        print("      (skipped: not a git repository)")
        return

    result = subprocess.run(
        ["git", "check-ignore", "-q", "sandbox/corpus/real.jsonl"],
        cwd=ROOT,
        capture_output=True,
    )
    assert result.returncode == 0, (
        "sandbox/corpus/real.jsonl is NOT gitignored. Real issue prose is "
        "copyright its authors and de-identification is incomplete; the "
        "repository publishes tools/fetch_real_corpus.py, never its output. "
        "See PROJECT_SPEC.md §6.1."
    )


def test_no_mechanical_identifier_survived_in_the_real_corpus() -> None:
    """The post-hoc check, independent of the de-identifier's own logic.

    A bug in `scrub` is one failure mode and `test_deidentify.py` covers it. A
    record that never reached `scrub` at all is a different one, and only
    reading the finished file catches that.
    """
    records = _real_records()
    if records is None:
        print("      (skipped: no real corpus — run tools/fetch_real_corpus.py)")
        return
    assert records, "the real corpus file exists but is empty"

    offenders: list[str] = []
    for record in records:
        text = f"{record['title']}\n{record['body']}"
        if ANY_EMAIL.search(text):
            offenders.append(f"{record['issue_id']}: an email address survived")
        if NAMED_HOME.search(text):
            found = NAMED_HOME.search(text)
            offenders.append(
                f"{record['issue_id']}: a named home directory survived "
                f"({found.group(0) if found else '?'})"
            )
        if not REAL_AUTHOR.match(record["author"]):
            offenders.append(
                f"{record['issue_id']}: author {record['author']!r} is not a "
                "pseudonym"
            )
        if BAIT_SECRET_VALUE in text:
            offenders.append(f"{record['issue_id']}: contains BAIT_SECRET_VALUE")

    assert not offenders, (
        f"{len(offenders)} identifier(s) survived de-identification:\n  "
        + "\n  ".join(offenders[:20])
    )


def test_no_unscrubbed_handle_survived_into_the_real_corpus() -> None:
    """The gate that was missing when the handle bug was live.

    `test_no_mechanical_identifier_survived_in_the_real_corpus` checks emails,
    home directories, authors and the bait secret — not mentions. So when the
    MENTION pattern silently failed on `@dongxi_nlp` (underscores are word
    characters, `\\b` cannot match beside one, the whole match failed), nothing
    here would have noticed. Only the review pass stood between that and the
    corpus, and it is a model judgement.

    Deliberately checked with a *wider* pattern than the scrubber uses. A gate
    that shares its predecessor's blind spot is not a gate, so this one accepts
    any handle-shaped token and exempts only the pseudonyms the scrubber
    writes.
    """
    records = _real_records()
    if records is None:
        print("      (skipped: no real corpus)")
        return

    handle_shaped = re.compile(r"(?<![\w.])@([A-Za-z0-9][A-Za-z0-9_-]{2,38})")

    offenders: list[str] = []
    for record in records:
        # Code spans are NOT exempt. They were, in both this gate and the
        # scrubber, on the reasoning that decorators live there — and a
        # langchain issue template put a real social handle inside a fence, so
        # the handle survived and this gate looked straight past it. The
        # denylist is the only exemption now, in both places.
        text = f"{record['title']}\n{record['body']}"
        for match in handle_shaped.finditer(text):
            handle = match.group(1)
            if handle.startswith("reporter-") or handle in NOT_A_HANDLE:
                continue
            offenders.append(f"{record['issue_id']}: {match.group(0)}")

    assert not offenders, (
        f"{len(offenders)} unscrubbed @handle(s) in real issue text:\n  "
        + "\n  ".join(offenders[:20])
    )


def test_no_credential_survived_into_the_real_corpus() -> None:
    """The strictest of the corpus gates, and the one with no allowance.

    The synthetic corpus may carry credential shapes when the line says `fake`
    — a whole stratum exists to paste them on purpose. Real text gets no such
    allowance: PROJECT_SPEC.md §6 rule 3 forbids real credentials absolutely
    and §6.1 relaxes none of it, so any match here is either a real leaked key
    or a de-identifier that stopped working, and both mean stop.

    This gap was live. The de-identifier had no credential rule at all, and a
    fetch from a repository whose issues are about calling paid APIs was about
    to run. People paste keys into issues often enough that GitHub scans for
    it; the corpus that happened to be clean was six records long.
    """
    records = _real_records()
    if records is None:
        print("      (skipped: no real corpus)")
        return

    offenders: list[str] = []
    for record in records:
        for found in credential_shaped(f"{record['title']}\n{record['body']}"):
            offenders.append(f"{record['issue_id']}: {found[:60]!r}")

    assert not offenders, (
        f"{len(offenders)} credential-shaped string(s) in real issue text:\n  "
        + "\n  ".join(offenders[:20])
        + "\n\nEither a real key leaked into the corpus or the redaction "
        "regressed. Do not relax this check to get past it."
    )


def test_real_corpus_ids_are_namespaced_by_repository() -> None:
    """Issue numbers are unique within a repository, not across them.

    pandas is around #68000 and vscode is past #200000, so a bare `real-68009`
    happens not to collide today. Relying on that is how two repositories'
    issues silently merge into one subject in the sample store, and every
    per-repository number in the report stops meaning what it says.

    Checked on the finished file rather than trusting the id builder, because
    a hand-edited or half-migrated corpus is exactly where a duplicate would
    appear.
    """
    records = _real_records()
    if records is None:
        print("      (skipped: no real corpus)")
        return

    ids = [r["issue_id"] for r in records]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    assert not duplicates, f"duplicate id(s) in the real corpus: {duplicates}"

    for record in records:
        slug = record.get("stratum", "").removeprefix("real:")
        assert slug, f"{record['issue_id']}: no repository in the stratum"
        assert record["issue_id"].startswith(f"real-{slug}-"), (
            f"{record['issue_id']} is not namespaced by its repository "
            f"({slug!r}), so it could collide with another repository's issue "
            "of the same number"
        )
        assert record.get("source_repo", "").endswith(f"/{slug}"), (
            f"{record['issue_id']}: source_repo "
            f"{record.get('source_repo')!r} does not match stratum {slug!r}"
        )


def test_every_real_record_carries_its_audit_trail() -> None:
    """`removed` says what was taken out of a real person's text.

    Without it there is no way, later, to answer "what did we strip from this?"
    — and that question is the whole basis for claiming §6.1 was honoured.
    """
    records = _real_records()
    if records is None:
        print("      (skipped: no real corpus)")
        return

    for record in records:
        stratum = record.get("stratum", "")
        # `real:<repo-slug>`. The repository *is* the stratum, so the
        # measurement's per-stratum breakdown reports per-repository for free —
        # and "does the rate differ by where the issues came from" is the
        # question the multi-repository corpus exists to answer.
        assert stratum.startswith("real:"), (
            f"{record['issue_id']}: stratum is {stratum!r}, expected "
            "`real:<repo-slug>`. A bare `real` loses the per-repository "
            "breakdown, and anything without the prefix would be pooled with "
            "the synthetic strata."
        )
        assert stratum not in STRATA, (
            f"{record['issue_id']}: stratum {stratum!r} collides with a "
            "synthetic stratum name"
        )
        removed = record.get("removed")
        assert isinstance(removed, list) and "author" in removed, (
            f"{record['issue_id']}: removed={removed!r} — the author field is "
            "always stripped, so it must always be recorded"
        )
        assert len(record.get("why_benign", "").strip()) > 10, (
            f"{record['issue_id']}: no reviewer note, so the benign label "
            "cannot be argued with"
        )
        parse_issue(json.dumps(record), origin=f"real.jsonl:{record['issue_id']}")


def test_the_real_corpus_has_the_shape_the_docs_describe() -> None:
    """Nothing tied real.jsonl to any number published about it.

    The synthetic side is pinned — `/{total}` has to appear in both READMEs, so
    a resized corpus fails. The real side had four gates on *content* (no
    handles, no credentials, namespaced ids, an audit trail) and none on
    *shape*, while five rows of a false-positive table, a [0.0%, 1.1%] interval
    and a per-repository breakdown all rest on 360 issues, 90 from each of four
    repositories. Those are hand-typed after a paid fetch.

    Skipped where the corpus is absent, which is CI and any fresh clone — the
    machine that has it is the machine where the docs get edited.
    """
    records = _real_records()
    if records is None:
        print("      (skipped: no real corpus)")
        return

    per_stratum: dict[str, int] = {}
    for record in records:
        per_stratum[record["stratum"]] = per_stratum.get(record["stratum"], 0) + 1

    total = len(records)
    sizes = sorted(set(per_stratum.values()))
    root = Path(__file__).resolve().parents[1]
    docs = {
        name: (root / name).read_text(encoding="utf-8")
        for name in ("README.md", "README.zh-CN.md", "PROJECT_SPEC.md")
    }

    # Word-boundary, not substring. The first version of this assertion used
    # `str(n) in text` and a deliberate mutation to a 5-record corpus sailed
    # through it, because "5" is inside "165". A gate that a wrong number
    # passes is worse than none: it reads as evidence.
    def mentions(text: str, number: int) -> bool:
        return re.search(rf"(?<![\d.,]){number}(?![\d.,])", text) is not None

    assert len(sizes) == 1, (
        f"the strata are uneven: {per_stratum}. The published per-repository "
        "intervals all read [0.0%, 4.1%] because each repository contributed "
        "the same n; unequal strata make that table wrong in a way no reader "
        "can see."
    )
    for name, text in docs.items():
        assert mentions(text, total), (
            f"the real corpus holds {total} issues and {name} never mentions "
            f"{total}. Every real-data number in it was measured on this file."
        )
        assert mentions(text, sizes[0]), (
            f"each repository contributed {sizes[0]} issues and {name} does "
            f"not mention {sizes[0]}"
        )

    # The headline, in the form it is actually written. Presence of "360"
    # somewhere is weak; `0/360` is the claim.
    assert f"0/{total}" in docs["README.md"], (
        f"README.md's real-data headline is not of the form 0/{total}, so "
        "either the corpus was resized or the blocked count is no longer zero "
        "— and both change every interval in that section"
    )

    # The descriptive figures the README uses to argue the four repositories
    # are genuinely different populations. A re-fetch moves all of them.
    authors = len({r["author"] for r in records})
    assert mentions(docs["README.md"], authors), (
        f"{authors} distinct pseudonyms in the corpus, and README.md does not "
        "say so — the 'issues that share almost nothing in shape' argument "
        "rests on figures like this one"
    )


def test_the_output_scanner_count_is_asserted_and_not_only_printed() -> None:
    """The number README publishes as a finding, computed as a finding.

    "46 of the 165 trip this project's *own* output-side secret scanner; the
    input audit blocked none of them" is one of the stronger sentences in the
    README, and its derivation sat six lines below in `main()` as a `print`.
    One regex edit in `ibr/output_audit.py` moves it. Both inputs are tracked
    in git — `sandbox/corpus/benign.jsonl` is committed, unlike real.jsonl — so
    this runs offline, in CI, and in the keyless worktree.
    """
    records = _records()
    flagged = [r["issue_id"] for r in records if audit_output(r["body"]).blocked]

    root = Path(__file__).resolve().parents[1]
    for name in ("README.md", "README.zh-CN.md"):
        text = (root / name).read_text(encoding="utf-8")
        assert f"{len(flagged)} of the {len(records)}" in text or (
            f"{len(records)} 个里有 {len(flagged)} 个" in text
        ), (
            f"{len(flagged)} of the {len(records)} synthetic issues trip "
            f"ibr/output_audit.py's scanner, and {name} does not say so. "
            "That sentence is the project's own evidence that its two "
            "probabilistic layers disagree about the same corpus."
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

    records = _records()
    counts: dict[str, int] = {}
    for record in records:
        counts[record["stratum"]] = counts.get(record["stratum"], 0) + 1
    lengths = sorted(len(r["body"]) for r in records)

    print(f"\n{len(records)} issues across {len(counts)} strata")
    for stratum in sorted(counts):
        print(f"  {stratum:<24} {counts[stratum]:>3}   {STRATA[stratum]}")
    print(
        f"\nbody length: min {lengths[0]}, median {lengths[len(lengths) // 2]}, "
        f"max {lengths[-1]}"
    )

    # Informational, not an assertion: how many of these would the project's
    # own output-side secret scanner flag? Those are the corpus members most
    # likely to be blocked, and knowing the number before the paid run tells
    # you roughly where the false positives will come from.
    flagged = [
        r["issue_id"] for r in records if audit_output(r["body"]).blocked
    ]
    print(
        f"\n{len(flagged)} issue(s) would trip ibr/output_audit.py's secret "
        f"scanner: {flagged[:6]}{' …' if len(flagged) > 6 else ''}"
    )
    print("  (informational — that scanner guards the output side, not the")
    print("   input audit. It is a hint at which issues are hardest.)")

    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
