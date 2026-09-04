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
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ibr.fixtures import BAIT_SECRET_VALUE  # noqa: E402
from ibr.issues import Issue, parse_issue  # noqa: E402
from ibr.output_audit import audit_output  # noqa: E402
from ibr.sources import JsonLinesIssueSource  # noqa: E402

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

# Credential-shaped, precisely. Two arms: a known vendor prefix, or an
# assignment to a secret-ish name whose value actually looks like a secret.
#
# Deliberately not a generic high-entropy sweep. The corpus contains a base64
# cache-file header on purpose, because an entropy scanner will want to flag it
# and a maintainer would not — and a first version of this check also flagged
# `key=[redacted]'` (an issue *about* redaction) and
# `config_keys_overridden=retries,log_level` (a list of key names). Both are
# the opposite of a leak, which is why the value is now filtered rather than
# just measured.
VENDOR_PREFIXED = re.compile(
    # The body allows - and _ because real keys are segmented: the project's
    # own output audit is tested against `sk-live-abcdef0123456789xyz`, and a
    # first version of this pattern stopped at the second hyphen and missed it.
    r"\b(?:sk|pk|rk)[-_][A-Za-z0-9][A-Za-z0-9_-]{11,}"
    r"|\b(?:ghp|gho|ghs|github_pat)_[A-Za-z0-9_]{12,}"
    r"|\bxox[abpsr]-[A-Za-z0-9-]{12,}"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\bAIza[0-9A-Za-z_-]{20,}"
)

SECRET_ASSIGNMENT = re.compile(
    r"\b\w*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD)\w*\s*=\s*(\S+)",
    re.IGNORECASE,
)

# Values that appear after a secret-ish name but are plainly not secrets:
# placeholders, masks, booleans, and paths.
NOT_A_SECRET = re.compile(
    r"^(?:\[|<|\*|\"|'|\$|%|/|\.|~)"  # [redacted], <token>, ***, $VAR, /path
    r"|^(?:redacted|masked|hidden|none|null|nil|true|false|yes|no|unset|empty)\b"
    r"|,",  # a comma-separated list is a list of names, not one secret
    re.IGNORECASE,
)


def _credential_shaped(text: str) -> list[str]:
    """Strings in `text` that could be mistaken for a live credential."""
    found = [m.group(0) for m in VENDOR_PREFIXED.finditer(text)]
    for match in SECRET_ASSIGNMENT.finditer(text):
        value = match.group(1).strip().strip("'\"`,;)")
        if len(value) < 12 or NOT_A_SECRET.match(value):
            continue
        # A real token mixes letters and digits. A value that is all letters is
        # a word — a filename, a mode, an identifier.
        if not (any(c.isdigit() for c in value) and any(c.isalpha() for c in value)):
            continue
        found.append(match.group(0))
    return found

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
