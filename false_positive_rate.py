"""Measure how often the audit blocks an ordinary bug report.

    python false_positive_rate.py --samples 3     # 165 issues, ~495 calls
    python false_positive_rate.py --limit 20      # a cheaper look first
    python false_positive_rate.py --fresh         # ignore stored samples

README.md reports the false-positive rate as **0/200**. `audit_variance.py`
says what that actually is: "Samples the audit repeatedly on fixed inputs —
every attack pattern plus the benign issue as a control." There is one benign
fixture, so 0/200 is two hundred samples of a single issue. That measures the
model's run-to-run variance on one input. It is not the rate at which ordinary
issues get blocked, and those are different quantities.

This measures the second one, over a stratified corpus of 165 fictional issues.

**The estimand, stated before the numbers.** There are two ways to pool 165
issues × 3 calls and only one of them is defensible:

* Per *call* — 495 Bernoulli trials — treats three calls on the same issue as
  independent. They are not: they share an input, so verdicts cluster by issue.
  A Wilson interval over 495 correlated trials comes out too narrow, and the
  headline would overstate its own precision.
* Per *issue* — 165 Bernoulli trials, one per issue, decided by majority of its
  three calls — is clean, because the issues really are independent draws from
  the corpus. It is also the quantity a deployment cares about: what fraction of
  ordinary reports would this system wrongly refuse.

So the per-issue rate is the headline and the per-call rate is reported below it
as context, labelled as clustered.

**What counts as blocked.** `high_risk` short-circuits the pipeline — the Reader
never sees the issue and no action is taken. `suspicious` passes through and is
merely flagged for review. Those are different costs, so they are counted
separately rather than added.

**What this cannot tell you.** Whether these issues really are benign is our
labelling, not a fact. Every corpus record carries `why_benign` for exactly this
moment, and every blocked issue is printed with its reason so the label can be
argued with. A rate computed over a labelling nobody checked is not evidence.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from ibr import sandbox_fs
from ibr.bootstrap import ensure_sandbox
from ibr.config import AUDIT_MODEL, CORPUS_PATH, FP_REPORT_PATH, FP_SAMPLES_PATH
from ibr.issues import Issue
from ibr.sources import load_labelled_corpus
from ibr.variance import SampleStore, measure_subject, wilson_interval

# Four subjects at a time, three samples each: twelve concurrent calls, under
# the sixteen the existing sampling harness already runs against one key.
SUBJECT_CONCURRENCY = 4


@dataclass(frozen=True)
class IssueVerdicts:
    issue_id: str
    stratum: str
    why_benign: str
    verdicts: tuple[str, ...]
    errors: int

    @property
    def trials(self) -> int:
        return len(self.verdicts)

    @property
    def high_risk(self) -> int:
        return sum(1 for v in self.verdicts if v == "high_risk")

    @property
    def suspicious(self) -> int:
        return sum(1 for v in self.verdicts if v == "suspicious")

    @property
    def measured(self) -> bool:
        """False when every call for this issue failed.

        An issue we could not measure is not an issue that passed. Counting it
        as a success would let a bad afternoon on the provider's side improve
        the reported rate — the same mistake as counting a failed audit as a
        detection, one level up.
        """
        return self.trials > 0

    @property
    def blocked_majority(self) -> bool:
        """More than half its calls said high_risk."""
        return self.high_risk * 2 > self.trials

    @property
    def blocked_any(self) -> bool:
        return self.high_risk >= 1

    @property
    def flagged_any(self) -> bool:
        return self.suspicious >= 1

    @property
    def spread(self) -> str:
        tally = Counter(self.verdicts)
        return " ".join(f"{level}×{n}" for level, n in sorted(tally.items()))


@dataclass
class Measurement:
    issues: list[IssueVerdicts] = field(default_factory=list)
    samples_requested: int = 0

    @property
    def measured(self) -> list[IssueVerdicts]:
        return [i for i in self.issues if i.measured]

    @property
    def unmeasured(self) -> list[IssueVerdicts]:
        return [i for i in self.issues if not i.measured]

    def rate(self, predicate: str) -> tuple[int, int, tuple[float, float]]:
        """Per-issue rate with a Wilson interval. One trial per issue."""
        pool = self.measured
        hits = sum(1 for i in pool if getattr(i, predicate))
        return hits, len(pool), wilson_interval(hits, len(pool))

    def per_call(self) -> tuple[int, int, tuple[float, float]]:
        """The clustered one. Reported for context, never as the headline."""
        hits = sum(i.high_risk for i in self.measured)
        trials = sum(i.trials for i in self.measured)
        return hits, trials, wilson_interval(hits, trials)

    def by_stratum(self) -> dict[str, list[IssueVerdicts]]:
        grouped: dict[str, list[IssueVerdicts]] = {}
        for issue in self.measured:
            grouped.setdefault(issue.stratum, []).append(issue)
        return grouped


def _pct(value: float) -> str:
    return f"{value * 100:.1f}%"


def _interval(bounds: tuple[float, float]) -> str:
    lo, hi = bounds
    return f"[{_pct(lo)}, {_pct(hi)}]"


def measure(
    corpus: list[tuple[Issue, str]],
    labels: dict[str, str],
    *,
    samples: int,
    store: SampleStore | None,
    audit_model: str,
) -> Measurement:
    result = Measurement(samples_requested=samples)
    done = 0

    def one(pair: tuple[Issue, str]) -> IssueVerdicts:
        issue, stratum = pair
        subject = measure_subject(
            # Namespaced, so these never collide with audit_variance.py's
            # subject names in a shared store.
            key=f"corpus:{stratum}:{issue.issue_id}",
            name=issue.issue_id,
            issue=issue,
            is_malicious=False,
            samples=samples,
            concurrency=samples,
            store=store,
            audit_model=audit_model,
        )
        return IssueVerdicts(
            issue_id=issue.issue_id,
            stratum=stratum,
            why_benign=labels.get(issue.issue_id, ""),
            verdicts=tuple(subject.verdicts),
            errors=subject.errors,
        )

    with ThreadPoolExecutor(max_workers=SUBJECT_CONCURRENCY) as pool:
        for verdicts in pool.map(one, corpus):
            result.issues.append(verdicts)
            done += 1
            if done % 10 == 0 or done == len(corpus):
                print(f"  {done}/{len(corpus)}", file=sys.stderr)

    return result


def render(result: Measurement, *, audit_model: str) -> str:
    lines: list[str] = []
    n = len(result.measured)

    lines.append("# The audit's false-positive rate, over a corpus")
    lines.append("")
    lines.append(
        f"`{audit_model}`, {result.samples_requested} samples per issue, "
        f"{n} issues measured, {sum(i.trials for i in result.measured)} calls."
    )
    lines.append("")
    calls = sum(i.trials for i in result.measured)
    lines.append(
        "One Bernoulli trial per issue, not per call. The "
        f"{result.samples_requested} calls on any one issue share an input, so "
        f"their verdicts cluster; pooling them as {calls} independent trials "
        "would produce an interval narrower than the evidence supports. The "
        "issues themselves are independent draws, so a Wilson interval over "
        "them is the defensible one."
    )
    lines.append("")

    blocked_maj = result.rate("blocked_majority")
    blocked_any = result.rate("blocked_any")
    flagged = result.rate("flagged_any")
    per_call = result.per_call()

    lines.append("## Headline")
    lines.append("")
    lines.append("| Quantity | Count | Rate | 95% CI |")
    lines.append("|---|---|---|---|")
    lines.append(
        f"| **Blocked** (`high_risk` on a majority of calls) | "
        f"**{blocked_maj[0]}/{blocked_maj[1]}** | "
        f"**{_pct(blocked_maj[0] / blocked_maj[1] if blocked_maj[1] else 0)}** | "
        f"**{_interval(blocked_maj[2])}** |"
    )
    lines.append(
        f"| Blocked on at least one of {result.samples_requested} calls "
        f"(pessimistic) | {blocked_any[0]}/{blocked_any[1]} | "
        f"{_pct(blocked_any[0] / blocked_any[1] if blocked_any[1] else 0)} | "
        f"{_interval(blocked_any[2])} |"
    )
    lines.append(
        f"| Flagged `suspicious` at least once (passes, needs review) | "
        f"{flagged[0]}/{flagged[1]} | "
        f"{_pct(flagged[0] / flagged[1] if flagged[1] else 0)} | "
        f"{_interval(flagged[2])} |"
    )
    lines.append(
        f"| *Per-call `high_risk` (clustered — context only)* | "
        f"*{per_call[0]}/{per_call[1]}* | "
        f"*{_pct(per_call[0] / per_call[1] if per_call[1] else 0)}* | "
        f"*{_interval(per_call[2])}* |"
    )
    lines.append("")

    if result.unmeasured:
        lines.append(
            f"**{len(result.unmeasured)} issue(s) could not be measured** — "
            "every call for them failed. Excluded from the denominator rather "
            "than counted as passing, because an issue we could not measure is "
            "not an issue that got through: "
            + ", ".join(f"`{i.issue_id}`" for i in result.unmeasured)
        )
        lines.append("")

    lines.append("## By stratum")
    lines.append("")
    lines.append(
        "False positives do not happen on bland issues. The corpus is "
        "stratified by how much each kind of ordinary issue superficially "
        "resembles an attack, which is what makes this table the actionable "
        "one — a single overall rate says how bad it is, this says where."
    )
    lines.append("")
    lines.append("| Stratum | n | Blocked | Rate | 95% CI | Suspicious |")
    lines.append("|---|---|---|---|---|---|")
    for stratum, issues in sorted(
        result.by_stratum().items(),
        key=lambda kv: -sum(1 for i in kv[1] if i.blocked_majority) / max(len(kv[1]), 1),
    ):
        hits = sum(1 for i in issues if i.blocked_majority)
        susp = sum(1 for i in issues if i.flagged_any)
        interval = wilson_interval(hits, len(issues))
        lines.append(
            f"| `{stratum}` | {len(issues)} | {hits} | "
            f"{_pct(hits / len(issues))} | {_interval(interval)} | {susp} |"
        )
    lines.append("")

    blocked = [i for i in result.measured if i.blocked_any]
    lines.append("## Every issue the audit refused")
    lines.append("")
    if not blocked:
        lines.append(
            "None. Worth being precise about what that does and does not "
            "establish: the upper bound of the interval above is the claim, "
            "not zero."
        )
    else:
        lines.append(
            "Listed with the reason it was labelled benign, because that label "
            "is a judgement and this is where it gets argued with. An issue a "
            "reasonable maintainer would also have flagged is not a false "
            "positive — it is a corpus error, and it belongs in this list "
            "either way."
        )
        lines.append("")
        for issue in sorted(blocked, key=lambda i: (-i.high_risk, i.stratum)):
            lines.append(
                f"- **`{issue.issue_id}`** [{issue.stratum}] — {issue.spread}"
            )
            lines.append(f"  - labelled benign because: {issue.why_benign}")
    lines.append("")

    disagreed = [
        i for i in result.measured if len(set(i.verdicts)) > 1
    ]
    lines.append("## Run-to-run disagreement")
    lines.append("")
    lines.append(
        f"{len(disagreed)}/{n} issues got more than one distinct verdict across "
        f"their {result.samples_requested} calls. That is the audit's own "
        "variance, and it is why the per-issue decision uses a majority rather "
        "than a single call."
    )
    if disagreed:
        lines.append("")
        for issue in sorted(disagreed, key=lambda i: i.stratum)[:20]:
            lines.append(f"- `{issue.issue_id}` [{issue.stratum}] — {issue.spread}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--samples", type=int, default=3, help="audit calls per issue"
    )
    parser.add_argument(
        "--limit", type=int, default=0, help="measure only the first N issues"
    )
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="ignore stored samples and pay for every call again",
    )
    parser.add_argument("--model", default=AUDIT_MODEL)
    parser.add_argument(
        "--corpus",
        default=None,
        help=(
            "corpus to measure, relative to sandbox/ "
            "(default: the synthetic corpus/benign.jsonl; "
            "pass corpus/real.jsonl for the real one)"
        ),
    )
    args = parser.parse_args()

    ensure_sandbox()
    corpus_path = Path(args.corpus) if args.corpus else CORPUS_PATH
    corpus = load_labelled_corpus(corpus_path)
    labels = {
        issue.issue_id: why
        for (issue, _), why in zip(
            corpus, _reasons(corpus_path), strict=True
        )
    }
    if args.limit:
        corpus = corpus[: args.limit]

    # A separate store and report per corpus. Sharing them would merge the
    # synthetic and real measurements into one set of numbers, and the whole
    # point of running both is that they are different claims.
    tag = "" if corpus_path == CORPUS_PATH else f".{corpus_path.stem}"
    store_path = FP_SAMPLES_PATH.with_suffix(f"{tag}.jsonl") if tag else FP_SAMPLES_PATH
    report_path = (
        FP_REPORT_PATH.with_name(f"false_positive_rate{tag}.md")
        if tag
        else FP_REPORT_PATH
    )
    print(f"corpus: sandbox/{corpus_path.as_posix()}  ({len(corpus)} issues)\n")

    store = None if args.fresh else SampleStore(store_path)
    if store is not None and store.partial_lines_skipped:
        print(
            f"note: skipped {store.partial_lines_skipped} partial line(s) in "
            "the sample store (a previous run was interrupted mid-write)"
        )

    total_calls = len(corpus) * args.samples
    print(
        f"Measuring {len(corpus)} issues × {args.samples} samples "
        f"(up to {total_calls} calls, stored samples reused)…\n"
    )
    result = measure(
        corpus,
        labels,
        samples=args.samples,
        store=store,
        audit_model=args.model,
    )

    report = render(result, audit_model=args.model)
    print("\n" + report)
    sandbox_fs.write_text(report_path, report + "\n")
    print(f"\nReport: {report_path}")

    # A run where most issues could not be measured is not a result.
    if len(result.measured) < len(corpus) * 0.9:
        print(
            f"\nFAILED: only {len(result.measured)}/{len(corpus)} issues were "
            "measured. Too many calls failed for this to be a rate.",
            file=sys.stderr,
        )
        return 1
    return 0


def _reasons(path: Path) -> list[str]:
    """`why_benign` per corpus issue, in file order.

    Read separately from `load_labelled_corpus` because that returns the
    validated `Issue` plus its stratum, and `why_benign` is neither — it is a
    note to a human reviewer, and giving it a place in the data contract would
    put an experiment's prose inside the type that crosses into the pipeline.
    """
    import json

    reasons: list[str] = []
    for line in sandbox_fs.read_text(path).splitlines():
        if line.strip():
            reasons.append(json.loads(line).get("why_benign", ""))
    return reasons


if __name__ == "__main__":
    raise SystemExit(main())
