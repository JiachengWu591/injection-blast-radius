"""Does a stronger model fix the probabilistic layer?

Runs the same corpus through the security audit on two or more models and
compares the measured rates. The question sounds like it should have an easy
answer — spend more per call, screen better — and the interesting result is how
hard that is to demonstrate at any sample size a small project can afford.

Reports three things per model pair:

  * each model's false-negative and false-positive rate with Wilson intervals;
  * the difference between them with a Newcombe interval, which is the only
    honest way to say whether the data distinguishes the models at all;
  * how many samples per model it would take to resolve a difference of the
    size observed, so "the newer model looked better" can be checked against
    what the experiment could actually have detected.

Usage:
    python model_comparison.py
    python model_comparison.py --models deepseek-v4-flash,deepseek-v4-pro
    python model_comparison.py --samples 40 --concurrency 8
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field

from ibr import sandbox_fs
from ibr.attack_corpus import PATTERNS
from ibr.bootstrap import ensure_sandbox
from ibr.config import AUDIT_MODEL, SANDBOX_ROOT
from ibr.issues import Issue, load_issue
from ibr.llm import build_client
from ibr.variance import (
    DEFAULT_CONCURRENCY,
    CorpusVariance,
    SubjectVariance,
    measure_subject,
    newcombe_difference_interval,
    required_samples_per_group,
    wilson_interval,
)

COMPARISON_REPORT_PATH = SANDBOX_ROOT / "model_comparison.md"
DEFAULT_MODELS = ("deepseek-v4-flash", "deepseek-v4-pro")
DEFAULT_SAMPLES = 25
RULE = "─" * 104


def _pct(value: float) -> str:
    return f"{value * 100:.2f}%"


def _signed_pct(value: float) -> str:
    return f"{value * 100:+.2f}%"


@dataclass
class ModelResult:
    model: str
    corpus: CorpusVariance
    latency_note: str = ""

    @property
    def false_negatives(self) -> tuple[int, int]:
        adverse, trials, _ = self.corpus.pooled(self.corpus.malicious)
        return adverse, trials

    @property
    def false_positives(self) -> tuple[int, int]:
        adverse, trials, _ = self.corpus.pooled(self.corpus.benign)
        return adverse, trials

    @property
    def fn_rate(self) -> float:
        adverse, trials = self.false_negatives
        return adverse / trials if trials else 0.0

    @property
    def fp_rate(self) -> float:
        adverse, trials = self.false_positives
        return adverse / trials if trials else 0.0


@dataclass
class Comparison:
    models: list[ModelResult] = field(default_factory=list)
    samples_requested: int = 0


def _subjects() -> list[tuple[str, str, bool, Issue]]:
    subjects: list[tuple[str, str, bool, Issue]] = [
        (p.key, p.name, True, p.as_issue()) for p in PATTERNS
    ]
    subjects.append(
        ("benign_control", "Benign bug report (control)", False, load_issue("benign"))
    )
    return subjects


def measure_model(
    model: str, *, samples: int, concurrency: int
) -> ModelResult:
    client = build_client(timeout=120.0)
    corpus = CorpusVariance(samples_requested=samples)
    for index, (key, name, is_malicious, issue) in enumerate(_subjects(), 1):
        print(f"    [{index}/8] {name}…", flush=True)
        corpus.subjects.append(
            measure_subject(
                key,
                name,
                issue,
                is_malicious=is_malicious,
                samples=samples,
                concurrency=concurrency,
                client=client,
                audit_model=model,
            )
        )
    return ModelResult(model=model, corpus=corpus)


def render_terminal(comparison: Comparison) -> str:
    lines = [RULE]
    lines.append(
        f"{'model':<22} {'false negatives':>18} {'95% CI':>20} "
        f"{'false positives':>18} {'95% CI':>20}"
    )
    lines.append(RULE)
    for result in comparison.models:
        fn_x, fn_n = result.false_negatives
        fp_x, fp_n = result.false_positives
        fn_lo, fn_hi = wilson_interval(fn_x, fn_n)
        fp_lo, fp_hi = wilson_interval(fp_x, fp_n)
        lines.append(
            f"{result.model:<22} "
            f"{f'{fn_x}/{fn_n} = {_pct(result.fn_rate)}':>18} "
            f"{f'[{_pct(fn_lo)}, {_pct(fn_hi)}]':>20} "
            f"{f'{fp_x}/{fp_n} = {_pct(result.fp_rate)}':>18} "
            f"{f'[{_pct(fp_lo)}, {_pct(fp_hi)}]':>20}"
        )
    lines.append(RULE)

    # Per-subject, so a reader can see whether the same payloads are hard for
    # every model or whether the difficulty moves around.
    subjects = comparison.models[0].corpus.subjects
    name_w = max((len(s.name) for s in subjects), default=20) + 1
    cell_w = max(
        [len(s.spread) for r in comparison.models for s in r.corpus.subjects]
        + [len(r.model) for r in comparison.models],
        default=20,
    ) + 2

    lines.append("")
    lines.append("Per-subject verdict spread:")
    header = f"  {'subject':<{name_w}}"
    for result in comparison.models:
        header += f" {result.model:<{cell_w}}"
    lines.append(header)
    for index, subject in enumerate(subjects):
        row = f"  {subject.name:<{name_w}}"
        for result in comparison.models:
            other = result.corpus.subjects[index]
            mark = " " if other.unanimous else "!"
            row += f" {mark}{other.spread:<{cell_w - 1}}"
        lines.append(row)

    if len(comparison.models) >= 2:
        lines.append("")
        lines.append(_render_pairwise_terminal(comparison))

    return "\n".join(lines)


def _render_pairwise_terminal(comparison: Comparison) -> str:
    lines: list[str] = []
    base = comparison.models[0]
    for other in comparison.models[1:]:
        a_x, a_n = base.false_negatives
        b_x, b_n = other.false_negatives
        lo, hi = newcombe_difference_interval(a_x, a_n, b_x, b_n)
        difference = base.fn_rate - other.fn_rate
        needed = required_samples_per_group(base.fn_rate, other.fn_rate)

        lines.append(f"{base.model} minus {other.model}, false-negative rate:")
        lines.append(
            f"  difference {_signed_pct(difference)}   "
            f"95% CI [{_signed_pct(lo)}, {_signed_pct(hi)}]"
        )
        if lo <= 0.0 <= hi:
            lines.append(
                "  The interval spans zero: this experiment does not "
                "distinguish the two models."
            )
            if needed is None:
                lines.append(
                    "  The two measured rates are identical, so no sample size "
                    "would separate them."
                )
            else:
                lines.append(
                    f"  Resolving a difference this size at 80% power would "
                    f"take roughly {needed:,} samples per model"
                )
                lines.append(
                    f"  ({needed * 8:,} audit calls each, versus the "
                    f"{a_n + comparison.models[0].false_positives[1]} run here)."
                )
        else:
            better = other.model if difference > 0 else base.model
            lines.append(
                f"  The interval excludes zero: {better} screened "
                "significantly better on this corpus."
            )
    return "\n".join(lines)


def render_markdown(comparison: Comparison) -> str:
    parts = ["# Does a stronger model fix the probabilistic layer?\n"]
    parts.append(
        f"Generated by `python model_comparison.py --samples "
        f"{comparison.samples_requested}`. Same corpus, same prompt, same "
        "fixed inputs; only the model behind the security audit changes.\n"
    )

    parts.append("## Rates\n")
    parts.append(
        "| Model | False negatives (attack reached Reader) | 95% CI | "
        "False positives (benign blocked) | 95% CI |"
    )
    parts.append("|---|---|---|---|---|")
    for result in comparison.models:
        fn_x, fn_n = result.false_negatives
        fp_x, fp_n = result.false_positives
        fn_lo, fn_hi = wilson_interval(fn_x, fn_n)
        fp_lo, fp_hi = wilson_interval(fp_x, fp_n)
        parts.append(
            f"| `{result.model}` | {fn_x}/{fn_n} = {_pct(result.fn_rate)} "
            f"| [{_pct(fn_lo)}, {_pct(fn_hi)}] "
            f"| {fp_x}/{fp_n} = {_pct(result.fp_rate)} "
            f"| [{_pct(fp_lo)}, {_pct(fp_hi)}] |"
        )
    parts.append("")

    parts.append("## Per-subject\n")
    header = "| Subject | Kind |"
    divider = "|---|---|"
    for result in comparison.models:
        header += f" `{result.model}` |"
        divider += "---|"
    parts.append(header)
    parts.append(divider)
    for index, subject in enumerate(comparison.models[0].corpus.subjects):
        kind = "attack" if subject.is_malicious else "*benign control*"
        row = f"| {subject.name} | {kind} |"
        for result in comparison.models:
            other = result.corpus.subjects[index]
            cell = other.spread if other.unanimous else f"**{other.spread}** ⚠︎"
            row += f" {cell} |"
        parts.append(row)
    parts.append("")

    if len(comparison.models) >= 2:
        parts.append("## Can this experiment tell the models apart?\n")
        base = comparison.models[0]
        for other in comparison.models[1:]:
            a_x, a_n = base.false_negatives
            b_x, b_n = other.false_negatives
            lo, hi = newcombe_difference_interval(a_x, a_n, b_x, b_n)
            difference = base.fn_rate - other.fn_rate
            needed = required_samples_per_group(base.fn_rate, other.fn_rate)

            parts.append(
                f"**`{base.model}` − `{other.model}`**, false-negative rate: "
                f"{_signed_pct(difference)}, 95% CI (Newcombe) "
                f"[{_signed_pct(lo)}, {_signed_pct(hi)}].\n"
            )
            if lo <= 0.0 <= hi:
                parts.append(
                    "The interval spans zero, so **this experiment does not "
                    "distinguish the two models.** Whatever the point estimates "
                    "show, the data is consistent with the rates being equal.\n"
                )
                if needed is None:
                    parts.append(
                        "The two measured rates came out identical, so no sample "
                        "size would separate them here.\n"
                    )
                else:
                    parts.append(
                        f"Resolving a difference of the observed size at 80% "
                        f"power would take roughly **{needed:,} samples per "
                        f"model** — about {needed * 8:,} audit calls each, "
                        f"against the {a_n + base.false_positives[1]} this run "
                        "made. That is the useful finding: at sample sizes a "
                        "small project can afford, *a clean run on a newer "
                        "model is not evidence that the newer model is safer.* "
                        "The experiment could not have shown otherwise.\n"
                    )
            else:
                better = other.model if difference > 0 else base.model
                parts.append(
                    f"The interval excludes zero: **`{better}` screened "
                    "significantly better** on this corpus, at this n.\n"
                )

    parts.append("## Why this doesn't change the architecture\n")
    parts.append(
        "Suppose a stronger model did measurably lower the miss rate. It would "
        "still be a rate. The verdict would still be a model's judgement of "
        "text, still non-deterministic on fixed input, and still something you "
        "could only characterise by sampling. Buying a better probabilistic "
        "layer moves a number; it does not change the kind of claim you can "
        "make about the system.\n\n"
        "The structural boundary is a different kind of claim, and it does not "
        "appear anywhere in this report because it isn't measured. The "
        "executor reads two enum-constrained fields and selects from four "
        "predefined actions; `python tests/test_phase2.py --offline` "
        "establishes that with no API calls at all. That statement doesn't get "
        "better with a bigger model and doesn't degrade with a worse one — "
        "which is the entire reason the defense is built from two materials "
        "rather than two tiers of the same one.\n"
    )

    parts.append("## Caveats\n")
    parts.append(
        f"- n={comparison.samples_requested} per subject per model. The "
        "intervals are wide; that is the honest state of the evidence, not a "
        "presentation problem.\n"
        "- The required-sample estimate uses a normal approximation, which is "
        "crude at rates near zero. Treat it as an order of magnitude.\n"
        "- Pooling across payloads assumes they share one rate, which they "
        "don't. The per-subject table is what qualifies the pooled figures.\n"
        "- One prompt, one corpus, one day. These numbers characterise this "
        "configuration, not the models in general.\n"
    )
    return "\n".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--models",
        default=",".join(DEFAULT_MODELS),
        help=f"comma-separated model ids (default {','.join(DEFAULT_MODELS)})",
    )
    parser.add_argument("--samples", type=int, default=DEFAULT_SAMPLES)
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument("--no-report", action="store_true")
    args = parser.parse_args()

    models = [m.strip() for m in args.models.split(",") if m.strip()]
    if len(models) < 2:
        print(
            "FAILED: --models needs at least two ids to compare "
            f"(got {models}); use audit_variance.py for a single model.",
            file=sys.stderr,
        )
        return 1
    if args.samples < 1:
        print("FAILED: --samples must be at least 1", file=sys.stderr)
        return 1

    ensure_sandbox()
    comparison = Comparison(samples_requested=args.samples)
    total = len(models) * 8 * args.samples
    print(
        f"Sampling the audit {args.samples}× on 8 subjects across "
        f"{len(models)} model(s) = {total} calls…\n"
    )

    for index, model in enumerate(models, 1):
        print(f"  [{index}/{len(models)}] {model}")
        result = measure_model(
            model, samples=args.samples, concurrency=args.concurrency
        )
        empty = [s for s in result.corpus.subjects if s.trials == 0]
        if empty:
            print(
                f"\nFAILED: no successful audit calls on {model} for "
                f"{', '.join(s.key for s in empty)}",
                file=sys.stderr,
            )
            return 1
        comparison.models.append(result)
        print()

    print(render_terminal(comparison))

    dropped = sum(
        s.errors for r in comparison.models for s in r.corpus.subjects
    )
    if dropped:
        print(f"\n{dropped} call(s) errored and were excluded from the counts.")

    if not args.no_report:
        sandbox_fs.write_text(COMPARISON_REPORT_PATH, render_markdown(comparison))
        print(f"\nFull report: {COMPARISON_REPORT_PATH}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
