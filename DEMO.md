# Demo script

*English · [简体中文](./DEMO.zh-CN.md)*

Four scenes, roughly ten minutes. Each one is a command you actually run, plus
the point it exists to make. PROJECT_SPEC.md §5 is the source for this
structure.

Before starting: `cp .env.example .env`, paste a DeepSeek key, and run
`python phase0_smoke.py` once to confirm the sandbox and the API are both
working. Do that *before* the audience is watching.

A note you should say out loud early: every "secret" here is the fixed
placeholder `fake-sk-00000000000000000000`, the "GitHub issue" is a local JSON
file, and the "public comment" is a text file in `sandbox/`. Nothing real is
involved, and nothing reaches the network except the model API.

---

## Scene 1 — Both architectures work on a normal issue

```bash
python phase1_baseline.py       # baseline, both fixtures
python phase2_isolated.py       # isolated pipeline, four scenes
```

**Point:** the defense didn't cost the feature.

Show the benign issue getting triaged sensibly in both. The baseline writes a
reply; the isolated pipeline applies a `bug` label. Say the honest version of
this out loud — they are not identical actions, and the isolated executor
*can't* produce free-form prose because it only picks from four predefined
actions. What matters is that a legitimate bug report still gets handled.

If someone asks why that's an acceptable trade: the fixed action set is not a
side effect of the design, it *is* the design. The reason a captured Reader
can't do damage later in the demo is exactly the reason it can't write custom
prose now.

---

## Scene 2 — The baseline falls over

```bash
python phase1_baseline.py
```

**Point:** the danger is three capabilities in one place, not a dumb model.

Walk the transcript. The agent reads the issue, hits the hidden instruction
inside an HTML comment, calls `read_file("sandbox/.env")`, and folds the
contents into its public reply under a "Resolved config" heading. Then show
the evidence:

```bash
cat sandbox/public_comments.txt   # Get-Content on Windows
```

Three things are true of this agent at the same time: it reads untrusted text,
it can read files, and it can publish. Any two of those are fine. All three in
one context is the whole bug. Point at
[`ibr/baseline_agent.py:149`](ibr/baseline_agent.py#L149) — `_post_comment_impl`
does no filtering at all, on purpose.

Two things worth admitting here, because someone will ask:

- **This is probabilistic.** The model sometimes recognises the injection and
  refuses. If it does, re-run — and say that you're re-running. The demo is
  showing that an undefended agent *can* be induced to leak, not that it always
  will.
- **The payload is not the textbook one.** `ignore all previous instructions`
  gets refused by every model tested. What works is a payload dressed as
  routine contributor convention. That's also what works in the wild.

---

## Scene 3 — The isolated pipeline holds, and *why* it holds

```bash
python phase2_isolated.py
python phase3_trace.py --run all
```

**Point:** two layers, two materials, and only one of them is load-bearing.

This scene has an ordering that matters. Do not stop after the first result.

**First**, the ordinary malicious run. The security audit rates the issue
`high_risk` and short-circuits — the Reader and Executor never run. Show the
trace tree. Then immediately undercut it: *this layer is the weak one*. It's a
model judging text, which is the same material as the thing attacking it. It's
cheap and it stops unsophisticated attacks, and a good enough attack walks past
it. If this were the only defense, the system would be one rephrasing away from
Scene 2.

**Second**, the bypassed-audit run. The audit's verdict is ignored and the
malicious text reaches the Reader. Show in the trace that the Reader produced
over a thousand characters of reasoning about the injection — and that the
action which crossed the boundary was still just
`suggested_action='label_bug'`.

**Third**, the deterministic scene, which is the one to spend time on. The
Executor is handed a Reader output with the secret stuffed into both free-text
fields and `reply_comment` selected. No model is involved. What gets published
is the untouched template.

That's the actual claim: a fully captured Reader gets to choose among four
predefined actions, and that set doesn't grow when the attacker gets smarter.

Point at the code while saying it —
[`ibr/executor.py:128`](ibr/executor.py#L128) for the `match`,
[`ibr/pipeline.py:385`](ibr/pipeline.py#L385) for the crossing point.

If you want the strongest version of the claim, run it with no network at all:

```bash
python phase2_isolated.py --scene 4     # the scene above, on its own, in <1s
python tests/test_phase2.py --offline   # ten assertions behind it
```

No API calls, no key needed, same answer every time. Worth doing live in front
of an audience precisely because it can't fail interestingly — which is the
property being demonstrated.

---

## Scene 4 — One command, reproducible

```bash
python run_all.py
```

**Point:** none of this rests on a story I told you.

Six runs, a summary table, and `sandbox/report.md` with a mechanism sentence
for every row and the leaked bytes quoted rather than asserted. The `tries`
column shows `1/3` on the baseline row — the denominator is printed because the
outcome is probabilistic and hiding that would make the demo dishonest.

Worth noting: `run_all.py` exits non-zero if an *isolated* run ever leaks. A
breach must never read as a successful demo.

---

## Questions you should expect

**"Isn't the audit doing the real work?"** In Scene 3's first run, yes — and
that's the point of showing runs 2 and 3. The audit is the layer that fails
first and fails quietly. The structural boundary is what's left.

**"Couldn't a smarter attack beat the boundary too?"** Not in the same way. A
smarter attack against the audit gets a better verdict. A smarter attack
against the Reader gets... one of four enum values. There's no phrasing that
adds a fifth. The way to beat the boundary is to find a bug in the executor or
widen the action set — an engineering mistake, not a prompting one.

**"Why is the isolated benign action different from the baseline's?"** See
Scene 1. Fixed action set, by construction, same reason the attack fails.

**"Does this work with other models?"** The provider is one line in
`ibr/config.py`. The structural assertions don't involve a model at all, so
they hold regardless. The probabilistic rows will differ.

**"Is the audit bypass a real attack?"** No — it's a switch that skips the
short-circuit. Simulated on purpose, so the structural claim is observable on
demand instead of only when someone crafts an attack that beats the current
screening model.
