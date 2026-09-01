# Architecture

*English · [简体中文](./ARCHITECTURE.zh-CN.md)*

How `ibr/` is layered, why that order and not another, and the three places to
change when pointing this at real data.

The layering is not aspirational. It is computed from the imports by
`test_dependency_layers_have_not_inverted` in
[`tests/test_architecture.py`](tests/test_architecture.py), which fails if a
module ever imports from a layer above its own.

## The dependency graph

Six layers, no cycles. Each module depends only on layers below it.

```
layer 0   config          schemas          output_audit
          (paths, ids,    (data contracts, (regex + entropy
           credentials)    the boundary)    scanning)
             │  │  │            │                 │
             │  │  └────────────┼─────────────────┼──────┐
             ▼  ▼               │                 │      │
layer 1   llm      sandbox_fs   │                 │      │
          (provider (the        │                 │      │
           client)   whitelist) │                 │      │
                        │       │                 │      │
             ┌──────────┼───────┴─────────────────┘      │
             ▼          ▼                                 ▼
layer 2   bootstrap  issues  observability          executor
          (sandbox   (issue  (JSONL logging)        (permissions,
           setup)     source)                        enum-only)
                        │            │                   │
             ┌──────────┴────────────┴───────────────────┤
             ▼                                            ▼
layer 3   attack_corpus   baseline_agent            pipeline
          (injection      (undefended,              (audit → reader →
           techniques)     one agent)                BOUNDARY → executor)
                                  │                       │
                                  └───────────┬───────────┤
                                              ▼           ▼
layer 4                              comparison        variance
                                     (scenario         (sampling,
                                      matrix)           statistics)
                                              │
                                              ▼
layer 5                                    report
                                           (rendering)
```

## What each layer is for

### Layer 0 — no dependencies at all

| Module | Responsibility |
|---|---|
| `config` | Every path, model id, and the credential check. One answer per question, so swapping a model is a one-line change. |
| `schemas` | The two data contracts and their parsers. **This is the structural boundary.** Raw model output goes in; a validated frozen dataclass comes out, or it raises. |
| `output_audit` | Regex and entropy scanning for secret shapes. Deliberately independent of everything: it must be usable on any string. |

That `schemas` sits at layer 0 is the single most important fact in this
diagram. The security property does not depend on the filesystem, the provider,
the logger, or the pipeline. It is a pure function from untrusted bytes to a
value in a finite set, which is why `tests/test_phase2.py --offline` can
establish it without a network.

### Layer 1 — one hop

| Module | Responsibility |
|---|---|
| `llm` | Constructs the provider client and forces a named tool call. The only module that knows the API exists. |
| `sandbox_fs` | The whitelist. Resolves a path and proves it lands inside `sandbox/`, or raises. One failure mode, so one `except` suffices everywhere. |

### Layer 2 — the surfaces

| Module | Responsibility |
|---|---|
| `bootstrap` | Creates the sandbox tree and writes the bait file. |
| `issues` | Loads issues. **Seam 1 for production data.** |
| `observability` | One JSONL record per stage. Scrubs the API key defensively. |
| `executor` | Holds the permissions and reads only two enum fields. **Seam 2 for production data** (where actions go). |

### Layer 3 — the agents

| Module | Responsibility |
|---|---|
| `baseline_agent` | The undefended architecture: reads untrusted text, reads files, publishes. All three in one context, on purpose. |
| `pipeline` | The isolated architecture: audit → Reader → boundary → Executor → output audit. |
| `attack_corpus` | Twelve injection techniques. Research input, not runtime. |

### Layers 4–5 — the harness

`comparison` runs the scenario matrix, `variance` samples the audit and computes
Wilson/Newcombe intervals, `report` renders both. None of it is needed to adopt
the architecture; it exists to measure it.

## Reading order

If you are reading the code for the first time, the useful order is not the
dependency order. Start where the argument is:

1. [`ibr/schemas.py`](ibr/schemas.py) — the contracts, and why `reasoning` is
   declared before the verdict.
2. [`ibr/executor.py`](ibr/executor.py) — the whitelist `match` and the four
   static templates. This is the whole claim in 149 lines.
3. [`ibr/pipeline.py`](ibr/pipeline.py) — how the stages are wired, and the
   comment marking the crossing point.
4. [`ibr/baseline_agent.py`](ibr/baseline_agent.py) — what it looks like
   without the boundary.

Everything else is support.

## Pointing this at real data

Three seams, in the order you would hit them. Each has a protocol, a default
implementation that keeps today's behaviour, and room for a second.

### Seam 1 — where issues come from

```python
from ibr.sources import IssueSource, SandboxIssueSource

class MyIssueSource:                       # satisfies IssueSource structurally
    def load_issue(self, name: str) -> Issue: ...
    def available_issues(self) -> list[str]: ...

run_isolated(issue, ...)                   # already takes an Issue, not a name
```

`Issue` is a frozen dataclass with four string fields. Anything that can produce
one — a JSONL export, a database row, a webhook payload — is a valid source. The
pipeline never loads issues itself; it is handed one.

### Seam 2 — where actions go

```python
from ibr.sinks import ActionSink, SandboxActionSink, DryRunSink

execute(issue_id, reader_output, sink=DryRunSink())   # records, writes nothing
```

The executor publishes through a sink rather than calling `sandbox_fs`
directly. `DryRunSink` exists because the first thing you want against real data
is to see what *would* have happened. Any real sink should be built on top of it
rather than beside it: run in dry-run until the recorded actions look right.

### Seam 3 — which model

One line in `ibr/config.py`. `AUDIT_MODEL` and `READER_MODEL` are separate on
purpose: screening is cheap and frequent, classification is neither, and there
is no reason they must be the same model.

## What does *not* change when you swap any of these

The structural guarantee is a property of `schemas` and `executor`, both at or
below layer 2, and neither of them knows where issues come from or where actions
go. Substituting a source or a sink cannot widen the set of reachable actions,
because that set is enumerated in a `match` statement over a fixed tuple.

This is worth stating plainly because it is the practical payoff of the
layering: **the part you have to trust is the part that does not change when you
integrate.**

## Things this architecture does not give you

- **No authorisation model.** The executor decides *what* to do, never *whether
  the requester may*. A production system needs that check somewhere, and it is
  not here.
- **No idempotency.** Running the same issue twice posts twice. A real sink
  needs a dedupe key.
- **No backpressure or rate limiting.** The sampling harness runs 16 concurrent
  calls because that is fine against one provider and one key; it is not a
  pattern to copy.
- **The probabilistic layers stay probabilistic.** Integrating real data does
  not make the audit reliable. See the measurements in
  [README.md](./README.md) for what its miss rate actually is.
