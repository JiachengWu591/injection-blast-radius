# Architecture

*English · [简体中文](./ARCHITECTURE.zh-CN.md)*

How `ibr/` is layered, why that order and not another, and the three places to
change when pointing this at real data.

The layering is not aspirational. It is computed from the imports by
`test_dependency_layers_have_not_inverted` in
[`tests/test_architecture.py`](tests/test_architecture.py), which fails if a
module ever imports from a layer above its own.

## The package diagram

Seven layers, no cycles, 18 modules. Arrows are UML dependencies: each points
**from a module to what it imports**, so every arrow runs downward and none may
run up. Red is the pair the security claim rests on; blue is the two seams you
replace to point this at real data.

Every edge below is real — this is the graph
[`tests/test_architecture.py`](tests/test_architecture.py) computes from the
imports, not a simplification of it. The edges into `config` and `fixtures` are
dotted only because eleven modules read paths and constants from them and solid
lines would bury everything else.

```mermaid
flowchart TD
    classDef trust fill:#fdeaea,stroke:#c0392b,stroke-width:3px,color:#7b241c
    classDef seam fill:#e8f1fd,stroke:#2471a3,stroke-width:3px,color:#1a5276
    classDef ambient fill:#f4f6f6,stroke:#aab7b8,stroke-dasharray:4,color:#566573
    classDef harness fill:#f5eef8,stroke:#8e44ad,color:#5b2c6f
    classDef plain fill:#fdfefe,stroke:#5d6d7e,color:#212f3d

    subgraph l6["layer 6"]
        report["report<br/>terminal + markdown rendering"]
    end
    subgraph l5["layer 5 · measurement, not architecture"]
        comparison["comparison<br/>the six-scenario matrix"]
        variance["variance<br/>sampling, Wilson/Newcombe"]
    end
    subgraph l4["layer 4 · the defended path"]
        pipeline["pipeline<br/>audit → Reader → BOUNDARY → Executor → output audit"]
    end
    subgraph l3["layer 3 · the agents"]
        executor["executor<br/>holds the permissions<br/>reads two enum fields"]
        baseline_agent["baseline_agent<br/>undefended: reads, reads files, publishes"]
        sources["sources<br/>SEAM 1 · where issues come from"]
        attack_corpus["attack_corpus<br/>twelve injection techniques"]
    end
    subgraph l2["layer 2 · the surfaces"]
        sinks["sinks<br/>SEAM 2 · where actions land"]
        issues["issues<br/>the Issue contract + one validator"]
        observability["observability<br/>one JSONL row per stage"]
        bootstrap["bootstrap<br/>sandbox tree + bait file"]
    end
    subgraph l1["layer 1"]
        llm["llm<br/>the only module that knows the API exists"]
        sandbox_fs["sandbox_fs<br/>the path whitelist"]
    end
    subgraph l0["layer 0 · no dependencies at all"]
        schemas["schemas<br/>THE STRUCTURAL BOUNDARY<br/>untrusted bytes → validated value"]
        output_audit["output_audit<br/>regex + entropy secret scan"]
        config["config<br/>paths · model ids · credentials"]
        fixtures["fixtures<br/>the demo's fake secret"]
    end

    report --> comparison
    comparison --> pipeline
    comparison --> baseline_agent
    comparison --> executor
    comparison --> bootstrap
    comparison --> issues
    comparison --> observability
    comparison --> schemas
    comparison --> sandbox_fs
    variance --> pipeline
    variance --> issues
    variance --> schemas
    pipeline --> executor
    pipeline --> sinks
    pipeline --> schemas
    pipeline --> issues
    pipeline --> llm
    pipeline --> observability
    executor --> schemas
    executor --> output_audit
    executor --> sinks
    baseline_agent --> llm
    baseline_agent --> issues
    baseline_agent --> observability
    baseline_agent --> sandbox_fs
    sources --> issues
    sources --> sandbox_fs
    attack_corpus --> issues
    sinks --> sandbox_fs
    issues --> sandbox_fs
    observability --> sandbox_fs
    bootstrap --> sandbox_fs
    llm -.-> config
    sandbox_fs -.-> config
    bootstrap -.-> fixtures
    comparison -.-> fixtures
    report -.-> fixtures

    class schemas trust
    class executor trust
    class sinks seam
    class sources seam
    class config ambient
    class fixtures ambient
    class report harness
    class comparison harness
    class variance harness
    class attack_corpus harness
    class pipeline plain
    class baseline_agent plain
    class issues plain
    class observability plain
    class bootstrap plain
    class llm plain
    class sandbox_fs plain
    class output_audit trust
```

The shape worth noticing: **`executor` — the module that holds every permission
— has exactly three arrows out of it**, and all three land on layer 0 or the
sink protocol. It does not know where issues come from, how the model is
called, or what gets logged. That is not tidiness; it is why substituting a
source or a sink cannot widen what the executor can be made to do.

## What each layer is for

### Layer 0 — no dependencies at all

| Module | Responsibility |
|---|---|
| `config` | Every path, model id, and the credential check. One answer per question, so swapping a model is a one-line change. |
| `schemas` | The two data contracts and their parsers. **This is the structural boundary.** Raw model output goes in; a validated frozen dataclass comes out, or it raises. |
| `output_audit` | Regex and entropy scanning for secret shapes. Deliberately independent of everything: it must be usable on any string. |
| `fixtures` | The demo's fake secret and bait file. Separate from `config` because they are props, not settings: `config` is the file you edit to adopt this, `fixtures` is the file you delete. |

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
| `issues` | The `Issue` contract and its validator. `parse_issue` is separate from any storage so every source shares one set of checks. |
| `observability` | One JSONL record per stage. Scrubs the API key defensively. |
| `sinks` | Where the executor's actions land. **Seam 2 for production data.** |

`sinks` sits *below* `executor` rather than beside it, which is the point: the
executor depends on the destination protocol, never the other way round. A sink
cannot reach back into the decision.

### Layer 3 — the agents

| Module | Responsibility |
|---|---|
| `executor` | Holds the permissions and reads only two enum fields. Writes nothing itself — hands the chosen action to a sink. |
| `baseline_agent` | The undefended architecture: reads untrusted text, reads files, publishes. All three in one context, on purpose. |
| `sources` | Where issues come from. **Seam 1 for production data.** |
| `attack_corpus` | Twelve injection techniques. Research input, not runtime. |

### Layer 4 — the defended path

| Module | Responsibility |
|---|---|
| `pipeline` | The isolated architecture: audit → Reader → boundary → Executor → output audit. Takes an `Issue` and a sink, so both seams meet here. |

### Layers 5–6 — the harness

`comparison` runs the scenario matrix, `variance` samples the audit and computes
Wilson/Newcombe intervals, `report` renders both. None of it is needed to adopt
the architecture; it exists to measure it.

## The class diagram

Six frozen dataclasses, two protocols, and four implementations. Everything
that crosses a stage boundary in this project is one of these — there is no
dict passed between stages anywhere, which is what makes "the boundary is these
lines" a statement you can check rather than a claim.

The field lists below are checked against the real `dataclasses.fields()` by
`test_the_class_diagram_matches_the_dataclasses`, so this diagram cannot
describe a class that has changed shape.

```mermaid
classDiagram
    direction LR

    class Issue {
        <<frozen>>
        +str issue_id
        +str title
        +str author
        +str body
    }

    class AuditVerdict {
        <<frozen>>
        +str reasoning
        +str risk_level
        +tuple~str~ matched_patterns
        +bool completed
    }

    class ReaderOutput {
        <<frozen>>
        +str reasoning
        +str issue_type
        +str summary
        +str suggested_action
    }

    class ExecutorDecision {
        <<frozen>>
        +str action_taken
        +Optional~str~ published_comment
        +tuple~str~ labels_added
        +Optional~OutputAuditResult~ output_audit
        +str note
    }

    class OutputAuditResult {
        <<frozen>>
        +bool blocked
        +tuple~str~ findings
        +summary() str
    }

    class IssueSource {
        <<interface>>
        +load_issue(name) Issue
        +available_issues() list
    }
    class SandboxIssueSource {
        +Path directory
    }
    class JsonLinesIssueSource {
        +Path path
    }

    class ActionSink {
        <<interface>>
        +publish_comment(issue_id, body) None
        +add_label(issue_id, label) None
    }
    class SandboxActionSink {
        +str surface
    }
    class DryRunSink {
        <<mutable>>
        +list~RecordedAction~ actions
    }
    class RecordedAction {
        <<frozen>>
        +str kind
        +str issue_id
        +str payload
    }

    IssueSource <|.. SandboxIssueSource : realises
    IssueSource <|.. JsonLinesIssueSource : realises
    IssueSource ..> Issue : produces
    ActionSink <|.. SandboxActionSink : realises
    ActionSink <|.. DryRunSink : realises
    DryRunSink o-- RecordedAction : records
    ExecutorDecision --> OutputAuditResult : carries
```

Both protocols are `typing.Protocol` and `@runtime_checkable`, so realisation
is **structural, not declared**: an adopter's own class satisfies `ActionSink`
without importing anything from this package, and
`test_a_hand_written_sink_satisfies_the_protocol_structurally` proves it with a
class defined inside the test.

Two implementations each, not one. A protocol with a single implementation is
indistinguishable from a description of that implementation, and every seam
assertion that matters runs against the *non-default* one.

### Where the boundary actually is

The class diagram cannot express the load-bearing fact, because UML has no way
to say "this consumer reads only some of that type's fields". `ReaderOutput`
has four fields; the Executor reads two:

```mermaid
flowchart LR
    classDef danger fill:#fdeaea,stroke:#c0392b,stroke-width:2px,color:#7b241c
    classDef safe fill:#eafaf1,stroke:#1e8449,stroke-width:2px,color:#145a32
    classDef dead fill:#f4f6f6,stroke:#aab7b8,stroke-dasharray:4,color:#566573

    subgraph reader["Reader · has seen the attack, has no tools"]
        rr["reasoning<br/>free text, attacker-controlled"]
        rs["summary<br/>free text, attacker-controlled"]
        rt["issue_type<br/>one of 4"]
        ra["suggested_action<br/>one of 4"]
    end

    log["observability<br/>logged, never branched on"]
    void["never read by the Executor"]
    ex["Executor<br/>holds every permission"]
    tpl["COMMENT_TEMPLATES<br/>4 static strings, no interpolation"]
    out["public surface"]

    rr --> log
    rs --> log
    rr --x void
    rs --x void
    rt --> ex
    ra --> ex
    ex --> tpl
    tpl --> out

    class rr danger
    class rs danger
    class rt safe
    class ra safe
    class void dead
    class log dead
    class ex safe
    class tpl safe
    class out safe
```

A fully captured Reader gets to pick one of four actions and one of four issue
types. Sixteen combinations, enumerated before the attacker arrived. The two
fields it can write anything at all into reach the log and nothing else —
[`ibr/executor.py:119`](ibr/executor.py#L119) is the `match`, and the whole file
never mentions `reasoning` or `summary` outside the logging record.

That is the difference between the two materials: the audit *probably* stops an
attack; this *bounds* what any attack can accomplish, and the bound does not
move when the attacker gets better.

## Reading order

If you are reading the code for the first time, the useful order is not the
dependency order. Start where the argument is:

1. [`ibr/schemas.py`](ibr/schemas.py) — the contracts, and why `reasoning` is
   declared before the verdict.
2. [`ibr/executor.py`](ibr/executor.py) — the whitelist `match` and the four
   static templates. This is the whole claim in 164 lines.
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
from ibr.sources import IssueSource, JsonLinesIssueSource

class MyIssueSource:                       # satisfies IssueSource structurally
    def load_issue(self, name: str) -> Issue: ...
    def available_issues(self) -> list[str]: ...

run_isolated(source.load_issue("4821"))    # takes an Issue, not a name
```

`Issue` is a frozen dataclass with four string fields. Anything that can produce
one — a JSONL export, a database row, a webhook payload — is a valid source. The
pipeline never loads issues itself; it is handed one, which is why this seam
needs no change to the defended path at all.

`JsonLinesIssueSource` ships as a worked second implementation, both because
that is the shape most exports arrive in and because one implementation of a
protocol is indistinguishable from a description of that implementation.

A source must not filter. Dropping suspicious-looking input at load time would
be a fourth defence layer, unmeasured and sitting where nobody would look for
it. Screening is the audit's job, and the audit is measured.

### Seam 2 — where actions go

```python
from ibr.sinks import ActionSink, DryRunSink

dry = DryRunSink()
run_isolated(issue, sink=dry)              # records, writes nothing
dry.comments, dry.labels                   # what it would have done
```

The executor publishes through a sink rather than calling `sandbox_fs`
directly. `DryRunSink` exists because the first thing you want against real data
is to see what *would* have happened. Any real sink should be built on top of it
rather than beside it: run in dry-run until the recorded actions look right.

Note where the output audit runs: in `_publish`, *before* the sink is called,
not inside the sink. A sink is swappable; the last check before anything becomes
public is not.

### Seam 3 — which model

One line in `ibr/config.py`. `AUDIT_MODEL` and `READER_MODEL` are separate on
purpose: screening is cheap and frequent, classification is neither, and there
is no reason they must be the same model.

## What does *not* change when you swap any of these

The structural guarantee is a property of `schemas` (layer 0) and `executor`
(layer 3), and neither of them knows where issues come from or where actions go.
`executor` imports `sinks`, `output_audit` and `schemas` — that is the entire
list. Substituting a source or a sink cannot widen the set of reachable actions,
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
