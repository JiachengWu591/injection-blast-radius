# injection-blast-radius

> Reproduces a real 2026 indirect prompt-injection attack class targeting coding agents, and demonstrates why **architectural isolation — not prompt-level filtering — is the one defense layer that doesn't degrade as attacks get smarter.**

<!-- TODO once Phase 1+2 are working: side-by-side GIF/screenshot,
     undefended agent leaking a secret vs. isolated agent staying clean -->

## The problem

Indirect prompt injection isn't a bug you can patch — it's a structural consequence of how LLMs work: instructions and data arrive as the same stream of tokens, so the model has no built-in way to tell them apart. In 2026, this stopped being theoretical: the same injection pattern was shown to compromise multiple production coding agents through nothing more than hidden instructions in a GitHub issue or PR comment.

Published prompt-level defenses don't hold up well against adaptive attackers — bypass rates well above 90% have been reported against them. That's expected, not a failure: a defense built from the same material as the thing it's defending against will eventually be beaten by a good enough attack.

## What this demonstrates

Given the *exact same* malicious input, two architectures side by side:

| | Baseline (single agent) | Isolated (this project) |
|---|---|---|
| Reads untrusted content | ✅ | ✅ |
| Has execution rights | ✅ — same agent | ✅ — different agent |
| Ever sees raw untrusted text *and* holds execution rights | ✅ (that's the bug) | ❌ (that's the fix) |
| Result under attack | ❌ leaks secret | ✅ contained |
| Result under normal use | ✅ works fine | ✅ works identically |

The last row matters as much as the second-to-last: isolation that only "works" by breaking normal functionality isn't a fix, it's a workaround.

## Why it works

The defense is layered from **two different materials**, not one stacked three times:

- **Probabilistic layers** (an audit agent screening intent, a scan for secret patterns before anything leaves the system) — cheap, fast, and enough to stop most unsophisticated attacks. Like any AI-based filter, they can in principle be fooled.
- **A structural layer in the middle** — the agent that reads untrusted content can only emit a schema-constrained, enum-limited decision; the agent that acts never reads raw text, only that enum. Even a fully successful injection against the audit and reasoning steps can't produce an action outside a small, predefined whitelist.

Full design rationale, data contracts, and the fail-closed rules this project follows: [PROJECT_SPEC.md](./PROJECT_SPEC.md).

## Try it

```bash
git clone <this-repo>
cd injection-blast-radius
cp .env.example .env
pip install -r requirements.txt
python run_all.py
```

`run_all.py` runs all four combinations (baseline/isolated × benign/malicious input) and prints a comparison.

## Disclaimer

This is an educational sandbox, not a production security tool. All "secrets" used are obviously fake placeholders. No real GitHub API or third-party service is touched — the "issue" and "public comment" surfaces are simulated local files. Do not point any part of this at a real production system or account.

## License

MIT — see [LICENSE](./LICENSE).
