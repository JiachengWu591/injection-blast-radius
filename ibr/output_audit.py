"""Output audit — the last probabilistic layer before anything goes public.

PROJECT_SPEC.md §2: regex and entropy scanning for secret-shaped strings; a
hit blocks publication. This is cheap, it catches the obvious cases, and it is
explicitly *not* the thing the project is arguing for — it is pattern matching,
so it can be evaded by anything that doesn't look like the patterns.

In the isolated pipeline this layer should never actually fire, because the
Executor only ever publishes static templates. It is here as depth: if a future
change accidentally lets model-generated text reach the output, this catches
the loudest failure before it leaves the system.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

# Length at which a single unbroken token starts looking like a credential
# rather than a word, and the Shannon entropy (bits per character) above which
# such a token is treated as random rather than English.
_ENTROPY_MIN_TOKEN_LENGTH = 20
_ENTROPY_THRESHOLD_BITS = 3.5

_TOKEN_RE = re.compile(rf"[A-Za-z0-9+/=_-]{{{_ENTROPY_MIN_TOKEN_LENGTH},}}")

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("openai_style_key", re.compile(r"\bsk-[A-Za-z0-9_-]{8,}")),
    (
        "env_credential_assignment",
        re.compile(
            r"\b(?:[A-Z][A-Z0-9_]*_)?"
            r"(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)\s*=\s*\S+"
        ),
    ),
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{20,}")),
)


@dataclass(frozen=True)
class OutputAuditResult:
    blocked: bool
    findings: tuple[str, ...]

    @property
    def summary(self) -> str:
        return ", ".join(self.findings) if self.findings else "clean"


def shannon_entropy(text: str) -> float:
    """Bits of entropy per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


def audit_output(text: str, *, scan_entropy: bool = True) -> OutputAuditResult:
    """Scan text destined for the public surface. A finding means: do not publish.

    `scan_entropy=False` runs the regex patterns only, skipping the entropy
    heuristic — a real trade-off, not a free precision improvement, and not
    something to reach for just because a string happens to be attacker-
    influenced. `ibr/executor.py` uses it for `issue_id`, which *is*
    attacker-shaped free text (`ibr/issues.py`'s own docstring says so): the
    entropy heuristic's "any 20+-character token with high enough per-
    character entropy is suspicious" rule cannot reliably distinguish an
    ordinary hyphenated identifier from a random secret of similar length —
    their distributions genuinely overlap, not just at the edges. Measured
    directly, one concrete pair rather than an abstract claim:
    `JEEoQEpeIEJKMxIp2a2J`, a genuinely random 20-character secret, comes
    back at 3.38 bits/char; `PROJ-1234-fix-the-login-bug`, an entirely
    ordinary issue-tracker slug, comes back at 4.18 — *higher* than the real
    secret. Any threshold that lets the slug through also lets that secret
    through; any threshold that catches the secret also blocks the slug.
    That is not cherry-picked: sampling several thousand random 20-32
    character secrets against a handful of ordinary slugs the same way
    consistently produces overlap of this kind, not a rare coincidence.
    Given that, running the entropy scan on `issue_id` would routinely block
    entirely ordinary long ids (over-blocking, an availability cost) without
    reliably catching a genuinely random one anyway (under-detecting, the
    actual risk) — neither side of that trade is a win.

    So `scan_entropy=False` for `issue_id` is a disclosed, partial defence,
    not a complete one: it catches an id shaped like one of the regex
    patterns above (an AWS-style key id, an `sk-`-prefixed token, and so on),
    which is a real, verified improvement over auditing `issue_id` not at
    all. It does **not** catch an arbitrary high-entropy id that matches none
    of those shapes, and nothing else in this project catches it either —
    `Issue.__post_init__`'s charset restriction (`[A-Za-z0-9._-]{1,64}`)
    constrains which characters may appear and how long the id may be, not
    how random it is, so a purely random id built entirely from that
    charset (a hex token, a base64url token, a JWT — all realistic secret
    shapes) satisfies it trivially. There is no backstop for that residual
    case; it is accepted, not covered, exactly like this module's own
    opening lines already say about the whole approach: pattern matching
    "can be evaded by anything that doesn't look like the patterns." This is
    that limitation, stated for one specific caller rather than left
    implicit — not a claim that something else quietly catches what this
    scan does not.
    """
    findings: list[str] = []

    for name, pattern in SECRET_PATTERNS:
        if pattern.search(text):
            findings.append(f"regex:{name}")

    if scan_entropy:
        for token in _TOKEN_RE.findall(text):
            if shannon_entropy(token) > _ENTROPY_THRESHOLD_BITS:
                findings.append(f"entropy:{token[:8]}…({len(token)} chars)")

    # Deduplicate while preserving order, so a repeated pattern reads as one
    # finding rather than inflating the count. dict.fromkeys rather than the
    # `f in seen or seen.add(f)` idiom: that version relies on set.add
    # returning None to be falsy, which is true but not worth making a reader
    # verify.
    unique = tuple(dict.fromkeys(findings))
    return OutputAuditResult(blocked=bool(unique), findings=unique)
