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
            r"\b[A-Z][A-Z0-9_]{2,}_(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)\s*=\s*\S+"
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


def audit_output(text: str) -> OutputAuditResult:
    """Scan text destined for the public surface. A finding means: do not publish."""
    findings: list[str] = []

    for name, pattern in SECRET_PATTERNS:
        if pattern.search(text):
            findings.append(f"regex:{name}")

    for token in _TOKEN_RE.findall(text):
        if shannon_entropy(token) > _ENTROPY_THRESHOLD_BITS:
            findings.append(f"entropy:{token[:8]}…({len(token)} chars)")

    # Deduplicate while preserving order, so a repeated pattern reads as one
    # finding rather than inflating the count.
    seen: set[str] = set()
    unique = tuple(f for f in findings if not (f in seen or seen.add(f)))
    return OutputAuditResult(blocked=bool(unique), findings=unique)
