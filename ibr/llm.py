"""DeepSeek client construction and the minimal liveness check.

DeepSeek's API is OpenAI-compatible and has no dedicated SDK — this project
talks to it through the official `openai` package pointed at DeepSeek's
base_url (PROJECT_SPEC.md §7). Phase 0 only needs to prove the wire works:
key, network, SDK, model id. The schema-constrained tool_choice calls that
carry the actual pipeline arrive in Phase 2 (PROJECT_SPEC.md §3.3).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import openai

from .config import DEEPSEEK_BASE_URL, API_KEY_ENV_VAR, assert_api_key_present

# Short by design: a hung request must fail the run, not stall it. Fail-closed
# applies to timeouts too (PROJECT_SPEC.md §1.4). 60s (not 30s) because
# multi-turn tool-calling loops against the "pro" tier model occasionally run
# past 30s per turn — observed timing out during Phase 1 experimentation.
DEFAULT_TIMEOUT_SECONDS = 60.0
DEFAULT_MAX_RETRIES = 2


@dataclass(frozen=True)
class PingResult:
    model: str
    text: str
    input_tokens: int
    output_tokens: int


def build_client(
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_retries: int = DEFAULT_MAX_RETRIES,
) -> openai.OpenAI:
    """Construct the SDK client, pointed at DeepSeek instead of OpenAI.

    Unlike Anthropic's SDK, `openai.OpenAI()` only auto-discovers
    `OPENAI_API_KEY` — it has no notion of a `DEEPSEEK_API_KEY` env var, so the
    key has to be read here and handed to the constructor explicitly. It is
    still never logged, printed, or passed through any other part of this
    project's code.
    """
    assert_api_key_present()
    return openai.OpenAI(
        api_key=os.environ[API_KEY_ENV_VAR],
        base_url=DEEPSEEK_BASE_URL,
        timeout=timeout,
        max_retries=max_retries,
    )


def ping(model: str, *, client: openai.OpenAI | None = None) -> PingResult:
    """Smallest possible live call, used by the Phase 0 smoke test."""
    client = client or build_client()
    response = client.chat.completions.create(
        model=model,
        max_tokens=64,
        messages=[
            {
                "role": "user",
                "content": "Reply with exactly: pipeline online",
            }
        ],
    )
    return PingResult(
        model=response.model,
        text=(response.choices[0].message.content or "").strip(),
        input_tokens=response.usage.prompt_tokens,
        output_tokens=response.usage.completion_tokens,
    )
