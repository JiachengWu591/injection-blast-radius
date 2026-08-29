"""DeepSeek client construction and the minimal liveness check.

DeepSeek's API is OpenAI-compatible and has no dedicated SDK — this project
talks to it through the official `openai` package pointed at DeepSeek's
base_url (PROJECT_SPEC.md §7). Phase 0 only needs to prove the wire works:
key, network, SDK, model id. The schema-constrained tool_choice calls that
carry the actual pipeline arrive in Phase 2 (PROJECT_SPEC.md §3.3).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

import openai

from .config import (
    API_KEY_ENV_VAR,
    DEEPSEEK_BASE_URL,
    PIPELINE_MAX_TOKENS,
    STRUCTURED_RETRIES,
    assert_api_key_present,
)

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


# --- Structured output via forced tool call (PROJECT_SPEC.md §3.3) ---------


class StructuredOutputFailure(RuntimeError):
    """The model never produced a parseable tool call. Callers must fail closed."""


@dataclass(frozen=True)
class StructuredCall:
    """One successful forced-tool call.

    `raw_arguments` is kept alongside the parsed payload because the raw JSON
    text is the only place you can *observe* generation order — it is what
    proves `reasoning` was written before the verdict rather than merely
    appearing first in a reordered dict (PROJECT_SPEC.md §8).
    """

    raw_arguments: str
    payload: dict
    attempts: int


def call_structured_tool(
    *,
    model: str,
    system: str,
    user: str,
    tool_name: str,
    tool_description: str,
    parameters: dict,
    client: openai.OpenAI | None = None,
    max_tokens: int = PIPELINE_MAX_TOKENS,
    retries: int = STRUCTURED_RETRIES,
) -> StructuredCall:
    """Force exactly one named tool call and return its parsed arguments.

    `tool_choice` pins the model to this one function, and `strict: true` asks
    the provider to constrain generation to the schema. Neither is trusted on
    its own — the caller still validates the payload through the parsers in
    schemas.py.

    On a malformed response the error is fed back and the call is retried
    `retries` times. If it still fails, this raises; every caller turns that
    into high_risk / no_action rather than letting the request through
    (PROJECT_SPEC.md §3.3).
    """
    client = client or build_client()
    tool = {
        "type": "function",
        "function": {
            "name": tool_name,
            "description": tool_description,
            "parameters": parameters,
            "strict": True,
        },
    }
    messages: list[dict] = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]

    last_error = "no attempt was made"
    for attempt in range(1, retries + 2):
        response = client.chat.completions.create(
            model=model,
            max_tokens=max_tokens,
            messages=messages,
            tools=[tool],
            tool_choice={"type": "function", "function": {"name": tool_name}},
            # DeepSeek v4 enables thinking mode by default, and thinking mode
            # rejects a named-function tool_choice with a 400 ("Thinking mode
            # does not support this tool_choice"). Forcing the named tool is
            # the whole mechanism this project relies on (PROJECT_SPEC.md
            # §3.3), so thinking is what gives way. No loss here: the schemas
            # carry an explicit `reasoning` field, so the chain of thought is
            # produced in the response where it can be inspected and logged,
            # rather than in an opaque provider-side channel.
            extra_body={"thinking": {"type": "disabled"}},
        )
        message = response.choices[0].message

        tool_calls = message.tool_calls or []
        matching = [c for c in tool_calls if c.function.name == tool_name]
        if not matching:
            last_error = f"the model did not call {tool_name!r}"
            messages.append(message.model_dump(exclude_none=True))
            messages.append(
                {
                    "role": "user",
                    "content": f"Error: {last_error}. You must call {tool_name}.",
                }
            )
            continue

        call = matching[0]
        raw = call.function.arguments or ""
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            last_error = f"arguments were not valid JSON ({exc})"
            messages.append(message.model_dump(exclude_none=True))
            # Every tool_call in the assistant turn needs a matching tool
            # message or the next request is rejected as malformed.
            for pending in tool_calls:
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": pending.id,
                        "content": (
                            f"Error: {last_error}. Re-send the call with valid "
                            "JSON arguments, keeping every field shorter."
                        ),
                    }
                )
            continue

        return StructuredCall(raw_arguments=raw, payload=payload, attempts=attempt)

    raise StructuredOutputFailure(
        f"{tool_name}: no valid structured output after {retries + 1} attempt(s); "
        f"last error: {last_error}"
    )
