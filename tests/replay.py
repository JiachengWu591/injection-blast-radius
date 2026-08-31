"""Record real API exchanges once, replay them in CI forever.

The offline suite covers the structural boundary completely and the
API-calling paths barely at all: `ibr/llm.py`'s retry loop, `ibr/pipeline.py`'s
four stages, and `ibr/baseline_agent.py`'s multi-turn tool loop sat at roughly
40% because reaching them costs money and a key. Those are also the three
modules where the last several real bugs lived — a malformed retry request, a
`.function` read on an SDK union, a fail-closed default counted as a detection.
Being uncovered and being buggy were the same fact.

A cassette is a recorded list of (request fingerprint, response body) pairs.
`record_cassettes.py` writes them with a real key; the tests replay them with
no network at all.

**Fingerprints are checked, not just order.** Replaying purely in sequence
would let a prompt edit sail through against stale recordings, which is the
failure mode that makes recorded tests worse than none: they keep passing while
testing something that no longer exists. A mismatch fails with instructions to
re-record. That means editing a prompt costs a re-record, which is the correct
price — a changed prompt is a changed experiment.

The fingerprint deliberately excludes nothing that affects the model's answer
(model id, messages, tool name) and includes nothing that doesn't (timeouts,
client identity), so it fails on real drift and not on incidental churn.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

CASSETTE_DIR = Path(__file__).resolve().parent / "cassettes"


class CassetteMismatch(AssertionError):
    """The request differs from what was recorded. Re-record, do not loosen."""


def fingerprint(kwargs: dict[str, Any]) -> str:
    """A stable digest of everything about a request that changes the answer.

    Model, the full message list, the forced tool name, and the tool schema.
    Not the timeout, not max_tokens, not the client — those can drift without
    invalidating a recording, and folding them in would force needless
    re-records.
    """
    tools = kwargs.get("tools") or []
    tool_choice = kwargs.get("tool_choice") or {}
    salient = {
        "model": kwargs.get("model"),
        "messages": kwargs.get("messages"),
        "tool_names": sorted(
            t.get("function", {}).get("name", "") for t in tools if isinstance(t, dict)
        ),
        "forced_tool": (
            tool_choice.get("function", {}).get("name")
            if isinstance(tool_choice, dict)
            else None
        ),
    }
    blob = json.dumps(salient, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


# --- Replaying -------------------------------------------------------------


class _Fn:
    def __init__(self, data: dict) -> None:
        self.name: str = data["name"]
        self.arguments: str = data["arguments"]


class _ToolCall:
    def __init__(self, data: dict) -> None:
        self.id: str = data["id"]
        self.type: str = data.get("type", "function")
        self.function = _Fn(data["function"]) if "function" in data else None


class _Message:
    def __init__(self, data: dict) -> None:
        self.content: str | None = data.get("content")
        raw_calls = data.get("tool_calls") or []
        self.tool_calls: list[_ToolCall] | None = (
            [_ToolCall(c) for c in raw_calls] if raw_calls else None
        )
        self._model_dump: dict = data.get("model_dump") or {"role": "assistant"}

    def model_dump(self, **_kwargs: object) -> dict:
        """Return exactly what the real SDK returned when this was recorded.

        The multi-turn loops append `model_dump()` back into the conversation,
        so reconstructing an approximation here makes the replayed history
        diverge from the recorded one on the second call — which is not a
        detail, it means the code under test is being driven with a different
        conversation than the responses were recorded against. The
        fingerprint check caught exactly that on the first attempt at this
        file; storing the real output is the fix.
        """
        return json.loads(json.dumps(self._model_dump))


class _Choice:
    def __init__(self, data: dict) -> None:
        self.message = _Message(data.get("message", {}))


class _Usage:
    def __init__(self, data: dict) -> None:
        self.prompt_tokens: int = data.get("prompt_tokens", 0)
        self.completion_tokens: int = data.get("completion_tokens", 0)


class _Response:
    def __init__(self, data: dict) -> None:
        self.model: str = data.get("model", "recorded")
        self.choices = [_Choice(c) for c in data.get("choices", [{}])]
        usage = data.get("usage")
        self.usage = _Usage(usage) if usage is not None else None


class ReplayClient:
    """Stands in for `openai.OpenAI`, serving recorded responses in order."""

    def __init__(self, interactions: list[dict], *, name: str) -> None:
        self._interactions = interactions
        self._name = name
        self.index = 0
        self.chat = _Chat(self)

    def _next(self, kwargs: dict[str, Any]) -> _Response:
        if self.index >= len(self._interactions):
            raise CassetteMismatch(
                f"cassette {self._name!r} has {len(self._interactions)} "
                f"interaction(s) but the code asked for one more. The code now "
                "makes more calls than were recorded — re-record with "
                "`python tests/record_cassettes.py`."
            )
        interaction = self._interactions[self.index]
        self.index += 1

        actual = fingerprint(kwargs)
        expected = interaction["fingerprint"]
        if actual != expected:
            raise CassetteMismatch(
                f"cassette {self._name!r} interaction {self.index}: request "
                f"fingerprint {actual} does not match recorded {expected}. "
                "A prompt, model id, or tool definition changed, so the "
                "recording no longer describes this experiment. Re-record with "
                "`python tests/record_cassettes.py` rather than relaxing this "
                "check — a recorded test that passes against a stale recording "
                "is worse than no test."
            )
        return _Response(interaction["response"])

    def assert_fully_consumed(self) -> None:
        remaining = len(self._interactions) - self.index
        if remaining:
            raise CassetteMismatch(
                f"cassette {self._name!r} has {remaining} unused interaction(s): "
                "the code made fewer calls than were recorded. Either a code "
                "path was lost or the recording is stale."
            )


class _Completions:
    def __init__(self, client: ReplayClient) -> None:
        self._client = client

    def create(self, **kwargs: Any) -> _Response:
        return self._client._next(kwargs)


class _Chat:
    def __init__(self, client: ReplayClient) -> None:
        self.completions = _Completions(client)


def load(name: str) -> ReplayClient:
    path = CASSETTE_DIR / f"{name}.json"
    if not path.is_file():
        raise AssertionError(
            f"missing cassette {path}. Record it with "
            "`python tests/record_cassettes.py`."
        )
    data = json.loads(path.read_text(encoding="utf-8"))
    return ReplayClient(data["interactions"], name=name)


def available() -> list[str]:
    if not CASSETTE_DIR.is_dir():
        return []
    return sorted(p.stem for p in CASSETTE_DIR.glob("*.json"))


# --- Recording -------------------------------------------------------------


class RecordingClient:
    """Wraps a real client, capturing every exchange for later replay."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.interactions: list[dict] = []
        self.chat = _RecordingChat(self)

    def _call(self, kwargs: dict[str, Any]) -> Any:
        response = self._inner.chat.completions.create(**kwargs)
        self.interactions.append(
            {
                "fingerprint": fingerprint(kwargs),
                "response": _serialise(response),
            }
        )
        return response


class _RecordingCompletions:
    def __init__(self, client: RecordingClient) -> None:
        self._client = client

    def create(self, **kwargs: Any) -> Any:
        return self._client._call(kwargs)


class _RecordingChat:
    def __init__(self, client: RecordingClient) -> None:
        self.completions = _RecordingCompletions(client)


def _serialise(response: Any) -> dict:
    """Keep only the fields this project reads, so cassettes stay reviewable."""
    choices = []
    for choice in response.choices:
        message = choice.message
        calls = []
        for call in message.tool_calls or []:
            entry: dict[str, Any] = {"id": call.id, "type": getattr(call, "type", "function")}
            function = getattr(call, "function", None)
            if function is not None:
                entry["function"] = {
                    "name": function.name,
                    "arguments": function.arguments,
                }
            calls.append(entry)
        choices.append(
            {
                "message": {
                    "content": message.content,
                    "tool_calls": calls,
                    # Stored verbatim: the multi-turn loops feed this back into
                    # the conversation, so replay has to reproduce it exactly
                    # or the history diverges from what was recorded.
                    "model_dump": message.model_dump(exclude_none=True),
                }
            }
        )
    usage = getattr(response, "usage", None)
    return {
        "model": response.model,
        "choices": choices,
        "usage": (
            {
                "prompt_tokens": usage.prompt_tokens,
                "completion_tokens": usage.completion_tokens,
            }
            if usage is not None
            else None
        ),
    }


def save(name: str, client: RecordingClient) -> Path:
    CASSETTE_DIR.mkdir(parents=True, exist_ok=True)
    path = CASSETTE_DIR / f"{name}.json"
    path.write_text(
        json.dumps({"interactions": client.interactions}, indent=2, ensure_ascii=False)
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return path
