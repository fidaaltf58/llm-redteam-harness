"""Adapters are tested against fake HTTP servers (httpx.MockTransport): no network, no keys."""

import json

import httpx
import pytest

from redteam.models import Message, ToolCall, ToolSpec
from redteam.targets import OllamaTarget, OpenAICompatTarget, TargetError, create_target

TOOL = ToolSpec(name="send_email", description="d", parameters={"type": "object"})


def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_ollama_parses_text_and_tool_calls():
    seen = {}

    def handler(request):
        seen.update(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "model": "llama3.1:8b",
                "message": {
                    "role": "assistant",
                    "content": "hi",
                    "tool_calls": [
                        {"function": {"name": "send_email", "arguments": {"to": "a@b.c"}}}
                    ],
                },
            },
        )

    t = OllamaTarget(client=_client(handler), temperature=0.3)
    resp = t.send([Message(role="user", content="x")], tools=[TOOL])
    assert resp.text == "hi"
    assert resp.tool_calls == [ToolCall(name="send_email", arguments={"to": "a@b.c"})]
    assert seen["options"]["temperature"] == 0.3 and seen["stream"] is False
    assert seen["tools"][0]["function"]["name"] == "send_email"


def test_ollama_missing_model_gives_helpful_error():
    t = OllamaTarget(model="nope", client=_client(lambda r: httpx.Response(404, text="not found")))
    with pytest.raises(TargetError, match="ollama pull nope"):
        t.send([Message(role="user", content="x")])


def test_ollama_connection_error_is_wrapped():
    def handler(request):
        raise httpx.ConnectError("refused")

    with pytest.raises(TargetError, match="ollama serve"):
        OllamaTarget(client=_client(handler)).send([Message(role="user", content="x")])


def test_openai_compat_parses_string_arguments_and_sends_tool_ids():
    seen = {}

    def handler(request):
        seen.update(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "model": "m",
                "choices": [
                    {
                        "message": {
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call_9",
                                    "type": "function",
                                    "function": {
                                        "name": "send_email",
                                        "arguments": '{"to": "x@y.z"}',
                                    },
                                }
                            ],
                        }
                    }
                ],
            },
        )

    t = OpenAICompatTarget(model="m", client=_client(handler))
    history = [
        Message(role="user", content="go"),
        Message(role="assistant", tool_calls=[ToolCall(id="call_1", name="send_email")]),
        Message(role="tool", content="{}", tool_call_id="call_1"),
    ]
    resp = t.send(history, tools=[TOOL])
    assert resp.tool_calls[0].arguments == {"to": "x@y.z"} and resp.text == ""
    assert seen["messages"][1]["tool_calls"][0]["function"]["arguments"] == "{}"
    assert seen["messages"][2]["tool_call_id"] == "call_1"


def test_openai_requires_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(TargetError, match="OPENAI_API_KEY"):
        OpenAICompatTarget(model="m")


def test_registry_rejects_unknown_target_and_filters_kwargs():
    with pytest.raises(TargetError):
        create_target("nope", model="x")
    t = create_target("mock", model="naive-v1", host="ignored", base_url="ignored")
    assert t.kind == "mock"
