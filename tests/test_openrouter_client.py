

"""Tests for the OpenRouter client wrapper.

These tests verify request construction, response parsing, validation, and retry
behavior without making real network calls.
"""

from __future__ import annotations

import io
import json
import urllib.error
from dataclasses import dataclass
from typing import Any

import pytest

from soc.openrouter_client import (
    ChatCompletionResult,
    ChatMessage,
    OpenRouterClient,
    OpenRouterConfig,
    OpenRouterError,
    parse_chat_completion_response,
    parse_json_response_text,
)


class FakeResponse:
    """Small context-manager response object for urllib-style tests."""

    def __init__(self, payload: dict[str, Any] | str, *, status: int = 200) -> None:
        """Initialize fake response.

        Inputs:
            payload: JSON-serializable object or raw text body.
            status: HTTP status code.

        Outputs:
            None.
        """

        self.status = status
        self.payload = payload

    def __enter__(self) -> FakeResponse:
        """Enter context manager.

        Inputs:
            None.

        Outputs:
            Self.
        """

        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        """Exit context manager.

        Inputs:
            exc_type: Exception type.
            exc: Exception instance.
            traceback: Traceback object.

        Outputs:
            None.
        """

        return None

    def read(self) -> bytes:
        """Return fake response body bytes.

        Inputs:
            None.

        Outputs:
            Response body as bytes.
        """

        if isinstance(self.payload, str):
            return self.payload.encode("utf-8")
        return json.dumps(self.payload).encode("utf-8")


class FakeOpener:
    """Fake urllib opener that records requests and returns queued responses."""

    def __init__(self, responses: list[Any]) -> None:
        """Initialize fake opener.

        Inputs:
            responses: Responses or exceptions to return from open().

        Outputs:
            None.
        """

        self.responses = responses
        self.requests = []
        self.timeouts = []

    def open(self, request, timeout: int):
        """Return or raise the next queued response.

        Inputs:
            request: urllib Request object.
            timeout: Request timeout.

        Outputs:
            FakeResponse when queued.
        """

        self.requests.append(request)
        self.timeouts.append(timeout)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


@dataclass(slots=True)
class FakeSettings:
    """Minimal settings object for from_settings tests."""

    openrouter_api_key: str = "test-key"
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    openrouter_model: str = "meta-llama/test-free"
    openrouter_site_url: str = "https://example.com"
    openrouter_app_name: str = "AI_Augmented_SOC"


def _config(**overrides) -> OpenRouterConfig:
    """Create a default OpenRouterConfig for tests.

    Inputs:
        overrides: Field overrides.

    Outputs:
        OpenRouterConfig object.
    """

    values = {
        "api_key": "test-key",
        "base_url": "https://openrouter.ai/api/v1",
        "model": "meta-llama/test-free",
        "site_url": "https://example.com",
        "app_name": "AI_Augmented_SOC",
        "timeout_seconds": 5,
        "max_retries": 0,
        "retry_backoff_seconds": 0,
    }
    values.update(overrides)
    return OpenRouterConfig(**values)


def _success_payload(content: str = "hello") -> dict[str, Any]:
    """Create a successful OpenAI-compatible chat completion payload.

    Inputs:
        content: Assistant message content.

    Outputs:
        Response payload dictionary.
    """

    return {
        "id": "chatcmpl-test",
        "model": "meta-llama/test-free",
        "choices": [{"message": {"role": "assistant", "content": content}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


def test_chat_message_to_dict():
    """ChatMessage should convert to OpenAI-compatible dictionary."""

    assert ChatMessage(role="user", content="hello").to_dict() == {
        "role": "user",
        "content": "hello",
    }


def test_openrouter_config_validates_required_values():
    """OpenRouterConfig should reject invalid required settings."""

    with pytest.raises(OpenRouterError, match="API key"):
        _config(api_key="")

    with pytest.raises(OpenRouterError, match="base_url"):
        _config(base_url="")

    with pytest.raises(OpenRouterError, match="model"):
        _config(model="")

    with pytest.raises(OpenRouterError, match="timeout_seconds"):
        _config(timeout_seconds=0)

    with pytest.raises(OpenRouterError, match="max_retries"):
        _config(max_retries=-1)

    with pytest.raises(OpenRouterError, match="retry_backoff_seconds"):
        _config(retry_backoff_seconds=-1)


def test_openrouter_config_from_settings_uses_settings_values():
    """from_settings should copy OpenRouter values from Settings-like object."""

    config = OpenRouterConfig.from_settings(FakeSettings(), model="override-model")

    assert config.api_key == "test-key"
    assert config.base_url == "https://openrouter.ai/api/v1"
    assert config.model == "override-model"
    assert config.site_url == "https://example.com"
    assert config.app_name == "AI_Augmented_SOC"


def test_chat_completion_sends_expected_request_and_parses_response():
    """chat_completion should send expected JSON and parse assistant content."""

    opener = FakeOpener([FakeResponse(_success_payload("triage complete"))])
    client = OpenRouterClient(_config(), opener=opener)

    result = client.chat_completion(
        [ChatMessage(role="user", content="Analyze this alert")],
        temperature=0.1,
        max_tokens=200,
    )

    assert isinstance(result, ChatCompletionResult)
    assert result.content == "triage complete"
    assert result.model == "meta-llama/test-free"
    assert result.usage["total_tokens"] == 15
    assert len(opener.requests) == 1
    assert opener.timeouts == [5]

    request = opener.requests[0]
    assert request.full_url == "https://openrouter.ai/api/v1/chat/completions"
    assert request.get_method() == "POST"
    assert request.headers["Authorization"] == "Bearer test-key"
    assert request.headers["Content-type"] == "application/json"
    assert request.headers["Accept"] == "application/json"
    assert request.headers["Http-referer"] == "https://example.com"
    assert request.headers["X-title"] == "AI_Augmented_SOC"

    body = json.loads(request.data.decode("utf-8"))
    assert body["model"] == "meta-llama/test-free"
    assert body["messages"] == [{"role": "user", "content": "Analyze this alert"}]
    assert body["temperature"] == 0.1
    assert body["max_tokens"] == 200


def test_chat_completion_accepts_dict_messages_and_extra_body():
    """chat_completion should accept dict messages and merge extra body fields."""

    opener = FakeOpener([FakeResponse(_success_payload())])
    client = OpenRouterClient(_config(), opener=opener)

    client.chat_completion(
        [{"role": "user", "content": "Return JSON"}],
        model="override-model",
        response_format={"type": "json_object"},
        extra_body={"top_p": 0.9},
    )

    body = json.loads(opener.requests[0].data.decode("utf-8"))
    assert body["model"] == "override-model"
    assert body["response_format"] == {"type": "json_object"}
    assert body["top_p"] == 0.9


def test_complete_text_wraps_prompt_messages():
    """complete_text should build system/user messages and return content."""

    opener = FakeOpener([FakeResponse(_success_payload("done"))])
    client = OpenRouterClient(_config(), opener=opener)

    text = client.complete_text("Analyze alert", system_prompt="You are a SOC analyst")

    assert text == "done"
    body = json.loads(opener.requests[0].data.decode("utf-8"))
    assert body["messages"] == [
        {"role": "system", "content": "You are a SOC analyst"},
        {"role": "user", "content": "Analyze alert"},
    ]


def test_chat_completion_validates_messages_and_parameters():
    """chat_completion should reject invalid messages and parameters."""

    client = OpenRouterClient(_config(), opener=FakeOpener([]))

    with pytest.raises(OpenRouterError, match="At least one"):
        client.chat_completion([])

    with pytest.raises(OpenRouterError, match="max_tokens"):
        client.chat_completion([ChatMessage(role="user", content="x")], max_tokens=0)

    with pytest.raises(OpenRouterError, match="temperature"):
        client.chat_completion([ChatMessage(role="user", content="x")], temperature=-0.1)

    with pytest.raises(OpenRouterError, match="role"):
        client.chat_completion([{"role": "", "content": "x"}])

    with pytest.raises(OpenRouterError, match="content"):
        client.chat_completion([{"role": "user", "content": ""}])


def test_parse_chat_completion_response_success():
    """parse_chat_completion_response should parse a valid response."""

    result = parse_chat_completion_response(_success_payload("hello analyst"))

    assert result.content == "hello analyst"
    assert result.model == "meta-llama/test-free"
    assert result.usage["prompt_tokens"] == 10


def test_parse_chat_completion_response_rejects_bad_shapes():
    """parse_chat_completion_response should reject malformed responses."""

    with pytest.raises(OpenRouterError, match="choices"):
        parse_chat_completion_response({})

    with pytest.raises(OpenRouterError, match="choice"):
        parse_chat_completion_response({"choices": ["bad"]})

    with pytest.raises(OpenRouterError, match="message"):
        parse_chat_completion_response({"choices": [{}]})

    with pytest.raises(OpenRouterError, match="content"):
        parse_chat_completion_response({"choices": [{"message": {}}]})

    with pytest.raises(OpenRouterError, match="content"):
        parse_chat_completion_response({"choices": [{"message": {"content": {}}}]})


def test_parse_json_response_text_accepts_plain_and_fenced_json():
    """parse_json_response_text should parse plain or fenced JSON objects."""

    assert parse_json_response_text('{"score": 8}') == {"score": 8}
    assert parse_json_response_text('```json\n{"score": 7}\n```') == {"score": 7}


def test_parse_json_response_text_rejects_invalid_or_non_object_json():
    """parse_json_response_text should reject invalid or non-object JSON."""

    with pytest.raises(OpenRouterError, match="Could not parse JSON"):
        parse_json_response_text("not json")

    with pytest.raises(OpenRouterError, match="must be an object"):
        parse_json_response_text('[{"score": 8}]')


def test_http_status_error_raises_openrouter_error():
    """Non-2xx HTTP status should raise OpenRouterError."""

    opener = FakeOpener([FakeResponse({"error": "bad request"}, status=400)])
    client = OpenRouterClient(_config(), opener=opener)

    with pytest.raises(OpenRouterError, match="HTTP 400"):
        client.chat_completion([ChatMessage(role="user", content="x")])


def test_invalid_json_http_response_raises_openrouter_error():
    """Invalid JSON HTTP body should raise OpenRouterError."""

    opener = FakeOpener([FakeResponse("not json")])
    client = OpenRouterClient(_config(), opener=opener)

    with pytest.raises(OpenRouterError, match="Invalid JSON response"):
        client.chat_completion([ChatMessage(role="user", content="x")])


def test_http_error_exception_body_is_included():
    """HTTPError exceptions should include response body in OpenRouterError."""

    http_error = urllib.error.HTTPError(
        url="https://openrouter.ai/api/v1/chat/completions",
        code=401,
        msg="Unauthorized",
        hdrs=None,
        fp=io.BytesIO(b'{"error":"unauthorized"}'),
    )
    opener = FakeOpener([http_error])
    client = OpenRouterClient(_config(), opener=opener)

    with pytest.raises(OpenRouterError, match="HTTP 401"):
        client.chat_completion([ChatMessage(role="user", content="x")])


def test_retryable_error_is_retried_then_succeeds(monkeypatch):
    """Retryable errors should be retried up to configured attempts."""

    sleeps: list[float] = []
    monkeypatch.setattr("soc.openrouter_client.time.sleep", sleeps.append)

    opener = FakeOpener([
        FakeResponse({"error": "temporary"}, status=503),
        FakeResponse(_success_payload("recovered")),
    ])
    client = OpenRouterClient(_config(max_retries=1, retry_backoff_seconds=0.5), opener=opener)

    result = client.chat_completion([ChatMessage(role="user", content="x")])

    assert result.content == "recovered"
    assert len(opener.requests) == 2
    assert sleeps == [0.5]


def test_non_retryable_error_is_not_retried():
    """Non-retryable errors should fail immediately."""

    opener = FakeOpener([
        FakeResponse({"error": "bad request"}, status=400),
        FakeResponse(_success_payload("should not run")),
    ])
    client = OpenRouterClient(_config(max_retries=2), opener=opener)

    with pytest.raises(OpenRouterError, match="HTTP 400"):
        client.chat_completion([ChatMessage(role="user", content="x")])

    assert len(opener.requests) == 1