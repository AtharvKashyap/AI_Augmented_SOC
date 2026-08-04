

"""OpenRouter client for AI_Augmented_SOC.

This module provides a small OpenAI-compatible client for OpenRouter chat
completion calls. It is intentionally isolated from triage logic so tests can
mock HTTP behavior and so the rest of the SOC pipeline does not depend directly
on a specific LLM provider.

Design goals:
    - Use only Python standard library networking.
    - Keep request/response objects simple and testable.
    - Support OpenRouter headers such as HTTP-Referer and X-Title.
    - Fail clearly when the API key, response body, or HTTP status is invalid.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from soc.config import Settings

JsonDict = dict[str, Any]


class OpenRouterError(RuntimeError):
    """Raised when OpenRouter request or response handling fails."""


@dataclass(frozen=True, slots=True)
class ChatMessage:
    """One OpenAI-compatible chat message.

    Attributes:
        role: Message role such as system, user, assistant, or tool.
        content: Message text content.
    """

    role: str
    content: str

    def to_dict(self) -> JsonDict:
        """Convert the message to an API-compatible dictionary.

        Inputs:
            None.

        Outputs:
            Dictionary with role and content keys.
        """

        return {"role": self.role, "content": self.content}


@dataclass(frozen=True, slots=True)
class OpenRouterConfig:
    """Configuration for OpenRouter chat requests.

    Attributes:
        api_key: OpenRouter API key.
        base_url: OpenRouter base URL.
        model: Default chat model.
        site_url: Optional HTTP-Referer header value.
        app_name: Optional X-Title header value.
        timeout_seconds: HTTP timeout in seconds.
        max_retries: Number of retry attempts after the first request.
        retry_backoff_seconds: Base sleep between retries.
    """

    api_key: str
    base_url: str = "https://openrouter.ai/api/v1"
    model: str = "openrouter/auto"
    site_url: str | None = None
    app_name: str | None = "AI_Augmented_SOC"
    timeout_seconds: int = 60
    max_retries: int = 2
    retry_backoff_seconds: float = 1.0

    @classmethod
    def from_settings(cls, settings: Settings, *, model: str | None = None) -> OpenRouterConfig:
        """Build OpenRouterConfig from project Settings.

        Inputs:
            settings: Application settings object.
            model: Optional model override.

        Outputs:
            OpenRouterConfig instance.
        """

        return cls(
            api_key=settings.openrouter_api_key,
            base_url=settings.openrouter_base_url,
            model=model or settings.openrouter_model,
            site_url=settings.openrouter_site_url,
            app_name=settings.openrouter_app_name,
        )

    def __post_init__(self) -> None:
        """Validate OpenRouter configuration.

        Raises:
            OpenRouterError: If required configuration is invalid.
        """

        if self.api_key.strip() == "":
            raise OpenRouterError("OpenRouter API key is required")
        if self.base_url.strip() == "":
            raise OpenRouterError("OpenRouter base_url is required")
        if self.model.strip() == "":
            raise OpenRouterError("OpenRouter model is required")
        if self.timeout_seconds <= 0:
            raise OpenRouterError("timeout_seconds must be greater than zero")
        if self.max_retries < 0:
            raise OpenRouterError("max_retries cannot be negative")
        if self.retry_backoff_seconds < 0:
            raise OpenRouterError("retry_backoff_seconds cannot be negative")


@dataclass(frozen=True, slots=True)
class ChatCompletionResult:
    """Parsed OpenRouter chat completion response.

    Attributes:
        content: Assistant message content.
        model: Model name returned by the provider.
        usage: Token usage dictionary when provided.
        raw: Full raw JSON response.
    """

    content: str
    model: str | None
    usage: JsonDict
    raw: JsonDict


class OpenRouterClient:
    """Small OpenRouter chat-completion client.

    Args:
        config: OpenRouter client configuration.
        opener: Optional urllib opener-like object for tests.
    """

    def __init__(self, config: OpenRouterConfig, opener: Any | None = None) -> None:
        """Initialize the client.

        Inputs:
            config: OpenRouter client configuration.
            opener: Optional object with an open(request, timeout=...) method.

        Outputs:
            None.
        """

        self.config = config
        self._opener = opener or urllib.request.build_opener()

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        model: str | None = None,
        opener: Any | None = None,
    ) -> OpenRouterClient:
        """Build a client from project Settings.

        Inputs:
            settings: Application settings object.
            model: Optional model override.
            opener: Optional test opener.

        Outputs:
            OpenRouterClient instance.
        """

        return cls(OpenRouterConfig.from_settings(settings, model=model), opener=opener)

    def chat_completion(
        self,
        messages: list[ChatMessage] | list[JsonDict],
        *,
        model: str | None = None,
        temperature: float = 0.2,
        max_tokens: int = 800,
        response_format: JsonDict | None = None,
        extra_body: JsonDict | None = None,
    ) -> ChatCompletionResult:
        """Request one chat completion from OpenRouter.

        Inputs:
            messages: Chat messages as ChatMessage objects or dictionaries.
            model: Optional model override.
            temperature: Sampling temperature.
            max_tokens: Maximum output tokens.
            response_format: Optional OpenAI-compatible response_format object.
            extra_body: Optional extra request fields.

        Outputs:
            Parsed ChatCompletionResult.
        """

        payload = self._build_payload(
            messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format=response_format,
            extra_body=extra_body,
        )
        raw_response = self._post_json("/chat/completions", payload)
        return parse_chat_completion_response(raw_response)

    def complete_text(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        model: str | None = None,
        temperature: float = 0.2,
        max_tokens: int = 800,
    ) -> str:
        """Send a simple prompt and return assistant text.

        Inputs:
            prompt: User prompt.
            system_prompt: Optional system prompt.
            model: Optional model override.
            temperature: Sampling temperature.
            max_tokens: Maximum output tokens.

        Outputs:
            Assistant response text.
        """

        messages: list[ChatMessage] = []
        if system_prompt:
            messages.append(ChatMessage(role="system", content=system_prompt))
        messages.append(ChatMessage(role="user", content=prompt))
        return self.chat_completion(
            messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
        ).content

    def _build_payload(
        self,
        messages: list[ChatMessage] | list[JsonDict],
        *,
        model: str | None,
        temperature: float,
        max_tokens: int,
        response_format: JsonDict | None,
        extra_body: JsonDict | None,
    ) -> JsonDict:
        """Build OpenRouter request payload.

        Inputs:
            messages: Chat messages.
            model: Optional model override.
            temperature: Sampling temperature.
            max_tokens: Maximum output tokens.
            response_format: Optional response format.
            extra_body: Optional extra request fields.

        Outputs:
            JSON-serializable request payload.
        """

        if not messages:
            raise OpenRouterError("At least one chat message is required")
        if max_tokens <= 0:
            raise OpenRouterError("max_tokens must be greater than zero")
        if temperature < 0:
            raise OpenRouterError("temperature cannot be negative")

        body: JsonDict = {
            "model": model or self.config.model,
            "messages": [_message_to_dict(message) for message in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if response_format is not None:
            body["response_format"] = response_format
        if extra_body:
            body.update(extra_body)
        return body

    def _post_json(self, path: str, payload: JsonDict) -> JsonDict:
        """POST JSON to OpenRouter with retry handling.

        Inputs:
            path: API path beginning with slash.
            payload: JSON request body.

        Outputs:
            Parsed JSON response dictionary.
        """

        request = self._build_request(path, payload)
        attempts = self.config.max_retries + 1
        last_error: Exception | None = None

        for attempt in range(attempts):
            try:
                return self._send_request(request)
            except OpenRouterError as exc:
                last_error = exc
                if attempt >= attempts - 1 or not _is_retryable_error(exc):
                    break
                time.sleep(self.config.retry_backoff_seconds * (attempt + 1))

        raise OpenRouterError(f"OpenRouter request failed: {last_error}") from last_error

    def _build_request(self, path: str, payload: JsonDict) -> urllib.request.Request:
        """Build a urllib Request for OpenRouter.

        Inputs:
            path: API path beginning with slash.
            payload: JSON request body.

        Outputs:
            urllib Request object.
        """

        url = f"{self.config.base_url.rstrip('/')}/{path.lstrip('/')}"
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if self.config.site_url:
            headers["HTTP-Referer"] = self.config.site_url
        if self.config.app_name:
            headers["X-Title"] = self.config.app_name
        return urllib.request.Request(url=url, data=body, headers=headers, method="POST")

    def _send_request(self, request: urllib.request.Request) -> JsonDict:
        """Send a prepared urllib request.

        Inputs:
            request: Prepared urllib Request.

        Outputs:
            Parsed JSON response dictionary.
        """

        try:
            with self._opener.open(request, timeout=self.config.timeout_seconds) as response:
                status = getattr(response, "status", 200)
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            body = _read_error_body(exc)
            raise OpenRouterError(f"HTTP {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise OpenRouterError(f"Network error: {exc.reason}") from exc
        except TimeoutError as exc:
            raise OpenRouterError("OpenRouter request timed out") from exc

        if status < 200 or status >= 300:
            raise OpenRouterError(f"HTTP {status}: {body}")
        return _parse_json_body(body)


def parse_chat_completion_response(response: JsonDict) -> ChatCompletionResult:
    """Parse an OpenAI-compatible chat completion response.

    Inputs:
        response: Raw JSON response dictionary.

    Outputs:
        ChatCompletionResult with assistant content.

    Raises:
        OpenRouterError: If expected fields are missing or malformed.
    """

    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        raise OpenRouterError("OpenRouter response did not contain choices")

    first_choice = choices[0]
    if not isinstance(first_choice, dict):
        raise OpenRouterError("OpenRouter response choice is not an object")

    message = first_choice.get("message")
    if not isinstance(message, dict):
        raise OpenRouterError("OpenRouter response choice did not contain a message")

    content = message.get("content")
    if content is None:
        raise OpenRouterError("OpenRouter response message did not contain content")
    if not isinstance(content, str):
        raise OpenRouterError("OpenRouter response content is not text")

    usage = response.get("usage")
    if not isinstance(usage, dict):
        usage = {}

    model = response.get("model")
    if model is not None and not isinstance(model, str):
        model = str(model)

    return ChatCompletionResult(content=content, model=model, usage=usage, raw=response)


def parse_json_response_text(text: str) -> JsonDict:
    """Parse a JSON object from LLM response text.

    This helper accepts plain JSON or fenced Markdown JSON blocks.

    Inputs:
        text: Assistant response text.

    Outputs:
        Parsed JSON object.

    Raises:
        OpenRouterError: If the text does not contain a JSON object.
    """

    cleaned = _strip_markdown_json_fence(text).strip()
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise OpenRouterError(f"Could not parse JSON response: {exc}") from exc
    if not isinstance(parsed, dict):
        raise OpenRouterError("Parsed JSON response must be an object")
    return parsed


def _message_to_dict(message: ChatMessage | JsonDict) -> JsonDict:
    """Convert a message object or dictionary to a validated dictionary.

    Inputs:
        message: ChatMessage or dict.

    Outputs:
        Chat message dictionary.
    """

    if isinstance(message, ChatMessage):
        message_dict = message.to_dict()
    elif isinstance(message, dict):
        message_dict = dict(message)
    else:
        raise OpenRouterError("Chat message must be ChatMessage or dict")

    role = message_dict.get("role")
    content = message_dict.get("content")
    if not isinstance(role, str) or role.strip() == "":
        raise OpenRouterError("Chat message role is required")
    if not isinstance(content, str) or content.strip() == "":
        raise OpenRouterError("Chat message content is required")
    return {"role": role, "content": content}


def _parse_json_body(body: str) -> JsonDict:
    """Parse an HTTP response body as a JSON object.

    Inputs:
        body: Response body text.

    Outputs:
        Parsed JSON dictionary.
    """

    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as exc:
        raise OpenRouterError(f"Invalid JSON response: {exc}") from exc
    if not isinstance(parsed, dict):
        raise OpenRouterError("OpenRouter response must be a JSON object")
    return parsed


def _read_error_body(exc: urllib.error.HTTPError) -> str:
    """Read HTTPError response body safely.

    Inputs:
        exc: HTTPError raised by urllib.

    Outputs:
        Response body text or fallback error string.
    """

    try:
        body = exc.read().decode("utf-8")
    except Exception:
        body = str(exc)
    return body or str(exc)


def _is_retryable_error(exc: OpenRouterError) -> bool:
    """Return whether an OpenRouterError should be retried.

    Inputs:
        exc: OpenRouterError instance.

    Outputs:
        Boolean retry flag.
    """

    message = str(exc).lower()
    retryable_markers = (
        "http 408",
        "http 409",
        "http 425",
        "http 429",
        "http 500",
        "http 502",
        "http 503",
        "http 504",
        "network error",
        "timed out",
    )
    return any(marker in message for marker in retryable_markers)


def _strip_markdown_json_fence(text: str) -> str:
    """Strip a Markdown JSON code fence when present.

    Inputs:
        text: Raw response text.

    Outputs:
        Text without surrounding JSON fence.
    """

    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped

    lines = stripped.splitlines()
    if len(lines) >= 3 and lines[0].startswith("```") and lines[-1].strip() == "```":
        return "\n".join(lines[1:-1]).strip()
    return stripped