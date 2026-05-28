from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol

from .config import Settings


class LLMError(RuntimeError):
    pass


@dataclass(frozen=True)
class LLMCompletion:
    text: str
    model: str
    provider: str


class LLMProvider(Protocol):
    @property
    def is_available(self) -> bool:
        ...

    @property
    def provider_name(self) -> str:
        ...

    def complete(self, *, system: str, prompt: str, max_tokens: int = 2048) -> LLMCompletion:
        ...


class DisabledLLMProvider:
    @property
    def is_available(self) -> bool:
        return False

    @property
    def provider_name(self) -> str:
        return "disabled"

    def complete(self, *, system: str, prompt: str, max_tokens: int = 2048) -> LLMCompletion:
        raise LLMError("No LLM provider is configured")


class AnthropicLLMProvider:
    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        timeout_seconds: int,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._timeout_seconds = timeout_seconds

    @property
    def is_available(self) -> bool:
        return bool(self._api_key)

    @property
    def provider_name(self) -> str:
        return "anthropic"

    def complete(self, *, system: str, prompt: str, max_tokens: int = 2048) -> LLMCompletion:
        if not self._api_key:
            raise LLMError("ANTHROPIC_API_KEY is not configured")
        body = {
            "model": self._model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
        }
        request = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "anthropic-version": "2023-06-01",
                "x-api-key": self._api_key,
                "content-type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_seconds) as response:  # noqa: S310
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise LLMError(f"Anthropic request failed: HTTP {exc.code}: {detail}") from exc
        except OSError as exc:
            raise LLMError(f"Anthropic request failed: {exc}") from exc

        text_parts = [
            str(item.get("text", ""))
            for item in payload.get("content", [])
            if item.get("type") == "text"
        ]
        text = "\n".join(part for part in text_parts if part).strip()
        if not text:
            raise LLMError("Anthropic response did not include text content")
        return LLMCompletion(text=text, model=self._model, provider=self.provider_name)


class OpenRouterLLMProvider:
    def __init__(
        self,
        *,
        api_key: str,
        model: str = "openai/gpt-4o-mini",
        timeout_seconds: int,
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._timeout_seconds = timeout_seconds

    @property
    def is_available(self) -> bool:
        return bool(self._api_key)

    @property
    def provider_name(self) -> str:
        return "openrouter"

    def complete(self, *, system: str, prompt: str, max_tokens: int = 2048) -> LLMCompletion:
        if not self._api_key:
            raise LLMError("OPENROUTER_API_KEY is not configured")
        
        body = {
            "model": self._model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt}
            ],
        }
        
        request = urllib.request.Request(
            "https://openrouter.ai/api/v1/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_seconds) as response:  # noqa: S310
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise LLMError(f"OpenRouter request failed: HTTP {exc.code}: {detail}") from exc
        except OSError as exc:
            raise LLMError(f"OpenRouter request failed: {exc}") from exc

        try:
            text = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            raise LLMError("OpenRouter response did not include valid content") from exc
            
        return LLMCompletion(text=text.strip(), model=self._model, provider=self.provider_name)


def build_llm_provider(settings: Settings) -> LLMProvider:
    or_api_key = os.getenv("OPENROUTER_API_KEY", "")
    if or_api_key:
        return OpenRouterLLMProvider(
            api_key=or_api_key,
            timeout_seconds=settings.llm_timeout_seconds,
        )

    api_key = settings.anthropic_api_key or os.getenv("ANTHROPIC_API_KEY", "")
    if api_key:
        return AnthropicLLMProvider(
            api_key=api_key,
            model=settings.anthropic_model,
            timeout_seconds=settings.llm_timeout_seconds,
        )
    return DisabledLLMProvider()


def extract_json_object(text: str) -> dict:
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    candidate = fenced.group(1) if fenced else text
    first = candidate.find("{")
    last = candidate.rfind("}")
    if first == -1 or last == -1 or last <= first:
        raise LLMError("LLM response did not contain a JSON object")
    try:
        return json.loads(candidate[first : last + 1])
    except json.JSONDecodeError as exc:
        raise LLMError(f"LLM response JSON was invalid: {exc}") from exc
