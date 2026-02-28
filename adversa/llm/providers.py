from __future__ import annotations

import os

from langchain.chat_models import init_chat_model

from adversa.config.models import ProviderConfig
from adversa.llm.errors import LLMErrorKind, LLMProviderError


class ProviderClient:
    def __init__(self, config: ProviderConfig):
        self.config = config

    def resolve_api_key(self) -> str:
        key = os.getenv(self.config.api_key_env)
        if not key:
            raise LLMProviderError(f"Missing env var: {self.config.api_key_env}", LLMErrorKind.CONFIG_REQUIRED)
        if key.startswith("expired"):
            raise LLMProviderError("Provider credits or key expired", LLMErrorKind.CONFIG_REQUIRED)
        return key

    def health_check(self) -> None:
        self.resolve_api_key()
        if self.config.provider == "openai_compatible" and not self.config.base_url:
            raise LLMProviderError("OpenAI-compatible provider requires base_url", LLMErrorKind.FATAL)

    def build_chat_model(self, *, temperature: float = 0) -> object:
        api_key = self.resolve_api_key()
        if self.config.provider == "anthropic":
            return init_chat_model(
                self.config.model,
                api_key=api_key,
                temperature=temperature,
            )
        if self.config.provider in {"openai_compatible", "router"}:
            kwargs = {
                "model": self.config.model,
                "model_provider": "openai",
                "api_key": api_key,
                "temperature": temperature,
            }
            if self.config.base_url:
                kwargs["base_url"] = self.config.base_url
            elif self.config.provider == "openai_compatible":
                raise LLMProviderError("OpenAI-compatible provider requires base_url", LLMErrorKind.FATAL)
            return init_chat_model(**kwargs)
        raise LLMProviderError(f"Unsupported provider: {self.config.provider}", LLMErrorKind.FATAL)

    def complete(self, prompt: str) -> str:
        self.health_check()
        lowered = prompt.lower()
        if "simulate_429" in lowered or "simulate_timeout" in lowered:
            raise LLMProviderError("Transient provider failure", LLMErrorKind.TRANSIENT)
        if "simulate_401" in lowered or "simulate_credits" in lowered:
            raise LLMProviderError("Provider credits or key expired", LLMErrorKind.CONFIG_REQUIRED)
        if "simulate_bad_request" in lowered:
            raise LLMProviderError("Bad request", LLMErrorKind.FATAL)
        return f"{self.config.provider}:{self.config.model}:stub-response"
