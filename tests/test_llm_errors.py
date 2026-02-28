from __future__ import annotations

import pytest

from adversa.config.models import ProviderConfig
from adversa.llm.errors import LLMErrorKind, LLMProviderError
from adversa.llm.providers import ProviderClient
from adversa.workflow_temporal.activities import classify_provider_error


def test_openai_compatible_requires_base_url() -> None:
    with pytest.raises(ValueError, match="requires base_url"):
        ProviderConfig(provider="openai_compatible", model="gpt-4o-mini", api_key_env="OPENAI_API_KEY")


def test_missing_env_var_is_config_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    client = ProviderClient(ProviderConfig())

    with pytest.raises(LLMProviderError) as exc_info:
        client.health_check()

    assert exc_info.value.kind == LLMErrorKind.CONFIG_REQUIRED
    assert "ANTHROPIC_API_KEY" in str(exc_info.value)


def test_expired_credits_classified_as_config_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "expired-token")
    client = ProviderClient(ProviderConfig())

    with pytest.raises(LLMProviderError) as exc_info:
        client.health_check()

    assert exc_info.value.kind == LLMErrorKind.CONFIG_REQUIRED


def test_transient_provider_failures_are_classified_as_retryable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "valid-token")
    client = ProviderClient(ProviderConfig())

    with pytest.raises(LLMProviderError) as exc_info:
        client.complete("simulate_429")

    assert exc_info.value.kind == LLMErrorKind.TRANSIENT
    assert classify_provider_error(exc_info.value).kind == LLMErrorKind.TRANSIENT


def test_bad_request_is_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "valid-token")
    client = ProviderClient(ProviderConfig())

    with pytest.raises(LLMProviderError) as exc_info:
        client.complete("simulate_bad_request")

    assert exc_info.value.kind == LLMErrorKind.FATAL


def test_complete_uses_env_ref_without_persisting_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "super-secret-value")
    client = ProviderClient(
        ProviderConfig(
            provider="openai_compatible",
            model="gpt-4o-mini",
            api_key_env="OPENAI_API_KEY",
            base_url="https://example.invalid/v1",
        )
    )

    response = client.complete("hello")

    assert response == "openai_compatible:gpt-4o-mini:stub-response"
    assert "super-secret-value" not in response


def test_router_provider_uses_env_reference(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ROUTER_API_KEY", "router-token")
    client = ProviderClient(
        ProviderConfig(
            provider="router",
            model="router-default",
            api_key_env="ROUTER_API_KEY",
        )
    )

    assert client.complete("hello") == "router:router-default:stub-response"
