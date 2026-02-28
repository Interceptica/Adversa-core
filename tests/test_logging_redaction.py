from __future__ import annotations

import json
from pathlib import Path

from adversa.config.models import AdversaConfig, ProviderConfig, RunConfig
from adversa.logging.audit import AuditLogger
from adversa.logging.redaction import redact_obj, redact_text
from adversa.workflow_temporal.activities import provider_health_check, run_phase_activity


def test_redaction_catches_known_secret_patterns() -> None:
    assert redact_text("api_key=abc123") == "api_key=[REDACTED]"
    assert redact_text("Bearer super-secret-token") == "Bearer [REDACTED]"
    payload = redact_obj({"token": "abc123", "nested": [{"password": "secret"}]})
    assert payload == {"token": "[REDACTED]", "nested": [{"password": "[REDACTED]"}]}


def test_jsonl_append_remains_valid_under_repeated_appends(tmp_path: Path) -> None:
    logger = AuditLogger(tmp_path)
    logger.log_tool_call({"event_type": "tool_call", "token": "abc123"})
    logger.log_tool_call({"event_type": "tool_call", "api_key": "xyz789"})

    lines = logger.tool_calls.read_text(encoding="utf-8").splitlines()
    parsed = [json.loads(line) for line in lines]

    assert len(parsed) == 2
    assert parsed[0]["token"] == "[REDACTED]"
    assert parsed[1]["api_key"] == "[REDACTED]"


def test_phase_activity_emits_audit_logs_per_phase(tmp_path: Path) -> None:
    import asyncio

    asyncio.run(
        run_phase_activity(
            str(tmp_path),
            "ws",
            "run1",
            "repos/target",
            "https://example.com",
            "intake",
            False,
        )
    )

    logs_dir = tmp_path / "ws" / "run1" / "logs"
    tool_events = [json.loads(line) for line in (logs_dir / "tool_calls.jsonl").read_text(encoding="utf-8").splitlines()]
    agent_events = [json.loads(line) for line in (logs_dir / "agent_events.jsonl").read_text(encoding="utf-8").splitlines()]

    assert any(event["event_type"] == "phase_artifacts_written" for event in tool_events)
    assert any(event["event_type"] == "phase_started" for event in agent_events)
    assert any(event["event_type"] == "phase_completed" for event in agent_events)


def test_provider_health_check_logs_redacted_events(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    cfg = AdversaConfig(
        provider=ProviderConfig(
            provider="openai_compatible",
            model="gpt-4o-mini",
            api_key_env="OPENAI_API_KEY",
            base_url="https://example.invalid/v1",
        ),
        run=RunConfig(workspace_root=str(tmp_path)),
    )

    import asyncio

    try:
        asyncio.run(provider_health_check(cfg.model_dump()))
    except Exception:
        pass

    logs_dir = tmp_path / "_system" / "provider_health" / "logs"
    tool_events = [json.loads(line) for line in (logs_dir / "tool_calls.jsonl").read_text(encoding="utf-8").splitlines()]
    agent_events = [json.loads(line) for line in (logs_dir / "agent_events.jsonl").read_text(encoding="utf-8").splitlines()]

    assert tool_events[0]["api_key_env"] == "[REDACTED]"
    assert agent_events[0]["event_type"] == "provider_health_check_failed"
