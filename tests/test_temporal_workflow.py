from __future__ import annotations

import asyncio

import pytest

from adversa.state.models import PHASES
from adversa.workflow_temporal.workflows import AdversaRunWorkflow, WorkflowEngine, workflow


def _payload() -> dict:
    return {
        "workspace": "runs/ws",
        "repo_path": "repos/target",
        "url": "https://example.com",
        "effective_config_path": "adversa.toml",
        "safe_mode": True,
        "run_id": "run-001",
        "force": False,
    }


def test_engine_signal_transitions() -> None:
    engine = WorkflowEngine()
    engine.pause()
    assert engine.status.paused is True

    engine.mark_waiting("LLM provider config required")
    assert engine.status.waiting_for_config is True
    assert engine.status.waiting_reason == "LLM provider config required"
    assert engine.status.paused is False

    engine.resume()
    assert engine.status.paused is False
    assert engine.status.waiting_for_config is True

    engine.mark_config_updated()
    assert engine.status.waiting_for_config is False
    assert engine.status.waiting_reason is None

    engine.cancel()
    assert engine.status.canceled is True
    assert engine.status.paused is False
    assert engine.status.waiting_for_config is False


def test_run_tracks_all_phases_and_status(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    async def fake_execute_activity(*args, **kwargs):  # type: ignore[no-untyped-def]
        phase = args[6]
        calls.append(phase)
        return {"status": "completed"}

    async def fake_sleep(*args, **kwargs):  # type: ignore[no-untyped-def]
        return None

    monkeypatch.setattr(workflow, "execute_activity", fake_execute_activity)
    monkeypatch.setattr(workflow, "sleep", fake_sleep)

    wf = AdversaRunWorkflow()
    status = asyncio.run(wf.run(_payload()))

    assert calls == PHASES
    assert status["completed_phases"] == PHASES
    assert status["current_phase"] == "report"
    assert status["artifact_index_path"] == "runs/ws/run-001/artifacts/index.json"
    assert status["waiting_for_config"] is False
    assert status["canceled"] is False


def test_update_config_unblocks_waiting(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = {"count": 0}

    async def fake_execute_activity(*args, **kwargs):  # type: ignore[no-untyped-def]
        phase = args[6]
        if phase == "intake" and attempts["count"] == 0:
            attempts["count"] += 1
            raise RuntimeError("401 Unauthorized")
        return {"status": "completed"}

    async def fake_wait_condition(fn, timeout=None):  # type: ignore[no-untyped-def]
        assert timeout is not None
        wf.update_config()
        assert fn() is True
        return None

    async def fake_sleep(*args, **kwargs):  # type: ignore[no-untyped-def]
        return None

    monkeypatch.setattr(workflow, "execute_activity", fake_execute_activity)
    monkeypatch.setattr(workflow, "wait_condition", fake_wait_condition)
    monkeypatch.setattr(workflow, "sleep", fake_sleep)

    wf = AdversaRunWorkflow()
    status = asyncio.run(wf.run(_payload()))

    assert attempts["count"] == 1
    assert status["waiting_for_config"] is False
    assert status["waiting_reason"] is None
    assert status["completed_phases"] == PHASES


def test_cancel_stops_phase_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    async def fake_execute_activity(*args, **kwargs):  # type: ignore[no-untyped-def]
        phase = args[6]
        calls.append(phase)
        if phase == "intake":
            wf.cancel()
        return {"status": "completed"}

    async def fake_sleep(*args, **kwargs):  # type: ignore[no-untyped-def]
        return None

    monkeypatch.setattr(workflow, "execute_activity", fake_execute_activity)
    monkeypatch.setattr(workflow, "sleep", fake_sleep)

    wf = AdversaRunWorkflow()
    status = asyncio.run(wf.run(_payload()))

    assert calls == ["intake"]
    assert status["canceled"] is True
    assert status["completed_phases"] == ["intake"]
