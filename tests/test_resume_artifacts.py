from pathlib import Path

import pytest
from typer.testing import CliRunner
from typer import BadParameter

from adversa.cli import app, resume
from adversa.artifacts.store import ArtifactStore
from adversa.config.models import AdversaConfig, RunConfig
from adversa.state.models import EvidenceRef, PhaseOutput


def test_resume_skips_when_artifact_exists_and_valid(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path, "ws", "run1")
    out = PhaseOutput(
        phase="intake",
        summary="ok",
        evidence=[EvidenceRef(id="e1", path="intake/evidence/stub.txt")],
    )
    store.write_phase_artifacts(out)
    assert store.should_skip_phase("intake") is True


def test_resume_reruns_when_existing_artifact_fails_schema_validation(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path, "ws", "run1")
    out = PhaseOutput(
        phase="intake",
        summary="ok",
        evidence=[EvidenceRef(id="e1", path="intake/evidence/stub.txt")],
    )
    files = store.write_phase_artifacts(out)
    files["output"].write_text('{"phase":"intake"}', encoding="utf-8")

    assert store.should_skip_phase("intake") is False


def test_resume_rejects_url_mismatch_without_force(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "runs", "ws", "run1")
    store.init_manifest(
        url="https://staging.example.com",
        repo_path="repos/target",
        workflow_id="wf-123",
    )

    monkeypatch.setattr(
        "adversa.cli.load_config",
        lambda config="adversa.toml": AdversaConfig(
            run=RunConfig(workspace_root=str(tmp_path / "runs")),
        ),
    )

    async def fake_get_client():  # type: ignore[no-untyped-def]
        return object()

    async def fake_signal_resume(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("resume signal should not be sent on URL mismatch")

    monkeypatch.setattr("adversa.cli.get_client", fake_get_client)
    monkeypatch.setattr("adversa.cli.signal_resume", fake_signal_resume)

    with pytest.raises(BadParameter, match="Resume URL does not match the original run target"):
        resume(workspace="ws", run_id="run1", url="https://other.example.com", force_target_mismatch=False)


def test_resume_allows_url_mismatch_with_explicit_force(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "runs", "ws", "run1")
    store.init_manifest(
        url="https://staging.example.com",
        repo_path="repos/target",
        workflow_id="wf-123",
    )
    calls = {"resume": 0, "update_config": 0}

    monkeypatch.setattr(
        "adversa.cli.load_config",
        lambda config="adversa.toml": AdversaConfig(
            run=RunConfig(workspace_root=str(tmp_path / "runs")),
        ),
    )

    async def fake_get_client():  # type: ignore[no-untyped-def]
        return object()

    async def fake_signal_resume(*args, **kwargs):  # type: ignore[no-untyped-def]
        calls["resume"] += 1

    async def fake_signal_update_config(*args, **kwargs):  # type: ignore[no-untyped-def]
        calls["update_config"] += 1

    monkeypatch.setattr("adversa.cli.get_client", fake_get_client)
    monkeypatch.setattr("adversa.cli.signal_resume", fake_signal_resume)
    monkeypatch.setattr("adversa.cli.signal_update_config", fake_signal_update_config)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "resume",
            "--workspace",
            "ws",
            "--run-id",
            "run1",
            "--url",
            "https://other.example.com",
            "--force-target-mismatch",
        ],
    )

    assert result.exit_code == 0
    assert calls == {"resume": 1, "update_config": 1}
