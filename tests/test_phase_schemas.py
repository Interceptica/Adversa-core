from __future__ import annotations

import json
from pathlib import Path

import pytest
from temporalio.exceptions import ApplicationError

from adversa.artifacts.store import ArtifactStore
from adversa.state.models import EvidenceRef, PhaseOutput
from adversa.state.schemas import export_schemas, validate_index, validate_manifest, validate_phase_output
from adversa.workflow_temporal.activities import run_phase_activity


def test_schema_export_writes_valid_json_schema_files(tmp_path: Path) -> None:
    export_schemas(tmp_path)

    expected = {
        "EvidenceRef.json",
        "PhaseOutput.json",
        "PlanBudget.json",
        "PhaseExpectation.json",
        "PlanWarning.json",
        "RunPlan.json",
        "ScopeContract.json",
        "IntakeCoverage.json",
        "ArtifactIndex.json",
        "ManifestState.json",
        "WorkflowInput.json",
        "WorkflowStatus.json",
    }
    assert {path.name for path in tmp_path.iterdir()} == expected

    phase_schema = json.loads((tmp_path / "PhaseOutput.json").read_text(encoding="utf-8"))
    assert phase_schema["title"] == "PhaseOutput"
    assert "properties" in phase_schema
    assert phase_schema["properties"]["summary"]["description"] == "Short narrative summary of the phase result."


def test_phase_output_validation_rejects_invalid_payload(tmp_path: Path) -> None:
    phase_dir = tmp_path / "intake"
    phase_dir.mkdir(parents=True)
    output_path = phase_dir / "output.json"
    output_path.write_text(json.dumps({"phase": "intake"}), encoding="utf-8")

    assert validate_phase_output(output_path) is False


def test_manifest_and_index_validators_reject_invalid_payloads(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    index_path = tmp_path / "index.json"
    manifest_path.write_text(json.dumps({"workspace": "ws"}), encoding="utf-8")
    index_path.write_text(json.dumps({"files": [{"path": "x"}]}), encoding="utf-8")

    assert validate_manifest(manifest_path) is False
    assert validate_index(index_path) is False


def test_run_phase_activity_fails_on_invalid_phase_boundary(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    original_write_phase_artifacts = ArtifactStore.write_phase_artifacts

    def fake_write_phase_artifacts(self, output: PhaseOutput):  # type: ignore[no-untyped-def]
        files = original_write_phase_artifacts(self, output)
        files["output"].write_text(json.dumps({"phase": output.phase}), encoding="utf-8")
        return files

    monkeypatch.setattr(ArtifactStore, "write_phase_artifacts", fake_write_phase_artifacts)

    import asyncio

    with pytest.raises(ApplicationError) as exc_info:
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

    assert exc_info.value.type == "invalid_phase_output"
    store = ArtifactStore(tmp_path, "ws", "run1")
    manifest = store.read_manifest()
    assert manifest is not None
    assert manifest.last_error == "Invalid phase output generated for phase 'intake'"


def test_resume_skip_only_when_schema_valid(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path, "ws", "run1")
    out = PhaseOutput(
        phase="intake",
        summary="ok",
        evidence=[EvidenceRef(id="e1", path="intake/evidence/stub.txt")],
    )
    files = store.write_phase_artifacts(out)
    assert store.should_skip_phase("intake") is True

    files["output"].write_text(json.dumps({"phase": "intake"}), encoding="utf-8")
    assert store.should_skip_phase("intake") is False
