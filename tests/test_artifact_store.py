from __future__ import annotations

import hashlib
from pathlib import Path

from adversa.artifacts.manifest import clear_waiting, mark_canceled, mark_phase_completed, mark_waiting
from adversa.artifacts.store import ArtifactStore
from adversa.state.models import EvidenceRef, ManifestState, PhaseOutput
from adversa.state.schemas import validate_index, validate_manifest


def test_append_index_hashes_all_files_deterministically(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path, "ws", "run1")
    output = PhaseOutput(
        phase="intake",
        summary="summary",
        evidence=[EvidenceRef(id="e1", path="intake/evidence/stub.txt")],
    )

    files = store.write_phase_artifacts(output)
    evidence_path = store.phase_dir("intake") / "evidence" / "stub.txt"
    evidence_path.write_text("evidence", encoding="utf-8")
    store.append_index([*files.values(), evidence_path])

    index = store.read_index()
    assert [entry.path for entry in index.files] == sorted(
        ["intake/coverage.json", "intake/evidence/stub.txt", "intake/output.json", "intake/summary.md"]
    )

    expected = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    evidence_entry = next(entry for entry in index.files if entry.path == "intake/evidence/stub.txt")
    assert evidence_entry.sha256 == expected
    assert validate_index(store.index_path) is True


def test_append_index_updates_existing_entries_when_file_changes(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path, "ws", "run1")
    evidence_path = store.phase_dir("intake") / "evidence" / "stub.txt"
    evidence_path.write_text("one", encoding="utf-8")
    store.append_index([evidence_path])
    first_hash = store.read_index().files[0].sha256

    evidence_path.write_text("two", encoding="utf-8")
    store.append_index([evidence_path])
    second_hash = store.read_index().files[0].sha256

    assert first_hash != second_hash


def test_manifest_helpers_track_completion_waiting_and_cancel_states(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path, "ws", "run1")
    manifest = store.init_manifest(
        url="https://example.com",
        repo_path="repos/target",
        workflow_id="wf-123",
    )

    mark_phase_completed(manifest, "intake")
    mark_waiting(manifest, "LLM provider config required")
    clear_waiting(manifest)
    mark_canceled(manifest)
    store.write_manifest(manifest)

    written = store.read_manifest()
    assert written is not None
    assert written.workflow_id == "wf-123"
    assert written.completed_phases == ["intake"]
    assert written.current_phase == "intake"
    assert written.waiting_for_config is False
    assert written.waiting_reason is None
    assert written.canceled is True
    assert validate_manifest(store.manifest_path) is True


def test_write_manifest_round_trips_state(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path, "ws", "run1")
    manifest = ManifestState(
        workspace="ws",
        run_id="run1",
        url="https://example.com",
        repo_path="repos/target",
        workflow_id="wf-456",
        current_phase="recon",
        completed_phases=["intake", "prerecon"],
        waiting_for_config=True,
        waiting_reason="missing key",
        paused=False,
        canceled=False,
    )

    store.write_manifest(manifest)
    loaded = store.read_manifest()

    assert loaded == manifest
