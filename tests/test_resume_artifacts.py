from pathlib import Path

from adversa.artifacts.store import ArtifactStore
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
