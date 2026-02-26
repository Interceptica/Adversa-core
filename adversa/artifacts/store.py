from __future__ import annotations

import hashlib
import json
from pathlib import Path

from adversa.state.models import ArtifactEntry, ArtifactIndex, ManifestState, PhaseOutput
from adversa.state.schemas import validate_phase_output


class ArtifactStore:
    def __init__(self, workspace_root: Path, workspace: str, run_id: str):
        self.base = workspace_root / workspace / run_id
        self.artifacts_dir = self.base / "artifacts"
        self.index_path = self.artifacts_dir / "index.json"
        self.manifest_path = self.artifacts_dir / "manifest.json"
        self.logs_dir = self.base / "logs"
        self.prompts_dir = self.base / "prompts"

        for d in [self.base, self.artifacts_dir, self.logs_dir, self.prompts_dir]:
            d.mkdir(parents=True, exist_ok=True)

    def phase_dir(self, phase: str) -> Path:
        d = self.base / phase
        (d / "evidence").mkdir(parents=True, exist_ok=True)
        return d

    def write_phase_artifacts(self, output: PhaseOutput) -> dict[str, Path]:
        phase_dir = self.phase_dir(output.phase)
        output_path = phase_dir / "output.json"
        summary_path = phase_dir / "summary.md"
        coverage_path = phase_dir / "coverage.json"

        output_path.write_text(output.model_dump_json(indent=2), encoding="utf-8")
        summary_path.write_text(f"# {output.phase}\n\n{output.summary}\n", encoding="utf-8")
        coverage_path.write_text(json.dumps({"phase": output.phase, "status": "stub"}, indent=2), encoding="utf-8")

        return {
            "output": output_path,
            "summary": summary_path,
            "coverage": coverage_path,
        }

    def append_index(self, paths: list[Path]) -> None:
        index = self.read_index()
        existing = {x.path: x for x in index.files}
        for path in paths:
            rel = str(path.relative_to(self.base))
            sha = _sha256(path)
            existing[rel] = ArtifactEntry(path=rel, sha256=sha)

        index.files = sorted(existing.values(), key=lambda x: x.path)
        self.index_path.write_text(index.model_dump_json(indent=2), encoding="utf-8")

    def read_index(self) -> ArtifactIndex:
        if not self.index_path.exists():
            return ArtifactIndex()
        return ArtifactIndex.model_validate_json(self.index_path.read_text(encoding="utf-8"))

    def read_manifest(self) -> ManifestState | None:
        if not self.manifest_path.exists():
            return None
        return ManifestState.model_validate_json(self.manifest_path.read_text(encoding="utf-8"))

    def write_manifest(self, manifest: ManifestState) -> None:
        self.manifest_path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")

    def should_skip_phase(self, phase: str, force: bool = False) -> bool:
        if force:
            return False
        phase_output = self.base / phase / "output.json"
        return phase_output.exists() and validate_phase_output(phase_output)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def latest_run_id(workspace_root: Path, workspace: str) -> str | None:
    workspace_dir = workspace_root / workspace
    if not workspace_dir.exists():
        return None
    runs = [p for p in workspace_dir.iterdir() if p.is_dir()]
    if not runs:
        return None
    runs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return runs[0].name
