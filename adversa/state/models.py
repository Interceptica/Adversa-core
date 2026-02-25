from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field


class EvidenceRef(BaseModel):
    id: str
    path: str
    note: str | None = None


class PhaseOutput(BaseModel):
    phase: Literal["intake", "prerecon", "recon", "vuln", "report"]
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    summary: str
    evidence: list[EvidenceRef] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)


class ArtifactEntry(BaseModel):
    path: str
    sha256: str


class ArtifactIndex(BaseModel):
    files: list[ArtifactEntry] = Field(default_factory=list)


class ManifestState(BaseModel):
    workspace: str
    run_id: str
    url: str
    repo_path: str
    workflow_id: str | None = None
    current_phase: str | None = None
    completed_phases: list[str] = Field(default_factory=list)
    waiting_for_config: bool = False
    waiting_reason: str | None = None
    paused: bool = False
    canceled: bool = False
    last_error: str | None = None


class WorkflowInput(BaseModel):
    workspace: str
    repo_path: str
    url: str
    effective_config_path: str
    safe_mode: bool
    run_id: str
    force: bool = False


class WorkflowStatus(BaseModel):
    current_phase: str | None = None
    completed_phases: list[str] = Field(default_factory=list)
    artifact_index_path: str | None = None
    last_error: str | None = None
    waiting_reason: str | None = None
    waiting_for_config: bool = False
    paused: bool = False
    canceled: bool = False


PHASES = ["intake", "prerecon", "recon", "vuln", "report"]


def schema_export(target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    for model in [EvidenceRef, PhaseOutput, ArtifactIndex, ManifestState, WorkflowInput, WorkflowStatus]:
        path = target_dir / f"{model.__name__}.json"
        path.write_text(model.model_json_schema().__repr__(), encoding="utf-8")
