from __future__ import annotations

import json
from pathlib import Path

from adversa.state.models import ArtifactIndex, ManifestState, PhaseOutput, RunPlan, schema_export


def validate_phase_output(path: Path) -> bool:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        PhaseOutput.model_validate(payload)
        return True
    except Exception:
        return False


def validate_manifest(path: Path) -> bool:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        ManifestState.model_validate(payload)
        return True
    except Exception:
        return False


def validate_run_plan(path: Path) -> bool:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        RunPlan.model_validate(payload)
        return True
    except Exception:
        return False


def validate_index(path: Path) -> bool:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        ArtifactIndex.model_validate(payload)
        return True
    except Exception:
        return False


def export_schemas(target_dir: Path) -> None:
    schema_export(target_dir)
