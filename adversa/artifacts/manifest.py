from __future__ import annotations

from adversa.state.models import ManifestState


def create_manifest(
    *,
    workspace: str,
    run_id: str,
    url: str,
    repo_path: str,
    workflow_id: str | None = None,
) -> ManifestState:
    return ManifestState(
        workspace=workspace,
        run_id=run_id,
        url=url,
        repo_path=repo_path,
        workflow_id=workflow_id,
    )


def mark_phase_completed(manifest: ManifestState, phase: str) -> ManifestState:
    manifest.current_phase = phase
    if phase not in manifest.completed_phases:
        manifest.completed_phases.append(phase)
    manifest.last_error = None
    return manifest


def mark_waiting(manifest: ManifestState, reason: str) -> ManifestState:
    manifest.waiting_for_config = True
    manifest.waiting_reason = reason
    manifest.paused = False
    return manifest


def clear_waiting(manifest: ManifestState) -> ManifestState:
    manifest.waiting_for_config = False
    manifest.waiting_reason = None
    return manifest


def mark_paused(manifest: ManifestState, paused: bool = True) -> ManifestState:
    manifest.paused = paused
    return manifest


def mark_canceled(manifest: ManifestState) -> ManifestState:
    manifest.canceled = True
    manifest.paused = False
    manifest.waiting_for_config = False
    manifest.waiting_reason = None
    return manifest


def ensure_resume_url_matches(
    manifest: ManifestState,
    requested_url: str | None,
    *,
    force_target_mismatch: bool = False,
) -> str:
    if not requested_url:
        return manifest.url
    if requested_url == manifest.url or force_target_mismatch:
        return requested_url
    raise ValueError(
        "Resume URL does not match the original run target. "
        "Pass --force-target-mismatch to override intentionally."
    )
