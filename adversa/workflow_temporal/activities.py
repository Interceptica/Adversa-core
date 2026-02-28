from __future__ import annotations

from pathlib import Path

from temporalio import activity
from temporalio.exceptions import ApplicationError

from adversa.artifacts.store import ArtifactStore
from adversa.config.models import AdversaConfig
from adversa.llm.errors import LLMErrorKind, LLMProviderError
from adversa.llm.providers import ProviderClient
from adversa.state.models import EvidenceRef, ManifestState, PhaseOutput
from adversa.state.schemas import validate_phase_output


@activity.defn
async def run_phase_activity(
    workspace_root: str,
    workspace: str,
    run_id: str,
    repo_path: str,
    url: str,
    phase: str,
    force: bool,
) -> dict:
    store = ArtifactStore(Path(workspace_root), workspace, run_id)
    manifest = store.read_manifest() or ManifestState(
        workspace=workspace,
        run_id=run_id,
        url=url,
        repo_path=repo_path,
    )

    if store.should_skip_phase(phase, force=force):
        return {"phase": phase, "status": "skipped"}

    output = PhaseOutput(
        phase=phase,
        summary=f"Stub {phase} phase completed in safe mode.",
        evidence=[EvidenceRef(id=f"{phase}-e1", path=f"{phase}/evidence/stub.txt", note="stub evidence")],
        data={"safe_mode": True},
    )

    files = store.write_phase_artifacts(output)
    if not validate_phase_output(files["output"]):
        message = f"Invalid phase output generated for phase '{phase}'"
        manifest.last_error = message
        store.write_manifest(manifest)
        activity.logger.error(message)
        raise ApplicationError(message, type="invalid_phase_output", non_retryable=True)

    evidence_path = store.phase_dir(phase) / "evidence" / "stub.txt"
    evidence_path.write_text("evidence", encoding="utf-8")
    store.append_index([*files.values(), evidence_path])

    if phase not in manifest.completed_phases:
        manifest.completed_phases.append(phase)
    manifest.current_phase = phase
    manifest.last_error = None
    store.write_manifest(manifest)
    return {"phase": phase, "status": "completed"}


@activity.defn
async def provider_health_check(config: dict) -> None:
    cfg = AdversaConfig.model_validate(config)
    client = ProviderClient(cfg.provider)
    client.health_check()


def classify_provider_error(exc: Exception) -> LLMProviderError:
    if isinstance(exc, LLMProviderError):
        return exc
    msg = str(exc).lower()
    if any(k in msg for k in ["401", "invalid api key", "credits", "quota"]):
        return LLMProviderError(str(exc), LLMErrorKind.CONFIG_REQUIRED)
    if any(k in msg for k in ["429", "timeout", "temporarily unavailable"]):
        return LLMProviderError(str(exc), LLMErrorKind.TRANSIENT)
    return LLMProviderError(str(exc), LLMErrorKind.FATAL)


def to_activity_error(exc: Exception) -> ApplicationError:
    provider_error = classify_provider_error(exc)
    non_retryable = provider_error.kind in {LLMErrorKind.CONFIG_REQUIRED, LLMErrorKind.FATAL}
    return ApplicationError(
        str(provider_error),
        type=provider_error.kind.value,
        non_retryable=non_retryable,
    )
