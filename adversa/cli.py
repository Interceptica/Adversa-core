from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path

import typer

from adversa.artifacts.manifest import ensure_resume_url_matches
from adversa.artifacts.store import ArtifactStore, latest_run_id
from adversa.config.load import load_config, scaffold_default_config
from adversa.security.scope import ScopeViolationError, ensure_repo_in_repos_root, ensure_safe_target_url
from adversa.state.models import ManifestState
from adversa.workflow_temporal.client import (
    check_provider_health,
    get_client,
    query_status,
    signal_cancel,
    signal_resume,
    signal_update_config,
    start_run,
)

app = typer.Typer(help="Adversa safe-by-default security CLI")


@app.command()
def init(
    path: str = typer.Option(
        "adversa.toml",
        "--path",
        help="Path where adversa.toml will be created.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite existing config/template files if they already exist.",
    ),
) -> None:
    target = Path(path)
    if target.exists() and not force:
        raise typer.BadParameter(f"{path} already exists. Use --force to overwrite.")

    scaffold_default_config(target)
    scope_template = target.parent / "scope.template.json"
    if not scope_template.exists() or force:
        scope_template.write_text(
            json.dumps(
                {
                    "authorized": True,
                    "target": "https://staging.example.com",
                    "out_of_scope": ["production"],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    typer.echo(f"Initialized {target} and {scope_template}")


@app.command()
def run(
    repo: str = typer.Option(
        ...,
        "--repo",
        help="Path to authorized target repository. Must be under local repos/.",
    ),
    url: str = typer.Option(
        ...,
        "--url",
        help="Authorized staging URL for this run (never production by default).",
    ),
    workspace: str = typer.Option(
        "default",
        "--workspace",
        help="Workspace name used under runs/<workspace>/ for grouping run history.",
    ),
    config: str = typer.Option(
        "adversa.toml",
        "--config",
        help="Path to adversa.toml configuration file.",
    ),
    i_acknowledge: bool = typer.Option(
        False,
        "--i-acknowledge",
        help="Required explicit acknowledgement for authorized safe-mode testing.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Re-run phases even if schema-valid artifacts already exist.",
    ),
) -> None:
    cfg = load_config(config)
    if not (i_acknowledge or cfg.safety.acknowledgement):
        raise typer.BadParameter("Acknowledgement required. Pass --i-acknowledge.")

    try:
        repo_path = ensure_repo_in_repos_root(Path(repo), Path(cfg.run.repos_root))
        safe_url = ensure_safe_target_url(url, network_discovery_enabled=cfg.safety.network_discovery_enabled)
    except ScopeViolationError as exc:
        raise typer.BadParameter(str(exc)) from exc

    run_id = uuid.uuid4().hex[:12]
    workflow_id = f"adversa-{workspace}-{run_id}"

    store = ArtifactStore(Path(cfg.run.workspace_root), workspace, run_id)
    manifest = ManifestState(
        workspace=workspace,
        run_id=run_id,
        url=safe_url,
        repo_path=str(repo_path),
        workflow_id=workflow_id,
    )
    store.write_manifest(manifest)

    payload = {
        "workspace": workspace,
        "repo_path": str(repo_path),
        "url": safe_url,
        "effective_config_path": str(Path(config).resolve()),
        "safe_mode": cfg.safety.safe_mode,
        "run_id": run_id,
        "force": force,
    }

    async def _start() -> None:
        client = await get_client()
        await start_run(client, workflow_id, payload)

    asyncio.run(_start())
    typer.echo(f"Started workflow {workflow_id}")


def _resolve_run_id(cfg_workspace_root: str, workspace: str, run_id: str | None) -> str:
    if run_id:
        return run_id
    resolved = latest_run_id(Path(cfg_workspace_root), workspace)
    if not resolved:
        raise typer.BadParameter(f"No runs found for workspace '{workspace}'.")
    return resolved


@app.command()
def resume(
    workspace: str = typer.Option(
        ...,
        "--workspace",
        help="Workspace name. Use the same workspace used in `adversa run`.",
    ),
    run_id: str | None = typer.Option(
        None,
        "--run-id",
        help="Specific run ID to resume. If omitted, resumes latest run in the workspace.",
    ),
    url: str | None = typer.Option(
        None,
        "--url",
        help="Optional target URL to verify against the original run before resuming.",
    ),
    force_target_mismatch: bool = typer.Option(
        False,
        "--force-target-mismatch",
        help="Allow resume even when the provided --url differs from the original run target.",
    ),
) -> None:
    cfg = load_config()
    run_id = _resolve_run_id(cfg.run.workspace_root, workspace, run_id)
    store = ArtifactStore(Path(cfg.run.workspace_root), workspace, run_id)
    manifest = store.read_manifest()
    if not manifest or not manifest.workflow_id:
        raise typer.BadParameter("No resumable manifest/workflow_id found.")
    try:
        ensure_resume_url_matches(
            manifest,
            url,
            force_target_mismatch=force_target_mismatch,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    async def _resume() -> None:
        client = await get_client()
        await signal_resume(client, manifest.workflow_id)
        await signal_update_config(client, manifest.workflow_id)

    asyncio.run(_resume())
    typer.echo(f"Resumed {manifest.workflow_id}")


@app.command()
def status(
    workspace: str = typer.Option(
        ...,
        "--workspace",
        help="Workspace name. Use the same workspace used in `adversa run`.",
    ),
    run_id: str | None = typer.Option(
        None,
        "--run-id",
        help="Specific run ID to inspect. If omitted, shows latest run in the workspace.",
    ),
) -> None:
    cfg = load_config()
    run_id = _resolve_run_id(cfg.run.workspace_root, workspace, run_id)
    store = ArtifactStore(Path(cfg.run.workspace_root), workspace, run_id)
    manifest = store.read_manifest()
    if not manifest or not manifest.workflow_id:
        raise typer.BadParameter("No manifest/workflow_id found.")

    async def _status() -> dict:
        client = await get_client()
        workflow_status = await query_status(client, manifest.workflow_id)
        provider_status = await check_provider_health(cfg.model_dump())
        return {
            **workflow_status,
            "provider_health": provider_status,
        }

    s = asyncio.run(_status())
    index = store.read_index()
    typer.echo(
        json.dumps(
            {
                "workspace": workspace,
                "run_id": run_id,
                "workflow_id": manifest.workflow_id,
                "url": manifest.url,
                "current_phase": s.get("current_phase"),
                "completed_phases": s.get("completed_phases", []),
                "waiting_for_config": s.get("waiting_for_config", False),
                "waiting_reason": s.get("waiting_reason"),
                "provider_health": s.get("provider_health"),
                "paused": s.get("paused", False),
                "canceled": s.get("canceled", False),
                "artifact_count": len(index.files),
                "artifacts": [f.path for f in index.files],
            },
            indent=2,
        )
    )


@app.command()
def cancel(
    workspace: str = typer.Option(
        ...,
        "--workspace",
        help="Workspace name. Use the same workspace used in `adversa run`.",
    ),
    run_id: str | None = typer.Option(
        None,
        "--run-id",
        help="Specific run ID to cancel. If omitted, cancels latest run in the workspace.",
    ),
) -> None:
    cfg = load_config()
    run_id = _resolve_run_id(cfg.run.workspace_root, workspace, run_id)
    store = ArtifactStore(Path(cfg.run.workspace_root), workspace, run_id)
    manifest = store.read_manifest()
    if not manifest or not manifest.workflow_id:
        raise typer.BadParameter("No manifest/workflow_id found.")

    async def _cancel() -> None:
        client = await get_client()
        await signal_cancel(client, manifest.workflow_id)

    asyncio.run(_cancel())
    typer.echo(f"Canceled {manifest.workflow_id}")


if __name__ == "__main__":
    app()
