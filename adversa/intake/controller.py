from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from pathlib import Path

from adversa.artifacts.store import ArtifactStore
from adversa.config.load import load_config, scaffold_default_config
from adversa.config.models import AdversaConfig, RuleMatcherConfig, RulesConfig
from adversa.intake.plan import build_run_plan
from adversa.intake.questions import INTAKE_QUESTIONS
from adversa.intake.scope import build_intake_coverage, build_scope_contract
from adversa.security.scope import ScopeViolationError, ensure_repo_in_repos_root, ensure_safe_target_url
from adversa.state.models import EvidenceRef, ManifestState, PhaseOutput


class IntakeExit(Exception):
    pass


def interactive_intake(
    *,
    prompt_fn: Callable[[str], str],
    repo: str | None = None,
    url: str | None = None,
    workspace: str = "default",
    config: str = "adversa.toml",
    i_acknowledge: bool = False,
    force: bool = False,
) -> dict[str, object]:
    config_path = Path(config)
    if not config_path.exists():
        scaffold = _ask_bool(prompt_fn, f"{config} not found. Scaffold it now?", default=True)
        if scaffold:
            scaffold_default_config(config_path)

    answers: dict[str, str | bool] = {
        "repo": repo or "",
        "url": url or "",
        "workspace": "",
        "i_acknowledge": i_acknowledge,
        "focus_paths": "",
        "avoid_paths": "",
        "exclusions": "",
        "notes": "",
    }

    for question in INTAKE_QUESTIONS:
        if question.key == "i_acknowledge" and answers["i_acknowledge"] is True:
            continue
        default = workspace if question.key == "workspace" else question.default
        if isinstance(answers.get(question.key), str) and str(answers[question.key]).strip():
            continue
        answers[question.key] = _ask_question(prompt_fn, question.prompt, default=default, required=question.required)

    cfg = load_config(config_path)
    repo_path = _validate_repo(str(answers["repo"]), cfg)
    safe_url = _validate_url(str(answers["url"]), cfg)
    authorized = _to_bool(answers["i_acknowledge"])
    if not authorized:
        raise ValueError("Acknowledgement required to proceed with intake.")

    focus_paths = _csv_values(str(answers["focus_paths"]))
    avoid_paths = _csv_values(str(answers["avoid_paths"]))
    exclusions = _csv_values(str(answers["exclusions"]))
    notes = _csv_values(str(answers["notes"]))
    effective_cfg = _merge_intake_rules(cfg, focus_paths=focus_paths, avoid_paths=avoid_paths)

    run_id = uuid.uuid4().hex[:12]
    workflow_id = f"adversa-{answers['workspace']}-{run_id}"
    workspace_root = Path(effective_cfg.run.workspace_root)
    if not workspace_root.is_absolute():
        workspace_root = config_path.parent / workspace_root
    store = ArtifactStore(workspace_root, str(answers["workspace"]), run_id)
    manifest = ManifestState(
        workspace=str(answers["workspace"]),
        run_id=run_id,
        url=safe_url,
        repo_path=str(repo_path),
        workflow_id=workflow_id,
        current_phase="intake",
        completed_phases=["intake"],
    )
    store.write_manifest(manifest)

    scope = build_scope_contract(
        url=safe_url,
        repo_path=str(repo_path),
        workspace=str(answers["workspace"]),
        authorized=authorized,
        cfg=effective_cfg,
        focus_paths=focus_paths,
        avoid_paths=avoid_paths,
        exclusions=exclusions,
        notes=notes,
    )
    plan = build_run_plan(
        url=safe_url,
        repo_path=str(repo_path),
        config=effective_cfg,
        safe_mode=effective_cfg.safety.safe_mode,
    )
    coverage = build_intake_coverage(
        answered_fields=["repo", "url", "workspace", "i_acknowledge", "focus_paths", "avoid_paths", "exclusions", "notes"],
        warnings=[warning.message for warning in plan.warnings] + scope.confidence_gaps,
    )

    evidence_path = store.phase_dir("intake") / "evidence" / "intake-session.json"
    evidence_path.write_text(
        json.dumps(
            {
                "workspace": answers["workspace"],
                "repo_path": str(repo_path),
                "url": safe_url,
                "focus_paths": focus_paths,
                "avoid_paths": avoid_paths,
                "exclusions": exclusions,
                "notes": notes,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    output = PhaseOutput(
        phase="intake",
        summary="Interactive intake completed and generated deterministic scope and plan artifacts.",
        evidence=[EvidenceRef(id="intake-session", path="intake/evidence/intake-session.json", note="Interactive intake answers")],
        data={
            "interactive": True,
            "scope_ready": True,
            "plan_ready": True,
            "safe_mode": effective_cfg.safety.safe_mode,
        },
    )
    files = store.write_phase_artifacts(output)
    scope_path = store.phase_dir("intake") / "scope.json"
    scope_path.write_text(scope.model_dump_json(indent=2), encoding="utf-8")
    plan_path = store.phase_dir("intake") / "plan.json"
    plan_path.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
    coverage_path = store.phase_dir("intake") / "coverage_intake.json"
    coverage_path.write_text(coverage.model_dump_json(indent=2), encoding="utf-8")
    store.append_index([*files.values(), evidence_path, scope_path, plan_path, coverage_path])

    return {
        "repo": str(repo_path),
        "url": safe_url,
        "workspace": str(answers["workspace"]),
        "config": str(config_path.resolve()),
        "i_acknowledge": authorized,
        "force": force,
        "run_id": run_id,
        "workflow_id": workflow_id,
    }


def _ask_question(prompt_fn: Callable[[str], str], prompt: str, *, default: str | None, required: bool) -> str:
    suffix = f" [{default}]" if default not in (None, "") else ""
    while True:
        value = prompt_fn(f"{prompt}{suffix}: ").strip()
        if not value and default is not None:
            value = default
        if value:
            return value
        if not required:
            return ""


def _ask_bool(prompt_fn: Callable[[str], str], prompt: str, *, default: bool) -> bool:
    default_token = "yes" if default else "no"
    value = prompt_fn(f"{prompt} [{default_token}]: ").strip().lower()
    if not value:
        return default
    if value in {"y", "yes", "true"}:
        return True
    if value in {"n", "no", "false"}:
        return False
    raise ValueError(f"Invalid boolean response '{value}'.")


def _to_bool(value: str | bool) -> bool:
    if isinstance(value, bool):
        return value
    return value.strip().lower() in {"y", "yes", "true"}


def _csv_values(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _validate_repo(repo: str, cfg: AdversaConfig) -> Path:
    try:
        return ensure_repo_in_repos_root(Path(repo), Path(cfg.run.repos_root))
    except ScopeViolationError as exc:
        raise ValueError(str(exc)) from exc


def _validate_url(url: str, cfg: AdversaConfig) -> str:
    try:
        return ensure_safe_target_url(url, network_discovery_enabled=cfg.safety.network_discovery_enabled)
    except ScopeViolationError as exc:
        raise ValueError(str(exc)) from exc


def _merge_intake_rules(cfg: AdversaConfig, *, focus_paths: list[str], avoid_paths: list[str]) -> AdversaConfig:
    focus = list(cfg.rules.focus)
    avoid = list(cfg.rules.avoid)
    focus.extend(
        RuleMatcherConfig(description="Interactive intake focus path", type="path", value=path, phases=["recon", "vuln"])
        for path in focus_paths
    )
    avoid.extend(
        RuleMatcherConfig(description="Interactive intake avoid path", type="path", value=path, phases=["recon", "vuln"])
        for path in avoid_paths
    )
    return cfg.model_copy(update={"rules": RulesConfig(focus=focus, avoid=avoid)})
