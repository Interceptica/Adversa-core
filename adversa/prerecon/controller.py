from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from deepagents import create_deep_agent
from deepagents.backends.filesystem import FilesystemBackend

from adversa.agent_runtime.context import AdversaAgentContext
from adversa.agent_runtime.middleware import load_rules_middleware, load_runtime_boundary_middleware
from adversa.config.load import load_config
from adversa.llm.providers import ProviderClient
from adversa.security.scope import ScopeViolationError, ensure_repo_in_repos_root
from adversa.state.models import PreReconReport


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PRERECON_PROMPT_PATH = PROJECT_ROOT / "adversa" / "prompts" / "pre-recon-code.txt"


@dataclass(frozen=True)
class PrereconInputs:
    target_url: str
    canonical_url: str
    repo_path: str
    repo_virtual_path: str
    repo_root_validated: bool
    host: str
    path: str
    scope_inputs: dict[str, Any]
    plan_inputs: dict[str, Any]


def build_prerecon_report(
    *,
    workspace_root: str,
    workspace: str,
    run_id: str,
    repo_path: str,
    url: str,
    config_path: str,
) -> PreReconReport:
    context = AdversaAgentContext(
        phase="prerecon",
        url=url,
        repo_path=repo_path,
        workspace=workspace,
        run_id=run_id,
        workspace_root=workspace_root,
        config_path=config_path,
    )
    cfg = load_config(config_path)
    inputs = load_prerecon_inputs(
        workspace_root=workspace_root,
        workspace=workspace,
        run_id=run_id,
        repo_path=repo_path,
        url=url,
        config_path=config_path,
    )
    model = ProviderClient(cfg.provider).build_chat_model(temperature=0)
    agent = create_deep_agent(
        model=model,
        system_prompt=PRERECON_PROMPT_PATH.read_text(encoding="utf-8"),
        middleware=[
            load_rules_middleware(context),
            load_runtime_boundary_middleware(context, allowed_repo_virtual_prefix=inputs.repo_virtual_path),
        ],
        subagents=[_repo_research_subagent()],
        response_format=PreReconReport,
        backend=FilesystemBackend(root_dir=PROJECT_ROOT, virtual_mode=True),
        name="adversa-prerecon",
    )
    result = agent.invoke(
        {
            "messages": [
                {
                    "role": "user",
                    "content": _build_prerecon_request(inputs),
                }
            ]
        }
    )
    structured = result.get("structured_response")
    if structured is None:
        raise ValueError("DeepAgent prerecon run did not return a structured_response.")
    if isinstance(structured, PreReconReport):
        report = structured
    else:
        report = PreReconReport.model_validate(structured)
    return _normalize_report(report, inputs)


def load_prerecon_inputs(
    *,
    workspace_root: str,
    workspace: str,
    run_id: str,
    repo_path: str,
    url: str,
    config_path: str,
) -> PrereconInputs:
    cfg = load_config(config_path)
    config_parent = Path(config_path).resolve().parent
    repos_root = Path(cfg.run.repos_root)
    if not repos_root.is_absolute():
        repos_root = (config_parent / repos_root).resolve()

    try:
        repo_resolved = ensure_repo_in_repos_root(Path(repo_path), repos_root)
    except ScopeViolationError as exc:
        raise ValueError(
            f"Prerecon cannot inspect repo '{repo_path}'. Ensure it is inside '{repos_root}'."
        ) from exc
    try:
        repo_relative_to_project = repo_resolved.relative_to(PROJECT_ROOT)
    except ValueError as exc:
        raise ValueError(
            f"Prerecon repo '{repo_resolved}' must live under the Adversa project root '{PROJECT_ROOT}' "
            "so the DeepAgents filesystem backend can enforce a deterministic virtual root."
        ) from exc

    scope_inputs, plan_inputs = _load_intake_inputs(
        workspace_root=workspace_root,
        workspace=workspace,
        run_id=run_id,
    )
    parsed = urlparse(url)
    repo_virtual_path = "/" + repo_relative_to_project.as_posix()
    return PrereconInputs(
        target_url=url,
        canonical_url=_canonical_url(url),
        repo_path=repo_path,
        repo_virtual_path=repo_virtual_path,
        repo_root_validated=True,
        host=(parsed.hostname or "").lower(),
        path=parsed.path or "/",
        scope_inputs=scope_inputs,
        plan_inputs=plan_inputs,
    )


def _load_intake_inputs(*, workspace_root: str, workspace: str, run_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    intake_dir = Path(workspace_root) / workspace / run_id / "intake"
    scope_path = intake_dir / "scope.json"
    plan_path = intake_dir / "plan.json"

    scope_inputs: dict[str, Any] = {}
    plan_inputs: dict[str, Any] = {}

    if scope_path.exists():
        scope_payload = json.loads(scope_path.read_text(encoding="utf-8"))
        scope_inputs = {
            "normalized_host": scope_payload.get("normalized_host", ""),
            "normalized_path": scope_payload.get("normalized_path", "/"),
            "allowed_paths": sorted(set(scope_payload.get("allowed_paths", []))),
            "exclusions": sorted(set(scope_payload.get("exclusions", []))),
            "notes": scope_payload.get("notes", []),
            "rules_summary": scope_payload.get("rules_summary", {}),
            "warnings": scope_payload.get("warnings", []),
        }

    if plan_path.exists():
        plan_payload = json.loads(plan_path.read_text(encoding="utf-8"))
        prerecon_expectation = next(
            (item for item in plan_payload.get("phase_expectations", []) if item.get("phase") == "prerecon"),
            {},
        )
        plan_inputs = {
            "selected_analyzers": prerecon_expectation.get("selected_analyzers", []),
            "required_artifacts": prerecon_expectation.get("required_artifacts", []),
            "constraints": prerecon_expectation.get("constraints", []),
            "goals": prerecon_expectation.get("goals", []),
        }

    return scope_inputs, plan_inputs


def _repo_research_subagent() -> dict[str, Any]:
    return {
        "name": "repo-researcher",
        "description": "Use this subagent for detailed repository inspection, route discovery, and architecture mapping inside the authorized repo only.",
        "prompt": (
            "You are a specialist prerecon code analyst. Read only the authorized repository path given in the task. "
            "Identify framework/runtime signals, important entry points, auth/security components, and candidate routes. "
            "Return only evidence-backed findings and call out uncertainty explicitly."
        ),
    }


def _build_prerecon_request(inputs: PrereconInputs) -> str:
    return (
        "Run a prerecon code analysis for Adversa.\n\n"
        "Authorized target:\n"
        f"- target_url: {inputs.target_url}\n"
        f"- canonical_url: {inputs.canonical_url}\n"
        f"- repo_virtual_path: {inputs.repo_virtual_path}\n"
        f"- normalized_host: {inputs.host}\n"
        f"- normalized_path: {inputs.path}\n"
        "\nIntake scope inputs:\n"
        f"{json.dumps(inputs.scope_inputs, indent=2, sort_keys=True)}\n"
        "\nPlanner prerecon inputs:\n"
        f"{json.dumps(inputs.plan_inputs, indent=2, sort_keys=True)}\n"
        "\nRequirements:\n"
        "- Use the repo-researcher subagent when repository inspection is non-trivial.\n"
        "- Use deep filesystem tools only under the authorized repo_virtual_path.\n"
        "- Do not fabricate frameworks, routes, or auth flows.\n"
        "- Prefer concrete file-backed evidence.\n"
        "- Produce a complete structured PreReconReport.\n"
        "- If something is unknown, leave it out of lists and explain it in warnings/remediation_hints.\n"
    )


def _normalize_report(report: PreReconReport, inputs: PrereconInputs) -> PreReconReport:
    return report.model_copy(
        update={
            "target_url": inputs.target_url,
            "canonical_url": inputs.canonical_url,
            "host": inputs.host,
            "path": inputs.path,
            "repo_path": inputs.repo_path,
            "repo_root_validated": inputs.repo_root_validated,
            "repo_top_level_entries": sorted(set(report.repo_top_level_entries))[:50],
            "framework_signals": sorted(set(report.framework_signals)),
            "candidate_routes": sorted(set(report.candidate_routes))[:50],
            "scope_inputs": inputs.scope_inputs,
            "plan_inputs": inputs.plan_inputs,
            "warnings": sorted(set(report.warnings)),
            "remediation_hints": sorted(set(report.remediation_hints)),
        }
    )


def _canonical_url(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    return parsed._replace(path=path, params="", query="", fragment="").geturl()
