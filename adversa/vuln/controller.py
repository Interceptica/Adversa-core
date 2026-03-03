"""Vulnerability analysis phase controller.

Runs 5 parallel DeepAgent analyzers (injection, XSS, SSRF, auth, authz), each with
its own isolated Playwright browser session, and aggregates results into a VulnReport.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from deepagents import create_deep_agent
from deepagents.backends.filesystem import FilesystemBackend

from adversa.agent_runtime.browser import VULN_BROWSER_TOOLS, playwright_tools_context
from adversa.agent_runtime.context import AdversaAgentContext
from adversa.agent_runtime.middleware import (
    load_rules_middleware,
    load_runtime_boundary_middleware,
)
from adversa.config.load import load_config
from adversa.llm.providers import ProviderClient
from adversa.security.scope import ScopeViolationError, ensure_repo_in_repos_root
from adversa.state.models import AnalyzerReport, VulnReport
from adversa.utils.markdown import load_upstream_markdown


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PROMPTS_DIR = PROJECT_ROOT / "adversa" / "prompts"

_ANALYZER_TYPES = ("injection", "xss", "ssrf", "auth", "authz")


@dataclass(frozen=True)
class VulnInputs:
    target_url: str
    canonical_url: str
    repo_path: str
    repo_virtual_path: str
    host: str
    path: str
    recon_markdown: str
    prerecon_markdown: str
    scope_inputs: dict[str, Any]
    plan_inputs: dict[str, Any]


async def build_vuln_report(
    *,
    workspace_root: str,
    workspace: str,
    run_id: str,
    repo_path: str,
    url: str,
    config_path: str,
) -> VulnReport:
    """Run all 5 vuln analyzers in parallel and return an aggregated VulnReport."""
    context = AdversaAgentContext(
        phase="vuln",
        url=url,
        repo_path=repo_path,
        workspace=workspace,
        run_id=run_id,
        workspace_root=workspace_root,
        config_path=config_path,
    )
    cfg = load_config(config_path)
    inputs = load_vuln_inputs(
        workspace_root=workspace_root,
        workspace=workspace,
        run_id=run_id,
        repo_path=repo_path,
        url=url,
        config_path=config_path,
    )
    model = ProviderClient(cfg.provider).build_chat_model(temperature=0)

    injection, xss, ssrf, auth, authz = await asyncio.gather(
        _run_analyzer("injection", inputs, run_id, model, context),
        _run_analyzer("xss", inputs, run_id, model, context),
        _run_analyzer("ssrf", inputs, run_id, model, context),
        _run_analyzer("auth", inputs, run_id, model, context),
        _run_analyzer("authz", inputs, run_id, model, context),
    )

    return VulnReport(
        target_url=inputs.target_url,
        canonical_url=inputs.canonical_url,
        host=inputs.host,
        path=inputs.path,
        injection=injection,
        xss=xss,
        ssrf=ssrf,
        auth=auth,
        authz=authz,
        scope_inputs=inputs.scope_inputs,
        plan_inputs=inputs.plan_inputs,
    )


async def _run_analyzer(
    analyzer_type: str,
    inputs: VulnInputs,
    run_id: str,
    model: Any,
    context: AdversaAgentContext,
) -> AnalyzerReport:
    """Run a single vuln analyzer with its own isolated Playwright session."""
    prompt_path = PROMPTS_DIR / f"vuln_{analyzer_type}.txt"
    session_id = f"{run_id}-{analyzer_type}"

    async with playwright_tools_context(
        allowed_tools=VULN_BROWSER_TOOLS,
        headless=True,
        run_id=session_id,
    ) as browser_tools:
        agent = create_deep_agent(
            model=model,
            tools=browser_tools,
            system_prompt=prompt_path.read_text(encoding="utf-8"),
            middleware=[
                load_rules_middleware(context),
                load_runtime_boundary_middleware(
                    context,
                    allowed_repo_virtual_prefix=inputs.repo_virtual_path,
                ),
            ],
            response_format=AnalyzerReport,
            backend=FilesystemBackend(root_dir=PROJECT_ROOT, virtual_mode=True),
            name=f"adversa-vuln-{analyzer_type}",
        )
        result = await agent.ainvoke(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": _build_analyzer_request(analyzer_type, inputs),
                    }
                ]
            }
        )

    structured = result.get("structured_response")
    if structured is None:
        raise ValueError(
            f"DeepAgent {analyzer_type} analyzer did not return a structured_response."
        )
    if isinstance(structured, AnalyzerReport):
        report = structured
    else:
        report = AnalyzerReport.model_validate(structured)

    # Enforce analyzer field matches the expected type
    return AnalyzerReport(
        analyzer=analyzer_type,  # type: ignore[arg-type]
        findings=report.findings,
        dominant_patterns=report.dominant_patterns,
        strategic_context=report.strategic_context,
        secure_vectors=report.secure_vectors,
        warnings=report.warnings,
    )


def load_vuln_inputs(
    *,
    workspace_root: str,
    workspace: str,
    run_id: str,
    repo_path: str,
    url: str,
    config_path: str,
) -> VulnInputs:
    cfg = load_config(config_path)
    config_parent = Path(config_path).resolve().parent
    repos_root = Path(cfg.run.repos_root)
    if not repos_root.is_absolute():
        repos_root = (config_parent / repos_root).resolve()

    try:
        repo_resolved = ensure_repo_in_repos_root(Path(repo_path), repos_root)
    except ScopeViolationError as exc:
        raise ValueError(
            f"Vuln phase cannot inspect repo '{repo_path}'. Ensure it is inside '{repos_root}'."
        ) from exc

    try:
        repo_relative_to_project = repo_resolved.relative_to(PROJECT_ROOT)
    except ValueError as exc:
        raise ValueError(
            f"Vuln repo '{repo_resolved}' must live under the Adversa project root '{PROJECT_ROOT}'."
        ) from exc

    run_dir = Path(workspace_root) / workspace / run_id
    recon_markdown = load_upstream_markdown(run_dir / "recon", "recon_analysis.md")
    prerecon_markdown = load_upstream_markdown(run_dir / "prerecon", "pre_recon_analysis.md")

    scope_inputs, plan_inputs = _load_phase_inputs(
        workspace_root=workspace_root,
        workspace=workspace,
        run_id=run_id,
    )
    parsed = urlparse(url)
    repo_virtual_path = "/" + repo_relative_to_project.as_posix()
    return VulnInputs(
        target_url=url,
        canonical_url=_canonical_url(url),
        repo_path=repo_path,
        repo_virtual_path=repo_virtual_path,
        host=(parsed.hostname or "").lower(),
        path=parsed.path or "/",
        recon_markdown=recon_markdown,
        prerecon_markdown=prerecon_markdown,
        scope_inputs=scope_inputs,
        plan_inputs=plan_inputs,
    )


def _load_phase_inputs(
    *, workspace_root: str, workspace: str, run_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
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
        }

    if plan_path.exists():
        plan_payload = json.loads(plan_path.read_text(encoding="utf-8"))
        vuln_expectation = next(
            (
                item
                for item in plan_payload.get("phase_expectations", [])
                if item.get("phase") == "vuln"
            ),
            {},
        )
        plan_inputs = {
            "selected_analyzers": vuln_expectation.get("selected_analyzers", []),
            "required_artifacts": vuln_expectation.get("required_artifacts", []),
            "constraints": vuln_expectation.get("constraints", []),
            "goals": vuln_expectation.get("goals", []),
        }

    return scope_inputs, plan_inputs


def _canonical_url(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme or "https"
    host = (parsed.hostname or "").lower()
    port = parsed.port
    path = parsed.path.rstrip("/") or "/"
    if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        return f"{scheme}://{host}:{port}{path}"
    return f"{scheme}://{host}{path}"


def _build_analyzer_request(analyzer_type: str, inputs: VulnInputs) -> str:
    recon_section = (
        inputs.recon_markdown
        if inputs.recon_markdown
        else "_Recon analysis report not available — run recon phase first._"
    )
    prerecon_section = (
        inputs.prerecon_markdown
        if inputs.prerecon_markdown
        else "_Pre-recon report not available — run prerecon phase first._"
    )
    return (
        f"Run a {analyzer_type} vulnerability analysis for Adversa.\n\n"
        "Authorized target:\n"
        f"- target_url: {inputs.target_url}\n"
        f"- canonical_url: {inputs.canonical_url}\n"
        f"- repo_virtual_path: {inputs.repo_virtual_path}\n"
        f"- normalized_host: {inputs.host}\n"
        f"- normalized_path: {inputs.path}\n"
        "\nIntake scope inputs:\n"
        f"{json.dumps(inputs.scope_inputs, indent=2, sort_keys=True)}\n"
        "\nPlanner vuln inputs:\n"
        f"{json.dumps(inputs.plan_inputs, indent=2, sort_keys=True)}\n"
        "\n== RECON ANALYSIS REPORT ==\n"
        f"{recon_section}\n"
        "\n== PRE-RECON ANALYSIS REPORT ==\n"
        f"{prerecon_section}\n"
        "\nRequirements:\n"
        f"- Perform a thorough {analyzer_type} vulnerability analysis using both upstream reports.\n"
        "- Use browser tools to verify live behavior where relevant (navigation, form submission).\n"
        "- Only navigate to the authorized target_url.\n"
        "- Do not exploit vulnerabilities — analysis and verification only.\n"
        "- Produce a complete structured AnalyzerReport with findings, dominant_patterns, "
        "strategic_context, secure_vectors, and warnings.\n"
        "- Set externally_exploitable=true only when a finding is directly reachable without "
        "special internal access.\n"
        "- If something is unknown, add it to warnings rather than guessing.\n"
    )
