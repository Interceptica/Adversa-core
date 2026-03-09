"""Vulnerability analysis phase controller.

Runs 5 DeepAgent analyzers (injection, XSS, SSRF, auth, authz) with bounded concurrency,
each with its own isolated Playwright browser session, and aggregates results into a VulnReport.
A semaphore caps simultaneous LLM requests to avoid rate-limit bursts (Shannon pattern).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from deepagents import create_deep_agent
from deepagents.backends.filesystem import FilesystemBackend

from adversa.agent_runtime.browser import VULN_BROWSER_TOOLS, playwright_tools_context
from adversa.agent_runtime.context import AdversaAgentContext
from adversa.agent_runtime.middleware import load_runtime_boundary_middleware
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
    max_concurrent: int = 3,
) -> VulnReport:
    """Run all 5 vuln analyzers with bounded concurrency and return an aggregated VulnReport.

    Uses a semaphore (Shannon-style runWithConcurrencyLimit) to cap simultaneous LLM
    requests. Default of 3 works well for DeepSeek/Novita; lower to 1-2 for providers
    with tight RPM limits.
    """
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

    output_virtual_prefix = _compute_vuln_output_prefix(repo_path, run_id)
    sem = asyncio.Semaphore(max_concurrent)

    async def _throttled(analyzer_type: str) -> tuple[str, AnalyzerReport]:
        async with sem:
            report = await _run_analyzer(
                analyzer_type, inputs, run_id, model, context,
                output_virtual_prefix=output_virtual_prefix,
            )
            return analyzer_type, report

    results = await asyncio.gather(*[_throttled(t) for t in _ANALYZER_TYPES])
    analyzer_results: dict[str, AnalyzerReport] = dict(results)

    return VulnReport(
        target_url=inputs.target_url,
        canonical_url=inputs.canonical_url,
        host=inputs.host,
        path=inputs.path,
        injection=analyzer_results["injection"],
        xss=analyzer_results["xss"],
        ssrf=analyzer_results["ssrf"],
        auth=analyzer_results["auth"],
        authz=analyzer_results["authz"],
        scope_inputs=inputs.scope_inputs,
        plan_inputs=inputs.plan_inputs,
    )


async def _run_analyzer(
    analyzer_type: str,
    inputs: VulnInputs,
    run_id: str,
    model: Any,
    context: AdversaAgentContext,
    *,
    output_virtual_prefix: str | None = None,
) -> AnalyzerReport:
    """Run a single vuln analyzer with its own isolated Playwright session."""
    prompt_path = PROMPTS_DIR / f"vuln_{analyzer_type}.txt"
    session_id = f"{run_id}-{analyzer_type}"

    async with playwright_tools_context(
        allowed_tools=VULN_BROWSER_TOOLS,
        headless=True,
        run_id=session_id,
    ) as browser_tools:
        output_virtual_path = (
            f"{output_virtual_prefix}/{analyzer_type}_analysis.md"
            if output_virtual_prefix
            else None
        )
        output_json_virtual_path = (
            f"{output_virtual_prefix}/{analyzer_type}_findings.json"
            if output_virtual_prefix
            else None
        )
        agent = create_deep_agent(
            model=model,
            tools=browser_tools,
            system_prompt=prompt_path.read_text(encoding="utf-8"),
            middleware=[
                load_runtime_boundary_middleware(
                    context,
                    allowed_repo_virtual_prefix=inputs.repo_virtual_path,
                    allowed_output_virtual_prefix=output_virtual_prefix,
                ),
            ],
            backend=FilesystemBackend(root_dir=PROJECT_ROOT, virtual_mode=True),
            name=f"adversa-vuln-{analyzer_type}",
        )
        result = await agent.ainvoke(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": _build_analyzer_request(
                            analyzer_type,
                            inputs,
                            output_virtual_path=output_virtual_path,
                            output_json_path=output_json_virtual_path,
                        ),
                    }
                ]
            }
        )

    # Primary: read the JSON findings file the agent wrote to disk.
    structured = None
    if output_virtual_prefix:
        json_disk_path = PROJECT_ROOT / output_virtual_prefix / f"{analyzer_type}_findings.json"
        structured = _read_agent_written_json(json_disk_path, AnalyzerReport)

    # Fallback: try to parse AnalyzerReport JSON from chat messages.
    if structured is None:
        structured = _extract_json_from_messages(result.get("messages", []), AnalyzerReport)

    if structured is None:
        # Graceful degradation: agent ran but produced no parseable JSON output.
        return AnalyzerReport(
            analyzer=analyzer_type,  # type: ignore[arg-type]
            findings=[],
            dominant_patterns=[],
            strategic_context="",
            secure_vectors=[],
            warnings=[
                f"{analyzer_type} analyzer completed but produced no structured findings. "
                "Review the raw agent output in LangSmith traces."
            ],
        )

    if isinstance(structured, AnalyzerReport):
        report = structured
    else:
        report = AnalyzerReport.model_validate(structured)

    # Enforce analyzer field matches the expected type.
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


def _build_analyzer_request(
    analyzer_type: str,
    inputs: VulnInputs,
    *,
    output_virtual_path: str | None = None,
    output_json_path: str | None = None,
) -> str:
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
    _findings_schema = (
        '{\n'
        f'  "analyzer": "{analyzer_type}",\n'
        '  "findings": [\n'
        '    {\n'
        '      "id": "INJ-001",\n'
        '      "vuln_type": "sql_injection",\n'
        f'      "analyzer": "{analyzer_type}",\n'
        '      "severity": "critical|high|medium|low|info",\n'
        '      "confidence": "high|medium|low",\n'
        '      "cvss_score": 9.8,\n'
        '      "externally_exploitable": true,\n'
        '      "endpoint": "/api/login",\n'
        '      "method": "POST",\n'
        '      "parameter": "email",\n'
        '      "source_location": "routes/login.ts:34",\n'
        '      "sink_location": null,\n'
        '      "description": "...",\n'
        '      "evidence": "code snippet or reasoning",\n'
        '      "remediation": "...",\n'
        '      "evidence_level": "high|medium|low"\n'
        '    }\n'
        '  ],\n'
        '  "dominant_patterns": ["Pattern 1: ..."],\n'
        '  "strategic_context": "...",\n'
        '  "secure_vectors": ["..."],\n'
        '  "warnings": ["..."]\n'
        '}'
    )
    output_instruction = (
        f"\n## Output\n"
        f"When analysis is complete, write two files:\n\n"
        f"1. Full markdown analysis — call write_file with:\n"
        f"   file_path: {output_virtual_path}\n"
        f"   content: <your complete markdown analysis report>\n\n"
        f"2. Structured findings JSON — call write_file with:\n"
        f"   file_path: {output_json_path}\n"
        f"   content: <AnalyzerReport JSON — schema below>\n\n"
        f"AnalyzerReport JSON schema:\n{_findings_schema}\n\n"
        f"After writing both files, stop.\n"
        if (output_virtual_path and output_json_path)
        else ""
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
        f"{output_instruction}"
        "- If something is unknown, add it to warnings rather than guessing.\n"
    )


def _compute_vuln_output_prefix(
    repo_path: str,
    run_id: str,
) -> str | None:
    """Return virtual path prefix for vuln output: repos/<name>/runs/<run_id>/vuln"""
    repo_resolved = Path(repo_path).resolve()
    try:
        repo_rel = repo_resolved.relative_to(PROJECT_ROOT)
        return str(repo_rel / "runs" / run_id / "vuln")
    except ValueError:
        return None


def _read_agent_written_json(disk_path: Path, schema_class: type) -> Any:
    """Read and validate a JSON file written by the agent. Returns None on any error."""
    if not disk_path.exists():
        return None
    try:
        data = json.loads(disk_path.read_text(encoding="utf-8"))
        return schema_class.model_validate(data)
    except Exception:
        return None


def _extract_json_from_messages(messages: list, schema_class: type) -> Any:
    """Fallback: try to parse schema JSON from the last AI message content."""
    for msg in reversed(messages):
        raw = getattr(msg, "content", "") or ""
        # LangChain multimodal messages have content as a list of content blocks.
        # Flatten to a plain string so regex can operate on it.
        if isinstance(raw, list):
            parts = []
            for block in raw:
                if isinstance(block, str):
                    parts.append(block)
                elif isinstance(block, dict):
                    parts.append(block.get("text", "") or "")
            raw = "\n".join(parts)
        content: str = raw or ""
        if not content:
            content = (getattr(msg, "additional_kwargs", {}) or {}).get("reasoning_content", "") or ""
        if not content:
            continue
        try:
            data = json.loads(content.strip())
            return schema_class.model_validate(data)
        except Exception:
            pass
        for match in re.finditer(r"\{[\s\S]*\}", content):
            try:
                data = json.loads(match.group())
                return schema_class.model_validate(data)
            except Exception:
                continue
    return None
