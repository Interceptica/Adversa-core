"""Report phase controller.

LLM agent synthesizes upstream phase artifacts (prerecon, netdisc, vuln) into
a polished executive report and full pentester report.
Pure-Python retest plan generation is retained for structured, hallucination-free output.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from deepagents import create_deep_agent
from deepagents.backends.filesystem import FilesystemBackend

from adversa.artifacts.store import ArtifactStore
from adversa.config.load import load_config
from adversa.llm.providers import ProviderClient
from adversa.report.reports import generate_retest_plan
from adversa.state.models import RetestPlan, VulnReport
from adversa.state.schemas import validate_retest_plan
from adversa.utils.agent_output import read_agent_written_file


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPORT_PROMPT_PATH = PROJECT_ROOT / "adversa" / "prompts" / "report.txt"


def _compute_report_output_paths(
    workspace_root: str,
    workspace: str,
    run_id: str,
    filename: str,
) -> tuple[str | None, Path | None]:
    ws = Path(workspace_root)
    if not ws.is_absolute():
        ws = (PROJECT_ROOT / ws).resolve()
    disk_path = ws / workspace / run_id / "report" / filename
    try:
        ws_rel = ws.relative_to(PROJECT_ROOT)
        virtual_path = str(ws_rel / workspace / run_id / "report" / filename)
        return virtual_path, disk_path
    except ValueError:
        return None, disk_path


def write_report_artifacts(
    store: ArtifactStore,
    *,
    workspace_root: str,
    workspace: str,
    run_id: str,
    repo_path: str,
    url: str,
    effective_config_path: str,
) -> tuple[list[Path], dict]:
    """Synthesize upstream artifacts into final report deliverables via LLM agent.

    Uses an LLM agent to write report.md and exec_summary.md from upstream phase outputs.
    Uses pure Python to generate retest_plan.json (deterministic, no hallucination risk).

    Returns (paths, result) where result has keys: retest_plan, findings_summary.
    """
    phase_dir = store.phase_dir("report")
    run_dir = Path(workspace_root) / workspace / run_id

    # Load upstream markdown artifacts (graceful if phases were skipped)
    prerecon_markdown = read_agent_written_file(run_dir / "prerecon" / "pre_recon_analysis.md")
    netdisc_markdown = read_agent_written_file(run_dir / "netdisc" / "network_discovery.md")
    vuln_markdown = read_agent_written_file(run_dir / "vuln" / "vuln_analysis.md")

    # Load VulnReport for retest plan (pure Python, no LLM)
    findings_path = run_dir / "vuln" / "findings.json"
    if findings_path.exists():
        vuln_report = VulnReport.model_validate_json(findings_path.read_text(encoding="utf-8"))
    else:
        parsed = urlparse(url)
        vuln_report = VulnReport(
            target_url=url,
            canonical_url=url,
            host=parsed.netloc,
            path=parsed.path or "/",
        )

    # Compute output paths for agent
    report_virtual_path, report_disk_path = _compute_report_output_paths(
        workspace_root, workspace, run_id, "report.md"
    )
    exec_virtual_path, exec_disk_path = _compute_report_output_paths(
        workspace_root, workspace, run_id, "exec_summary.md"
    )

    # Load config and build model
    cfg = load_config(effective_config_path)
    model = ProviderClient(cfg.provider).build_chat_model(temperature=0)

    # Build agent request with upstream context
    findings_json_path = run_dir / "vuln" / "findings.json"
    findings_json_content = (
        findings_json_path.read_text(encoding="utf-8")
        if findings_json_path.exists()
        else "{}"
    )

    prerecon_section = prerecon_markdown or "_Pre-recon analysis not available._"
    netdisc_section = netdisc_markdown or "_Network discovery report not available._"
    vuln_section = vuln_markdown or "_Vulnerability analysis not available._"

    output_instruction = ""
    if report_virtual_path and exec_virtual_path:
        output_instruction = (
            f"\n## Output\n"
            f"When synthesis is complete, write two files:\n\n"
            f"1. Full pentester report — call write_file with:\n"
            f"   file_path: {report_virtual_path}\n"
            f"   content: <your complete report.md>\n\n"
            f"2. Executive summary — call write_file with:\n"
            f"   file_path: {exec_virtual_path}\n"
            f"   content: <your complete exec_summary.md>\n\n"
            f"After writing both files, stop.\n"
        )

    request = (
        "Generate a final security assessment report for Adversa.\n\n"
        f"Target: {url}\n\n"
        "== PRE-RECON ANALYSIS ==\n"
        f"{prerecon_section}\n\n"
        "== NETWORK DISCOVERY REPORT ==\n"
        f"{netdisc_section}\n\n"
        "== VULNERABILITY ANALYSIS ==\n"
        f"{vuln_section}\n\n"
        "== FINDINGS JSON (structured data) ==\n"
        f"{findings_json_content}\n"
        f"{output_instruction}"
    )

    agent = create_deep_agent(
        model=model,
        system_prompt=REPORT_PROMPT_PATH.read_text(encoding="utf-8"),
        backend=FilesystemBackend(root_dir=PROJECT_ROOT, virtual_mode=True),
        name="adversa-report",
    )
    agent.invoke({"messages": [{"role": "user", "content": request}]})

    # Read agent-written files; fall back to empty if agent didn't write them
    report_md = read_agent_written_file(report_disk_path)
    if not report_md:
        report_md = "# Security Assessment Report\n\n_Report generation did not produce output._\n"

    exec_md = read_agent_written_file(exec_disk_path)
    if not exec_md:
        exec_md = "# Executive Summary\n\n_Executive summary generation did not produce output._\n"

    # Write (or overwrite) the final markdown files
    report_path = phase_dir / "report.md"
    report_path.write_text(report_md, encoding="utf-8")

    exec_path = phase_dir / "exec_summary.md"
    exec_path.write_text(exec_md, encoding="utf-8")

    # Pure Python: generate retest plan (deterministic, no hallucination risk)
    retest_plan: RetestPlan = generate_retest_plan(vuln_report)
    retest_path = phase_dir / "retest_plan.json"
    retest_path.write_text(retest_plan.model_dump_json(indent=2), encoding="utf-8")
    if not validate_retest_plan(retest_path):
        raise ValueError("Invalid retest plan generated.")

    # Pre-compute counts for activities.py
    all_findings = vuln_report.all_findings
    findings_summary = {
        "total": len(all_findings),
        "critical": sum(1 for f in all_findings if f.severity == "critical"),
        "high": sum(1 for f in all_findings if f.severity == "high"),
        "medium": sum(1 for f in all_findings if f.severity == "medium"),
        "low": sum(1 for f in all_findings if f.severity == "low"),
        "info": sum(1 for f in all_findings if f.severity == "info"),
        "externally_exploitable": sum(1 for f in all_findings if f.externally_exploitable),
    }

    evidence_path = phase_dir / "evidence" / "baseline.json"
    evidence_path.write_text(
        json.dumps(
            {
                "target_url": retest_plan.target_url,
                "generated_at": retest_plan.generated_at,
                "total_findings": retest_plan.total_findings,
                "findings_summary": findings_summary,
                "retest_steps": [step.model_dump(mode="json") for step in retest_plan.retest_steps],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    return (
        [report_path, exec_path, retest_path, evidence_path],
        {"retest_plan": retest_plan, "findings_summary": findings_summary},
    )
