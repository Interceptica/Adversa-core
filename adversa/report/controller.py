"""Report phase controller.

Pure-Python synthesis — no LLM, no Playwright.
Loads VulnReport from vuln/findings.json and upstream intake artifacts,
then calls all three generators to produce the final deliverables.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from adversa.report.reports import (
    generate_exec_summary_markdown,
    generate_retest_plan,
    generate_report_markdown,
)
from adversa.state.models import RetestPlan, VulnReport


def build_report(
    *,
    workspace_root: str,
    workspace: str,
    run_id: str,
    repo_path: str,
    url: str,
    config_path: str,
) -> dict:
    """Load upstream artifacts and generate all three report deliverables.

    Returns a dict with keys:
        report_md        - full pentester report (str)
        exec_summary_md  - executive summary (str)
        retest_plan      - RetestPlan model instance
        findings_summary - pre-computed severity / exploitability counts (dict)
    """
    run_dir = Path(workspace_root) / workspace / run_id

    # Load VulnReport — graceful empty if vuln phase was skipped
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

    # Load intake scope and plan
    scope_path = run_dir / "intake" / "scope.json"
    scope_inputs: dict = json.loads(scope_path.read_text(encoding="utf-8")) if scope_path.exists() else {}

    plan_path = run_dir / "intake" / "plan.json"
    plan_inputs: dict = json.loads(plan_path.read_text(encoding="utf-8")) if plan_path.exists() else {}

    # Generate deliverables
    report_md = generate_report_markdown(vuln_report, scope_inputs, plan_inputs)
    exec_summary_md = generate_exec_summary_markdown(vuln_report, scope_inputs)
    retest_plan: RetestPlan = generate_retest_plan(vuln_report)

    # Pre-compute counts for activities.py (avoids re-reading files)
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

    return {
        "report_md": report_md,
        "exec_summary_md": exec_summary_md,
        "retest_plan": retest_plan,
        "findings_summary": findings_summary,
    }
