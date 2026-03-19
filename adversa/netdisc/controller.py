"""Network discovery phase controller.

Orchestrates passive and active network discovery between prerecon and recon using a
DeepAgent with a scope-enforced bash tool.  The agent runs subfinder, httpx, whatweb,
openssl, nuclei (tech-detect only), and optionally nmap, then produces a validated
``NetworkDiscoveryReport``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from deepagents import create_deep_agent

from adversa.agent_runtime.context import AdversaAgentContext
from adversa.agent_runtime.middleware import load_rules_middleware
from adversa.artifacts.store import ArtifactStore
from adversa.config.load import load_config
from adversa.llm.providers import ProviderClient
from adversa.netdisc.bash_tool import ScopedBashTool
from adversa.state.models import (
    DiscoveredHost,
    NetworkDiscoveryReport,
    PortService,
    ScopeContract,
    ServiceFingerprint,
    TLSObservation,
)
from adversa.state.schemas import validate_network_discovery
from adversa.utils.agent_output import extract_json_from_messages, read_agent_written_json


PROJECT_ROOT = Path(__file__).resolve().parents[2]
NETDISC_PROMPT_PATH = PROJECT_ROOT / "adversa" / "prompts" / "netdisc.txt"


# ── Scope contract loading ────────────────────────────────────────────────────


def _load_scope_contract(
    workspace_root: str,
    workspace: str,
    run_id: str,
) -> ScopeContract | None:
    """Load scope contract from intake phase artifacts."""
    from adversa.artifacts.store import ArtifactStore
    from pydantic import ValidationError

    store = ArtifactStore(Path(workspace_root), workspace, run_id)
    scope_path = store.phase_dir("intake") / "scope.json"
    if not scope_path.exists():
        return None
    data = json.loads(scope_path.read_text(encoding="utf-8"))
    try:
        return ScopeContract.model_validate(data)
    except ValidationError:
        # Intake writes a minimal stub scope.json that doesn't satisfy the full
        # ScopeContract schema. Return None so netdisc proceeds without scope filtering.
        return None


# ── Scope classification helpers ─────────────────────────────────────────────


def _is_host_in_scope(hostname: str, scope: ScopeContract) -> bool:
    """Return ``True`` if hostname is within the authorized scope."""
    for exclusion in scope.exclusions:
        if exclusion in hostname:
            return False
    if hostname in scope.allowed_hosts:
        return True
    for allowed_subdomain in scope.allowed_subdomains:
        if hostname.endswith(f".{allowed_subdomain}") or hostname == allowed_subdomain:
            return True
    if hostname == scope.normalized_host:
        return True
    return False


def _classify_discovered_hosts(
    hosts: list[DiscoveredHost],
    scope: ScopeContract,
) -> list[DiscoveredHost]:
    """Set ``scope_classification`` on each host based on the scope contract."""
    classified = []
    for host in hosts:
        host.scope_classification = (
            "in_scope" if _is_host_in_scope(host.hostname, scope) else "out_of_scope"
        )
        classified.append(host)
    return classified


# ── Deduplication helpers ─────────────────────────────────────────────────────


def _dedupe_hosts(hosts: list[DiscoveredHost]) -> list[DiscoveredHost]:
    deduped = {host.hostname: host for host in hosts}
    return sorted(deduped.values(), key=lambda h: (h.scope_classification, h.hostname))


def _dedupe_fingerprints(fingerprints: list[ServiceFingerprint]) -> list[ServiceFingerprint]:
    deduped = {fp.url: fp for fp in fingerprints}
    return sorted(deduped.values(), key=lambda fp: fp.url)


def _dedupe_tls_observations(observations: list[TLSObservation]) -> list[TLSObservation]:
    deduped = {(obs.hostname, obs.port): obs for obs in observations}
    return sorted(deduped.values(), key=lambda obs: obs.hostname)


def _dedupe_port_services(port_services: list[PortService]) -> list[PortService]:
    deduped = {(ps.host, ps.port, ps.protocol): ps for ps in port_services}
    return sorted(deduped.values(), key=lambda ps: (ps.host, ps.port))


# ── Request builder ───────────────────────────────────────────────────────────


def _build_netdisc_request(
    *,
    url: str,
    canonical_url: str,
    host: str,
    scope: ScopeContract,
    passive_discovery_enabled: bool,
    active_scanning_enabled: bool,
    output_json_path: str | None = None,
) -> str:
    from urllib.parse import urlparse as _urlparse
    _parsed = _urlparse(url)
    target_port: int | None = _parsed.port or (443 if _parsed.scheme == "https" else 80)

    scope_summary: dict[str, Any] = {
        "normalized_host": scope.normalized_host,
        "allowed_hosts": scope.allowed_hosts,
        "allowed_subdomains": scope.allowed_subdomains,
        "exclusions": scope.exclusions,
    }
    flags: dict[str, bool] = {
        "passive_discovery_enabled": passive_discovery_enabled,
        "active_scanning_enabled": active_scanning_enabled,
    }
    output_instruction = (
        f"\n## Output\n"
        f"When discovery is complete, call write_file with:\n"
        f"  file_path: {output_json_path}\n"
        f"  content: <NetworkDiscoveryReport JSON — see schema below>\n\n"
        f"NetworkDiscoveryReport JSON schema: populate all array fields from discovery results.\n"
        f"After writing, stop.\n"
        if output_json_path
        else ""
    )
    return (
        "Run network discovery for Adversa.\n\n"
        "Authorized target:\n"
        f"- target_url: {url}\n"
        f"- canonical_url: {canonical_url}\n"
        f"- normalized_host: {host}\n"
        f"- target_port: {target_port}  ← focus port scans here first\n"
        "\nScope contract:\n"
        f"{json.dumps(scope_summary, indent=2)}\n"
        "\nDiscovery flags:\n"
        f"{json.dumps(flags, indent=2)}\n"
        "\nRequirements:\n"
        "- Run the discovery tools as instructed in the system prompt.\n"
        "- Only target in-scope hosts. The bash tool blocks out-of-scope commands.\n"
        "- Focus port scanning on target_port first; expand to common ports only if needed.\n"
        "- Do NOT scan ports used by local infrastructure (e.g. 8080, 7233) unless they are part of the target application.\n"
        "- Populate the full NetworkDiscoveryReport with discovered hosts, fingerprints, TLS, and ports.\n"
        "- Add warnings for any tools that fail or are not installed.\n"
        "- Set passive_discovery_enabled and active_scanning_enabled in the report.\n"
        f"{output_instruction}"
    )


# ── Output normalizer ─────────────────────────────────────────────────────────


def _normalize_report(
    report: NetworkDiscoveryReport,
    *,
    url: str,
    canonical_url: str,
    host: str,
    path: str,
    scope: ScopeContract,
    passive_discovery_enabled: bool,
    active_scanning_enabled: bool,
) -> NetworkDiscoveryReport:
    """Classify, deduplicate, and enforce canonical fields on the agent output."""
    scope_inputs: dict[str, Any] = {
        "target_url": scope.target_url,
        "normalized_host": scope.normalized_host,
        "allowed_hosts": scope.allowed_hosts,
        "allowed_subdomains": scope.allowed_subdomains,
        "exclusions": scope.exclusions,
    }
    classified_hosts = _classify_discovered_hosts(report.discovered_hosts, scope)
    return NetworkDiscoveryReport(
        target_url=url,
        canonical_url=canonical_url,
        host=host,
        path=path,
        discovered_hosts=_dedupe_hosts(classified_hosts)[:100],
        service_fingerprints=_dedupe_fingerprints(report.service_fingerprints)[:50],
        tls_observations=_dedupe_tls_observations(report.tls_observations)[:50],
        port_services=_dedupe_port_services(report.port_services)[:200],
        scope_inputs=scope_inputs,
        plan_inputs=report.plan_inputs,
        passive_discovery_enabled=passive_discovery_enabled,
        active_scanning_enabled=active_scanning_enabled,
        warnings=report.warnings,
        remediation_hints=report.remediation_hints,
    )


# ── Main entry point ──────────────────────────────────────────────────────────


async def build_network_discovery_report(
    *,
    workspace_root: str,
    workspace: str,
    run_id: str,
    repo_path: str,
    url: str,
    config_path: str,
) -> NetworkDiscoveryReport:
    """Build a network discovery report using a DeepAgent with a scoped bash tool.

    Args:
        workspace_root: Workspace root directory path.
        workspace: Workspace name.
        run_id: Unique run identifier.
        repo_path: Repository path (kept for interface consistency; not used for scanning).
        url: Target URL.
        config_path: Configuration file path.

    Returns:
        Validated ``NetworkDiscoveryReport`` artifact.
    """
    cfg = load_config(config_path)
    passive_discovery_enabled = cfg.safety.network_discovery_enabled
    active_scanning_enabled = cfg.safety.active_scanning_enabled

    parsed = urlparse(url)
    canonical_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")
    host = parsed.netloc
    path = parsed.path or "/"

    # Early exit when discovery is disabled — return stub without running the agent.
    if not passive_discovery_enabled:
        return NetworkDiscoveryReport(
            target_url=url,
            canonical_url=canonical_url,
            host=host,
            path=path,
            passive_discovery_enabled=False,
            active_scanning_enabled=False,
            warnings=["Passive network discovery is disabled - emitting stub artifact"],
            remediation_hints=[
                "Enable network_discovery_enabled in adversa.toml [safety] section"
            ],
        )

    scope = _load_scope_contract(workspace_root, workspace, run_id)
    if scope is None:
        return NetworkDiscoveryReport(
            target_url=url,
            canonical_url=canonical_url,
            host=host,
            path=path,
            passive_discovery_enabled=passive_discovery_enabled,
            active_scanning_enabled=active_scanning_enabled,
            warnings=[
                "Scope contract not found — cannot safely run network discovery"
            ],
            remediation_hints=[
                "Ensure the intake phase completed successfully before running netdisc"
            ],
        )

    context = AdversaAgentContext(
        phase="netdisc",
        url=url,
        repo_path=repo_path,
        workspace=workspace,
        run_id=run_id,
        workspace_root=workspace_root,
        config_path=config_path,
    )

    # Compute virtual output path for the agent to write the JSON report directly.
    output_json_virtual_path, output_json_disk_path = _compute_netdisc_output_path(
        workspace_root, workspace, run_id
    )

    scoped_bash = ScopedBashTool(scope=scope)
    model = ProviderClient(cfg.provider).build_chat_model(temperature=0)
    system_prompt = NETDISC_PROMPT_PATH.read_text(encoding="utf-8")

    agent = create_deep_agent(
        model=model,
        tools=[scoped_bash],
        system_prompt=system_prompt,
        middleware=[load_rules_middleware(context)],
        name="adversa-netdisc",
    )

    result = await agent.ainvoke(
        {
            "messages": [
                {
                    "role": "user",
                    "content": _build_netdisc_request(
                        url=url,
                        canonical_url=canonical_url,
                        host=host,
                        scope=scope,
                        passive_discovery_enabled=passive_discovery_enabled,
                        active_scanning_enabled=active_scanning_enabled,
                        output_json_path=output_json_virtual_path,
                    ),
                }
            ]
        }
    )

    # Primary: read the JSON file the agent wrote to disk.
    structured = None
    if output_json_disk_path:
        structured = read_agent_written_json(output_json_disk_path, NetworkDiscoveryReport)

    # Fallback: try to parse NetworkDiscoveryReport JSON from chat messages.
    if structured is None:
        structured = extract_json_from_messages(result.get("messages", []), NetworkDiscoveryReport)

    if structured is None:
        # Graceful degradation: return stub report with warning.
        structured = NetworkDiscoveryReport(
            target_url=url,
            canonical_url=canonical_url,
            host=host,
            path=path,
            passive_discovery_enabled=passive_discovery_enabled,
            active_scanning_enabled=active_scanning_enabled,
            warnings=["netdisc agent completed but produced no parseable JSON output."],
        )

    if not isinstance(structured, NetworkDiscoveryReport):
        structured = NetworkDiscoveryReport.model_validate(structured)

    return _normalize_report(
        structured,
        url=url,
        canonical_url=canonical_url,
        host=host,
        path=path,
        scope=scope,
        passive_discovery_enabled=passive_discovery_enabled,
        active_scanning_enabled=active_scanning_enabled,
    )


def _compute_netdisc_output_path(
    workspace_root: str,
    workspace: str,
    run_id: str,
) -> tuple[str | None, Path | None]:
    """Return (virtual_path, disk_path) for the netdisc JSON output artifact."""
    ws = Path(workspace_root)
    if not ws.is_absolute():
        ws = (PROJECT_ROOT / ws).resolve()
    disk_path = ws / workspace / run_id / "netdisc" / "network_discovery.json"
    try:
        ws_rel = ws.relative_to(PROJECT_ROOT)
        virtual_path = str(ws_rel / workspace / run_id / "netdisc" / "network_discovery.json")
        return virtual_path, disk_path
    except ValueError:
        return None, disk_path


async def write_netdisc_artifacts(
    store: ArtifactStore,
    *,
    workspace_root: str,
    workspace: str,
    run_id: str,
    repo_path: str,
    url: str,
    effective_config_path: str,
) -> list[Path]:
    """Run the netdisc agent and write all phase artifacts.

    Returns the list of written paths (network_discovery.json, network_discovery.md,
    evidence/baseline.json). Raises on agent failure or schema validation errors.
    """
    from adversa.netdisc.reports import generate_netdisc_markdown

    phase_dir = store.phase_dir("netdisc")

    report = await build_network_discovery_report(
        workspace_root=workspace_root,
        workspace=workspace,
        run_id=run_id,
        repo_path=repo_path,
        url=url,
        config_path=effective_config_path,
    )

    network_discovery_path = phase_dir / "network_discovery.json"
    network_discovery_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    if not validate_network_discovery(network_discovery_path):
        raise ValueError("Invalid netdisc artifact generated.")

    markdown_content = generate_netdisc_markdown(report)
    markdown_path = phase_dir / "network_discovery.md"
    markdown_path.write_text(markdown_content, encoding="utf-8")

    evidence_path = phase_dir / "evidence" / "baseline.json"
    evidence_path.write_text(
        json.dumps(
            {
                "target_url": report.target_url,
                "canonical_url": report.canonical_url,
                "discovered_hosts": [item.model_dump(mode="json") for item in report.discovered_hosts],
                "service_fingerprints": [item.model_dump(mode="json") for item in report.service_fingerprints],
                "tls_observations": [item.model_dump(mode="json") for item in report.tls_observations],
                "port_services": [item.model_dump(mode="json") for item in report.port_services],
                "scope_inputs": report.scope_inputs,
                "plan_inputs": report.plan_inputs,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return [network_discovery_path, markdown_path, evidence_path]
