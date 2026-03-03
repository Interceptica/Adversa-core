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

    store = ArtifactStore(Path(workspace_root), workspace, run_id)
    scope_path = store.phase_dir("intake") / "scope.json"
    if not scope_path.exists():
        return None
    data = json.loads(scope_path.read_text(encoding="utf-8"))
    return ScopeContract.model_validate(data)


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
) -> str:
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
    return (
        "Run network discovery for Adversa.\n\n"
        "Authorized target:\n"
        f"- target_url: {url}\n"
        f"- canonical_url: {canonical_url}\n"
        f"- normalized_host: {host}\n"
        "\nScope contract:\n"
        f"{json.dumps(scope_summary, indent=2)}\n"
        "\nDiscovery flags:\n"
        f"{json.dumps(flags, indent=2)}\n"
        "\nRequirements:\n"
        "- Run the discovery tools as instructed in the system prompt.\n"
        "- Only target in-scope hosts. The bash tool blocks out-of-scope commands.\n"
        "- Populate the full NetworkDiscoveryReport with discovered hosts, fingerprints, TLS, and ports.\n"
        "- Add warnings for any tools that fail or are not installed.\n"
        "- Set passive_discovery_enabled and active_scanning_enabled in the report.\n"
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
    passive_discovery_enabled = getattr(cfg.safety, "network_discovery_enabled", False)
    active_scanning_enabled = getattr(cfg.safety, "active_scanning_enabled", False)

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

    scoped_bash = ScopedBashTool(scope=scope)
    model = ProviderClient(cfg.provider).build_chat_model(temperature=0)
    system_prompt = NETDISC_PROMPT_PATH.read_text(encoding="utf-8")

    agent = create_deep_agent(
        model=model,
        tools=[scoped_bash],
        system_prompt=system_prompt,
        middleware=[load_rules_middleware(context)],
        response_format=NetworkDiscoveryReport,
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
                    ),
                }
            ]
        }
    )

    structured = result.get("structured_response")
    if structured is None:
        raise ValueError("DeepAgent netdisc run did not return a structured_response.")
    if isinstance(structured, NetworkDiscoveryReport):
        report = structured
    else:
        report = NetworkDiscoveryReport.model_validate(structured)

    return _normalize_report(
        report,
        url=url,
        canonical_url=canonical_url,
        host=host,
        path=path,
        scope=scope,
        passive_discovery_enabled=passive_discovery_enabled,
        active_scanning_enabled=active_scanning_enabled,
    )
