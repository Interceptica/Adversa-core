from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field


class EvidenceRef(BaseModel):
    id: str = Field(description="Stable identifier for the evidence item within a phase output.")
    path: str = Field(description="Workspace-relative path to the evidence artifact on disk.")
    note: str | None = Field(default=None, description="Optional human-readable context about why this evidence matters.")


class PhaseOutput(BaseModel):
    phase: Literal["intake", "prerecon", "netdisc", "recon", "vuln", "report"] = Field(
        description="Lifecycle phase that produced this output."
    )
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when this phase output was generated.",
    )
    summary: str = Field(description="Short narrative summary of the phase result.")
    evidence: list[EvidenceRef] = Field(
        default_factory=list,
        description="Evidence references that support the phase summary and data.",
    )
    data: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured phase-specific payload written alongside the summary.",
    )


class PlanBudget(BaseModel):
    time_budget_minutes: int = Field(description="Maximum wall-clock budget allocated to the run plan in minutes.")
    token_budget: int = Field(description="Maximum model token budget allocated to the run plan.")
    cost_budget_usd: float = Field(description="Maximum provider spend budget allocated to the run plan in USD.")
    tool_call_budget: int = Field(description="Maximum number of tool invocations allowed across the run plan.")


class PhaseExpectation(BaseModel):
    phase: Literal["intake", "prerecon", "netdisc", "recon", "vuln", "report"] = Field(
        description="Phase this execution expectation applies to."
    )
    selected_analyzers: list[str] = Field(
        default_factory=list,
        description="Deterministically selected analyzers planned for this phase.",
    )
    required_artifacts: list[str] = Field(
        default_factory=list,
        description="Schema-valid artifacts the phase is expected to emit.",
    )
    goals: list[str] = Field(
        default_factory=list,
        description="Operator-readable goals that explain what the phase should accomplish.",
    )
    constraints: list[str] = Field(
        default_factory=list,
        description="Constraints that the phase must respect during execution.",
    )


class PlanWarning(BaseModel):
    code: str = Field(description="Stable machine-readable warning code.")
    message: str = Field(description="Operator-readable warning emitted during planning.")


class RunPlan(BaseModel):
    phases: list[Literal["intake", "prerecon", "netdisc", "recon", "vuln", "report"]] = Field(
        default_factory=list,
        description="Ordered lifecycle phases that the run intends to execute.",
    )
    phase_expectations: list[PhaseExpectation] = Field(
        default_factory=list,
        description="Per-phase execution contract including analyzers, artifacts, goals, and constraints.",
    )
    budgets: PlanBudget = Field(description="Safe-mode execution budgets for time, tokens, cost, and tool usage.")
    max_concurrent_pipelines: int = Field(
        description="Maximum number of concurrent execution pipelines allowed by the plan."
    )
    constraints: list[str] = Field(
        default_factory=list,
        description="Global execution constraints that apply to the entire run.",
    )
    warnings: list[PlanWarning] = Field(
        default_factory=list,
        description="Actionable planner warnings about blocked phases, empty analyzer sets, or unsupported combinations.",
    )
    rationale: str = Field(description="Operator-readable explanation of how this plan was derived.")
    safe_mode: bool = Field(description="Whether the plan is constrained to safe verification mode.")


class ScopeContract(BaseModel):
    target_url: str = Field(description="Normalized authorized target URL for this run.")
    repo_path: str = Field(description="Authorized repository path under the local repos root.")
    workspace: str = Field(description="Workspace name used to group this run.")
    authorized: bool = Field(description="Whether the operator explicitly acknowledged authorization.")
    safe_mode: bool = Field(description="Whether execution remains constrained to safe mode.")
    source_precedence: list[str] = Field(
        default_factory=list,
        description="Ordered sources used to derive this scope contract.",
    )
    normalized_host: str = Field(description="Normalized host extracted from the authorized target URL.")
    normalized_path: str = Field(description="Normalized path extracted from the authorized target URL.")
    allowed_hosts: list[str] = Field(
        default_factory=list,
        description="Hosts explicitly allowed for this run.",
    )
    allowed_subdomains: list[str] = Field(
        default_factory=list,
        description="Subdomains explicitly allowed for this run.",
    )
    allowed_paths: list[str] = Field(
        default_factory=list,
        description="Path prefixes or concrete paths explicitly allowed for this run.",
    )
    exclusions: list[str] = Field(
        default_factory=list,
        description="Operator-provided out-of-scope targets or exclusions.",
    )
    capability_constraints: list[str] = Field(
        default_factory=list,
        description="Execution capability constraints derived from safety mode and config.",
    )
    repo_root_validated: bool = Field(description="Whether the repository path passed repo-root enforcement checks.")
    evidence_expectations: list[str] = Field(
        default_factory=list,
        description="Evidence requirements downstream phases should preserve.",
    )
    notes: list[str] = Field(
        default_factory=list,
        description="Operator-provided notes that should accompany the scope contract.",
    )
    rules_summary: dict[str, list[dict[str, str]]] = Field(
        default_factory=dict,
        description="Summary of focus/avoid rules resolved from intake or config with type/value/source metadata.",
    )
    confidence_gaps: list[str] = Field(
        default_factory=list,
        description="Scope ambiguities that later phases should preserve as warnings.",
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Structured normalization warnings that should remain visible to operators and later phases.",
    )


class IntakeCoverage(BaseModel):
    phase: Literal["intake"] = Field(description="Coverage artifact phase identifier.")
    status: Literal["complete", "incomplete"] = Field(description="Whether intake gathered enough information to proceed.")
    answered_fields: list[str] = Field(
        default_factory=list,
        description="Fields that were explicitly answered during the interactive intake flow.",
    )
    pending_fields: list[str] = Field(
        default_factory=list,
        description="Fields still missing or deferred after intake completion.",
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Operator-facing intake warnings captured during scope clarification.",
    )


class FrameworkSignal(BaseModel):
    name: str = Field(description="Detected framework, runtime, or platform signal.")
    evidence: str = Field(description="Concrete file or config evidence supporting this signal.")
    evidence_level: Literal["high", "medium", "low"] = Field(
        description="Confidence level based on the quality of the supporting evidence."
    )


class RouteSurface(BaseModel):
    path: str = Field(description="Normalized candidate route or endpoint path.")
    kind: str = Field(description="Route type such as page, api, graphql, websocket, admin, or health.")
    scope_classification: Literal["in_scope", "out_of_scope"] = Field(
        description="Whether this surface is network-reachable and relevant to downstream recon."
    )
    evidence: str = Field(description="Concrete evidence supporting the presence of this route or surface.")
    evidence_level: Literal["high", "medium", "low"] = Field(
        description="Confidence level based on the quality of the supporting evidence."
    )


class AuthSignal(BaseModel):
    signal: str = Field(description="Authentication or session handling behavior identified during prerecon.")
    location: str = Field(description="File or component location where the auth signal was found.")
    evidence: str = Field(description="Concrete evidence supporting the auth finding.")
    evidence_level: Literal["high", "medium", "low"] = Field(
        description="Confidence level based on the quality of the supporting evidence."
    )


class SchemaFile(BaseModel):
    path: str = Field(description="Repository-relative path to an API or data schema file.")
    schema_type: str = Field(description="Schema type such as openapi, graphql, or json_schema.")
    evidence_level: Literal["high", "medium", "low"] = Field(
        description="Confidence level that this file is a schema relevant to attack-surface understanding."
    )


class ExternalIntegration(BaseModel):
    name: str = Field(description="External integration or outbound dependency identified during prerecon.")
    location: str = Field(description="File or component location where the integration was identified.")
    kind: str = Field(description="Integration type such as webhook, api_client, url_fetcher, import_export, or third_party.")
    evidence: str = Field(description="Concrete evidence supporting the integration finding.")
    evidence_level: Literal["high", "medium", "low"] = Field(
        description="Confidence level based on the quality of the supporting evidence."
    )


class SecurityConfigSignal(BaseModel):
    signal: str = Field(description="Security-relevant middleware, config, or policy signal.")
    location: str = Field(description="File or component location where the security configuration was found.")
    evidence: str = Field(description="Concrete evidence supporting the security configuration finding.")
    evidence_level: Literal["high", "medium", "low"] = Field(
        description="Confidence level based on the quality of the supporting evidence."
    )


class VulnerabilitySink(BaseModel):
    sink_type: str = Field(
        description="Vulnerability sink category: xss, sql_injection, command_injection, ssrf, deserialization, path_traversal, xxe, ldap_injection, or template_injection."
    )
    location: str = Field(description="File path and line reference where the sink was identified.")
    context: str = Field(description="Code context showing the dangerous sink pattern.")
    input_sources: list[str] = Field(
        default_factory=list,
        description="Potential user-controlled input sources that could reach this sink.",
    )
    evidence_level: Literal["high", "medium", "low"] = Field(
        description="Confidence level based on the quality of the supporting evidence."
    )
    scope_classification: Literal["in_scope", "out_of_scope"] = Field(
        description="Whether this sink is network-reachable and relevant to downstream vulnerability analysis."
    )
    mitigation_present: bool = Field(
        default=False,
        description="Whether sanitization, validation, or other mitigation was detected near this sink.",
    )


class DataFlowPattern(BaseModel):
    data_type: str = Field(
        description="Sensitive data category: credentials, pii, tokens, api_keys, session_data, credit_cards, health_records, or other."
    )
    sources: list[str] = Field(
        default_factory=list,
        description="Code locations where this sensitive data originates or is collected.",
    )
    sinks: list[str] = Field(
        default_factory=list,
        description="Code locations where this sensitive data is consumed, stored, or transmitted.",
    )
    encryption_status: Literal["encrypted", "plaintext", "mixed", "unknown"] = Field(
        description="Whether sensitive data is protected by encryption in transit and at rest."
    )
    storage_locations: list[str] = Field(
        default_factory=list,
        description="Where sensitive data is persisted: database, file, cache, session, or third_party.",
    )
    evidence_level: Literal["high", "medium", "low"] = Field(
        description="Confidence level based on the quality of the supporting evidence."
    )
    compliance_concerns: list[str] = Field(
        default_factory=list,
        description="Potential compliance issues: gdpr, hipaa, pci_dss, sox, or custom requirements.",
    )


class PreReconReport(BaseModel):
    target_url: str = Field(description="Authorized target URL evaluated during prerecon.")
    canonical_url: str = Field(description="Normalized canonical URL used for prerecon baselining.")
    host: str = Field(description="Normalized host extracted from the target URL.")
    path: str = Field(description="Normalized path extracted from the target URL.")
    repo_path: str = Field(description="Authorized repository path inspected during prerecon.")
    repo_root_validated: bool = Field(description="Whether the repository path passed repo-root validation before inspection.")
    repo_top_level_entries: list[str] = Field(
        default_factory=list,
        description="Deterministically sorted top-level files and directories discovered in the target repository.",
    )
    framework_signals: list[FrameworkSignal] = Field(
        default_factory=list,
        description="Detected framework and runtime signals inferred from repository files.",
    )
    candidate_routes: list[RouteSurface] = Field(
        default_factory=list,
        description="Potential application route paths inferred from repository and target inputs.",
    )
    auth_signals: list[AuthSignal] = Field(
        default_factory=list,
        description="Authentication and session handling signals relevant to downstream recon.",
    )
    schema_files: list[SchemaFile] = Field(
        default_factory=list,
        description="Discovered schema files that document the application's surface area.",
    )
    external_integrations: list[ExternalIntegration] = Field(
        default_factory=list,
        description="External integrations and outbound interactions that inform recon scope.",
    )
    security_config: list[SecurityConfigSignal] = Field(
        default_factory=list,
        description="Security middleware and policy signals relevant to safe recon planning.",
    )
    vulnerability_sinks: list[VulnerabilitySink] = Field(
        default_factory=list,
        description="Identified vulnerability sinks (XSS, injection, SSRF, etc.) discovered during code analysis.",
    )
    data_flow_patterns: list[DataFlowPattern] = Field(
        default_factory=list,
        description="Sensitive data flow patterns traced through the codebase for security and compliance analysis.",
    )
    scope_inputs: dict[str, Any] = Field(
        default_factory=dict,
        description="Key normalized intake scope inputs consumed by prerecon.",
    )
    plan_inputs: dict[str, Any] = Field(
        default_factory=dict,
        description="Relevant planner expectations consumed by prerecon.",
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Operator-facing prerecon warnings and confidence gaps that downstream recon should preserve.",
    )
    remediation_hints: list[str] = Field(
        default_factory=list,
        description="Actionable next steps when prerecon inputs are incomplete or weak.",
    )


class DiscoveredHost(BaseModel):
    hostname: str = Field(description="Discovered hostname or subdomain.")
    ip_addresses: list[str] = Field(
        default_factory=list,
        description="Resolved IP addresses for this host.",
    )
    source: str = Field(description="Discovery source: subfinder, dns_query, scope_expansion, or manual.")
    scope_classification: Literal["in_scope", "out_of_scope"] = Field(
        description="Whether this host is within the authorized scope for this run."
    )
    evidence_level: Literal["high", "medium", "low"] = Field(
        description="Confidence level based on the quality of the supporting evidence."
    )
    discovered_at: str = Field(description="ISO 8601 timestamp when this host was discovered.")


class ServiceFingerprint(BaseModel):
    url: str = Field(description="Target URL that was fingerprinted.")
    http_status: int | None = Field(default=None, description="HTTP response status code if available.")
    server_header: str | None = Field(default=None, description="Server header value if present.")
    detected_technologies: list[str] = Field(
        default_factory=list,
        description="Detected web technologies, frameworks, or platforms.",
    )
    title: str | None = Field(default=None, description="HTML page title if available.")
    content_type: str | None = Field(default=None, description="Content-Type header value.")
    tls_enabled: bool = Field(default=False, description="Whether HTTPS/TLS is enabled.")
    redirect_chain: list[str] = Field(
        default_factory=list,
        description="HTTP redirect chain if redirects were followed.",
    )
    evidence_level: Literal["high", "medium", "low"] = Field(
        description="Confidence level based on the quality of the supporting evidence."
    )
    source: str = Field(description="Fingerprinting source: whatweb, httpx, curl, or custom.")


class TLSObservation(BaseModel):
    hostname: str = Field(description="Target hostname for TLS inspection.")
    port: int = Field(default=443, description="Port number where TLS was observed.")
    tls_version: str | None = Field(default=None, description="TLS protocol version (e.g., TLSv1.3).")
    cipher_suite: str | None = Field(default=None, description="Negotiated cipher suite.")
    certificate_subject: str | None = Field(default=None, description="Certificate subject DN.")
    certificate_issuer: str | None = Field(default=None, description="Certificate issuer DN.")
    certificate_valid_from: str | None = Field(default=None, description="Certificate validity start date.")
    certificate_valid_until: str | None = Field(default=None, description="Certificate expiration date.")
    san_entries: list[str] = Field(
        default_factory=list,
        description="Subject Alternative Name entries from the certificate.",
    )
    self_signed: bool = Field(default=False, description="Whether the certificate is self-signed.")
    expired: bool = Field(default=False, description="Whether the certificate is expired.")
    evidence_level: Literal["high", "medium", "low"] = Field(
        description="Confidence level based on the quality of the supporting evidence."
    )


class PortService(BaseModel):
    host: str = Field(description="Target host where the port was scanned.")
    port: int = Field(description="Port number.")
    protocol: str = Field(description="Protocol: tcp or udp.")
    state: str = Field(description="Port state: open, closed, filtered, or unknown.")
    service_name: str | None = Field(default=None, description="Detected service name if available.")
    service_version: str | None = Field(default=None, description="Detected service version if available.")
    service_product: str | None = Field(default=None, description="Detected service product if available.")
    banner: str | None = Field(default=None, description="Service banner if captured.")
    evidence_level: Literal["high", "medium", "low"] = Field(
        description="Confidence level based on the quality of the supporting evidence."
    )
    scan_method: str = Field(description="Scan method: nmap, netcat, or custom.")


class NetworkDiscoveryReport(BaseModel):
    target_url: str = Field(description="Authorized target URL for network discovery.")
    canonical_url: str = Field(description="Normalized canonical URL used for discovery.")
    host: str = Field(description="Normalized host extracted from the target URL.")
    path: str = Field(description="Normalized path extracted from the target URL.")
    discovered_hosts: list[DiscoveredHost] = Field(
        default_factory=list,
        description="Hosts and subdomains discovered during network enumeration.",
    )
    service_fingerprints: list[ServiceFingerprint] = Field(
        default_factory=list,
        description="HTTP service fingerprints and technology detection results.",
    )
    tls_observations: list[TLSObservation] = Field(
        default_factory=list,
        description="TLS/SSL configuration and certificate observations.",
    )
    port_services: list[PortService] = Field(
        default_factory=list,
        description="Port and service discovery results (only when active scanning is enabled).",
    )
    scope_inputs: dict[str, Any] = Field(
        default_factory=dict,
        description="Key normalized scope inputs consumed by netdisc.",
    )
    plan_inputs: dict[str, Any] = Field(
        default_factory=dict,
        description="Relevant planner expectations consumed by netdisc.",
    )
    passive_discovery_enabled: bool = Field(
        description="Whether passive network discovery was enabled for this run."
    )
    active_scanning_enabled: bool = Field(
        default=False,
        description="Whether active port scanning was enabled for this run.",
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Operator-facing warnings and confidence gaps that downstream recon should preserve.",
    )
    remediation_hints: list[str] = Field(
        default_factory=list,
        description="Actionable next steps when network discovery inputs are incomplete or weak.",
    )


class ReconEndpoint(BaseModel):
    method: str = Field(description="HTTP method: GET, POST, PUT, DELETE, PATCH, etc.")
    path: str = Field(description="Route path, e.g. /api/users/{user_id}.")
    required_role: str = Field(description="Minimum role required to call this endpoint: anon, user, admin, etc.")
    object_id_params: list[str] = Field(
        default_factory=list,
        description="Path or query parameters that identify a specific object (IDOR candidates).",
    )
    auth_mechanism: str = Field(description="Auth enforcement code reference, e.g. 'Bearer Token + requireAuth()'.")
    handler_location: str = Field(description="File and line number of the route handler, e.g. 'controllers/users.py:42'.")
    description: str = Field(description="Short description of what this endpoint does.")
    evidence_level: Literal["high", "medium", "low"] = Field(
        description="Confidence in this mapping based on code evidence quality."
    )


class InputVector(BaseModel):
    vector_type: str = Field(
        description="Input type: url_param, post_body, header, cookie, file_upload, graphql_arg, websocket_msg."
    )
    name: str = Field(description="Field or parameter name as it appears in the request.")
    endpoint: str = Field(description="Endpoint this input belongs to, e.g. POST /api/users.")
    location: str = Field(description="File and line number where this input is handled, e.g. 'routes/users.js:55'.")
    validation_present: bool = Field(description="Whether any input validation or sanitization is applied.")
    flows_to_sink: bool = Field(description="Whether this input reaches a dangerous code pattern (sink).")
    evidence_level: Literal["high", "medium", "low"] = Field(
        description="Confidence based on code evidence quality."
    )


class NetworkEntity(BaseModel):
    title: str = Field(description="Human-readable name for this entity, e.g. 'API Server', 'PostgreSQL DB'.")
    entity_type: Literal["Service", "DataStore", "Identity", "ThirdParty", "AdminPlane", "ExternAsset"] = Field(
        description="Category of this network entity."
    )
    zone: Literal["Internet", "Edge", "App", "Data", "Admin", "ThirdParty"] = Field(
        description="Network zone where this entity resides."
    )
    tech: str = Field(description="Technology stack, e.g. 'Node/Express', 'PostgreSQL 15', 'Redis'.")
    data_sensitivity: list[str] = Field(
        default_factory=list,
        description="Data types this entity handles: PII, Tokens, Payments, Secrets, Public.",
    )
    notes: str = Field(default="", description="Additional notes about this entity.")


class NetworkFlow(BaseModel):
    from_entity: str = Field(description="Source entity title.")
    to_entity: str = Field(description="Destination entity title.")
    channel: str = Field(description="Communication channel: HTTPS, TCP, Message, File, gRPC.")
    path_port: str = Field(description="Path or port qualifier, e.g. ':443 /api/auth' or ':5432'.")
    guards: list[str] = Field(
        default_factory=list,
        description="Security controls on this flow, e.g. 'auth:user', 'vpc-only', 'mTLS'.",
    )
    touches: list[str] = Field(
        default_factory=list,
        description="Data sensitivity types that flow through this channel: PII, Tokens, Payments, Secrets.",
    )


class AuthorizationGuard(BaseModel):
    name: str = Field(description="Guard identifier, e.g. 'auth:user', 'ownership:user', 'require_admin'.")
    category: str = Field(description="Guard category: Auth, Network, Protocol, Authorization, ObjectOwnership.")
    statement: str = Field(description="Human-readable description of what this guard enforces.")


class PrivilegeRole(BaseModel):
    name: str = Field(description="Role name, e.g. anon, user, moderator, admin, superadmin.")
    privilege_level: int = Field(description="Privilege level 0–10, where 0 is public and 10 is superadmin.")
    scope: str = Field(description="Role scope: Global, Org, Team, Resource.")
    middleware_location: str = Field(
        default="", description="File and line of the middleware or guard enforcing this role."
    )
    default_landing: str = Field(default="", description="Default landing route after login for this role.")


class AuthzCandidate(BaseModel):
    candidate_type: Literal["horizontal", "vertical", "context_based"] = Field(
        description="Horizontal: same-role object access. Vertical: privilege escalation. Context: workflow bypass."
    )
    priority: Literal["high", "medium", "low"] = Field(
        description="Testing priority based on data sensitivity and object exposure."
    )
    endpoint_pattern: str = Field(description="Endpoint pattern where this candidate applies, e.g. '/api/orders/{id}'.")
    object_id_param: str | None = Field(
        default=None, description="The object ID parameter name relevant to this candidate."
    )
    data_type: str = Field(description="Type of data exposed: financial, user_data, admin_config, health_records, etc.")
    notes: str = Field(description="Rationale for why this is a candidate and how to test it.")


class ReconReport(BaseModel):
    target_url: str = Field(description="Authorized target URL for this recon run.")
    canonical_url: str = Field(description="Normalized canonical URL.")
    host: str = Field(description="Normalized host extracted from the target URL.")
    path: str = Field(description="Normalized path extracted from the target URL.")
    executive_summary: str = Field(
        default="", description="High-level summary of application purpose, tech stack, and primary attack surface."
    )
    frontend_tech: list[str] = Field(default_factory=list, description="Detected frontend technologies and frameworks.")
    backend_tech: list[str] = Field(default_factory=list, description="Detected backend technologies and frameworks.")
    infrastructure: list[str] = Field(
        default_factory=list, description="Infrastructure components: CDN, load balancers, cloud services."
    )
    endpoints: list[ReconEndpoint] = Field(
        default_factory=list, description="Complete inventory of network-accessible API endpoints with auth requirements."
    )
    input_vectors: list[InputVector] = Field(
        default_factory=list,
        description="All user-controlled input vectors with file locations and sink flow status.",
    )
    network_entities: list[NetworkEntity] = Field(
        default_factory=list, description="Services, datastores, and external entities in the network map."
    )
    network_flows: list[NetworkFlow] = Field(
        default_factory=list, description="Communication flows between network entities."
    )
    authorization_guards: list[AuthorizationGuard] = Field(
        default_factory=list, description="Security guards and authorization controls identified in the codebase."
    )
    privilege_roles: list[PrivilegeRole] = Field(
        default_factory=list, description="User roles with privilege levels and code locations."
    )
    authz_candidates: list[AuthzCandidate] = Field(
        default_factory=list,
        description="Pre-prioritized authorization vulnerability candidates for the vuln phase.",
    )
    live_observations: list[str] = Field(
        default_factory=list,
        description="Observations from live browser interaction: redirects, auth prompts, observed endpoints.",
    )
    scope_inputs: dict[str, Any] = Field(
        default_factory=dict, description="Key scope inputs consumed from the intake phase."
    )
    plan_inputs: dict[str, Any] = Field(
        default_factory=dict, description="Relevant planner expectations consumed by recon."
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Operator-facing warnings about weak evidence, gaps, or ambiguities.",
    )
    remediation_hints: list[str] = Field(
        default_factory=list,
        description="Concrete next steps to strengthen recon or improve coverage.",
    )


class ArtifactEntry(BaseModel):
    path: str = Field(description="Run-relative path to a generated artifact file.")
    sha256: str = Field(description="SHA-256 digest of the artifact contents for reproducibility checks.")


class ArtifactIndex(BaseModel):
    files: list[ArtifactEntry] = Field(
        default_factory=list,
        description="Deterministically sorted list of generated artifacts and their content hashes.",
    )


class ManifestState(BaseModel):
    workspace: str = Field(description="Workspace root or workspace key used to store this run.")
    run_id: str = Field(description="Unique identifier for this run within the workspace.")
    url: str = Field(description="Target URL associated with the run.")
    repo_path: str = Field(description="Repository path for the authorized target under the local repos directory.")
    workflow_id: str | None = Field(default=None, description="Temporal workflow identifier associated with this run.")
    current_phase: str | None = Field(default=None, description="Phase currently executing or most recently executed.")
    completed_phases: list[str] = Field(
        default_factory=list,
        description="Ordered list of phases that completed successfully for this run.",
    )
    waiting_for_config: bool = Field(
        default=False,
        description="Whether execution is blocked pending operator configuration updates.",
    )
    waiting_reason: str | None = Field(default=None, description="Operator-facing explanation for the current waiting state.")
    paused: bool = Field(default=False, description="Whether execution is intentionally paused by operator signal.")
    canceled: bool = Field(default=False, description="Whether the run has been canceled and should not continue.")
    last_error: str | None = Field(default=None, description="Most recent terminal or non-retryable error message, if any.")


class WorkflowInput(BaseModel):
    workspace: str = Field(description="Workspace root or workspace key where run artifacts should be stored.")
    repo_path: str = Field(description="Authorized target repository path under the local repos directory.")
    url: str = Field(description="Target URL for the Adversa run.")
    effective_config_path: str = Field(description="Resolved configuration file path used for this execution.")
    safe_mode: bool = Field(description="Whether the run is restricted to non-destructive safe-mode behavior.")
    run_id: str = Field(description="Unique identifier assigned to this workflow run.")
    force: bool = Field(default=False, description="Whether to re-run phases even when valid artifacts already exist.")


class WorkflowStatus(BaseModel):
    current_phase: str | None = Field(default=None, description="Phase currently executing or most recently executed.")
    completed_phases: list[str] = Field(
        default_factory=list,
        description="Ordered list of phases that have completed or been deterministically skipped.",
    )
    artifact_index_path: str | None = Field(
        default=None,
        description="Workspace-relative path to the artifact index for this run.",
    )
    last_error: str | None = Field(default=None, description="Most recent terminal or non-retryable error message, if any.")
    waiting_reason: str | None = Field(default=None, description="Operator-facing explanation for why the workflow is waiting.")
    waiting_for_config: bool = Field(
        default=False,
        description="Whether the workflow is blocked pending configuration changes.",
    )
    paused: bool = Field(default=False, description="Whether the workflow is paused by signal and waiting to resume.")
    canceled: bool = Field(default=False, description="Whether the workflow has been canceled.")


PHASES = ["intake", "prerecon", "netdisc", "recon", "vuln", "report"]


def schema_export(target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    for model in [
        EvidenceRef,
        PhaseOutput,
        PlanBudget,
        PhaseExpectation,
        PlanWarning,
        RunPlan,
        ScopeContract,
        IntakeCoverage,
        FrameworkSignal,
        RouteSurface,
        AuthSignal,
        SchemaFile,
        ExternalIntegration,
        SecurityConfigSignal,
        VulnerabilitySink,
        DataFlowPattern,
        PreReconReport,
        DiscoveredHost,
        ServiceFingerprint,
        TLSObservation,
        PortService,
        NetworkDiscoveryReport,
        ReconEndpoint,
        InputVector,
        NetworkEntity,
        NetworkFlow,
        AuthorizationGuard,
        PrivilegeRole,
        AuthzCandidate,
        ReconReport,
        ArtifactIndex,
        ManifestState,
        WorkflowInput,
        WorkflowStatus,
    ]:
        path = target_dir / f"{model.__name__}.json"
        path.write_text(json.dumps(model.model_json_schema(), indent=2, sort_keys=True), encoding="utf-8")
