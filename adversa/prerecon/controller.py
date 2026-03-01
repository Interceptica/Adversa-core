from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from deepagents import create_deep_agent
from deepagents.backends.filesystem import FilesystemBackend

from adversa.agent_runtime.context import AdversaAgentContext
from adversa.agent_runtime.middleware import (
    load_rules_middleware,
    load_runtime_boundary_middleware,
)
from adversa.config.load import load_config
from adversa.llm.providers import ProviderClient
from adversa.security.scope import ScopeViolationError, ensure_repo_in_repos_root
from adversa.state.models import (
    AuthSignal,
    DataFlowPattern,
    ExternalIntegration,
    FrameworkSignal,
    PreReconReport,
    RouteSurface,
    SchemaFile,
    SecurityConfigSignal,
    VulnerabilitySink,
)


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
            load_runtime_boundary_middleware(
                context, allowed_repo_virtual_prefix=inputs.repo_virtual_path
            ),
        ],
        subagents=_prerecon_subagents(),
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


def _load_intake_inputs(
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
            "rules_summary": scope_payload.get("rules_summary", {}),
            "warnings": scope_payload.get("warnings", []),
        }

    if plan_path.exists():
        plan_payload = json.loads(plan_path.read_text(encoding="utf-8"))
        prerecon_expectation = next(
            (
                item
                for item in plan_payload.get("phase_expectations", [])
                if item.get("phase") == "prerecon"
            ),
            {},
        )
        plan_inputs = {
            "selected_analyzers": prerecon_expectation.get("selected_analyzers", []),
            "required_artifacts": prerecon_expectation.get("required_artifacts", []),
            "constraints": prerecon_expectation.get("constraints", []),
            "goals": prerecon_expectation.get("goals", []),
        }

    return scope_inputs, plan_inputs


def _prerecon_subagents() -> list[dict[str, Any]]:
    """
    Returns specialized subagents for comprehensive prerecon analysis aligned with Shannon's architecture.
    
    Phase 1: Architecture & Entry Points (parallel execution)
    Phase 2: Security & Vulnerability Analysis (uses Phase 1 results)
    """
    return [
        {
            "name": "architecture-scanner",
            "description": "Specialized subagent for mapping project structure, technology stack, frameworks, and security-relevant configurations.",
            "prompt": (
                "You are an architecture analysis specialist for security-focused code reconnaissance.\n"
                "Your mission: Map the codebase structure, identify frameworks/runtimes, locate entry points, and find security configurations.\n\n"
                "Focus areas:\n"
                "1. Project structure and organization patterns\n"
                "2. Framework detection (Express, FastAPI, Django, Rails, Next.js, Gin, etc.)\n"
                "3. Entry points (main files, server bootstrapping, route registration)\n"
                "4. Configuration files (.env, config.*, settings.*, docker-compose.yml)\n"
                "5. Security middleware (CORS, CSP, rate limiting, auth middleware)\n"
                "6. Dependency analysis for security-relevant packages\n\n"
                "Evidence quality:\n"
                "- HIGH: Direct code evidence (import statements, explicit framework usage)\n"
                "- MEDIUM: Configuration patterns and naming conventions\n"
                "- LOW: Dependency-only inferences\n\n"
                "Scope discipline:\n"
                "- IN-SCOPE: Network-reachable code (routes, APIs, webhooks, handlers)\n"
                "- OUT-OF-SCOPE: CLI tools, build scripts, test harnesses, dev utilities\n\n"
                "Return concrete file paths, line numbers, and code snippets for all findings.\n"
                "If evidence is weak, explicitly note the uncertainty.\n"
            ),
        },
        {
            "name": "entry-point-mapper",
            "description": "Specialized subagent for discovering and cataloging all application routes, APIs, endpoints, and webhook handlers.",
            "prompt": (
                "You are an entry point discovery specialist for security reconnaissance.\n"
                "Your mission: Find every network-reachable entry point into the application.\n\n"
                "Discovery targets:\n"
                "1. HTTP routes (GET, POST, PUT, DELETE, PATCH, OPTIONS)\n"
                "2. API endpoints (REST, GraphQL, gRPC, WebSocket)\n"
                "3. Webhook receivers and callback handlers\n"
                "4. File upload/download handlers\n"
                "5. Admin/management interfaces\n"
                "6. Health check and status endpoints\n"
                "7. Authentication endpoints (login, logout, OAuth callbacks, token refresh)\n"
                "8. Static file serving and public assets\n\n"
                "For each entry point, document:\n"
                "- Full route path and HTTP method(s)\n"
                "- Kind (page, api, graphql, websocket, admin, health, auth, upload, webhook)\n"
                "- File location with line numbers\n"
                "- Authentication requirements (public vs protected)\n"
                "- Input handling (query params, body, headers, files)\n"
                "- Evidence level (HIGH for explicit routes, MEDIUM for framework conventions, LOW for assumptions)\n"
                "- Scope classification (in_scope for network-reachable, out_of_scope for CLI/local-only)\n\n"
                "Search patterns for common frameworks:\n"
                "- Express: app.get/post/put/delete, router.METHOD\n"
                "- FastAPI: @app.get/post, @router.get/post\n"
                "- Django: path(), re_path(), urls.py patterns\n"
                "- Rails: routes.rb, resources, get/post/put/delete\n"
                "- Next.js: pages/*, app/*, pages/api/*\n"
                "- Gin: router.GET/POST, engine.Handle\n\n"
                "Return only evidence-backed routes. Do not fabricate or infer routes without code evidence.\n"
            ),
        },
        {
            "name": "sink-hunter",
            "description": "Specialized subagent for identifying XSS, injection, SSRF, deserialization, and path traversal vulnerability sinks.",
            "prompt": (
                "You are a vulnerability sink discovery specialist for security analysis.\n"
                "Your mission: Identify dangerous code patterns where user input could lead to security vulnerabilities.\n\n"
                "Critical sink categories to hunt:\n\n"
                "1. XSS (Cross-Site Scripting) Sinks:\n"
                "   - DOM manipulation: innerHTML, outerHTML, document.write, insertAdjacentHTML\n"
                "   - Unsafe template rendering: dangerouslySetInnerHTML, v-html, [innerHTML]\n"
                "   - Direct HTML construction from user input\n"
                "   - JavaScript contexts: eval() with user data, setTimeout/setInterval with strings\n\n"
                "2. SQL Injection Sinks:\n"
                "   - Raw SQL with string concatenation or f-strings\n"
                "   - ORM bypasses: .raw(), .execute() with unparameterized queries\n"
                "   - Dynamic table/column names from user input\n"
                "   - Stored procedures with unvalidated parameters\n\n"
                "3. Command Injection Sinks:\n"
                "   - System calls: exec, spawn, shell_exec, system, popen, subprocess.run with shell=True\n"
                "   - Shell commands with user-controlled arguments\n"
                "   - Template injection in command strings\n\n"
                "4. SSRF (Server-Side Request Forgery) Sinks:\n"
                "   - HTTP client calls with user-controlled URLs\n"
                "   - URL fetchers, link preview generators\n"
                "   - Webhook dispatchers\n"
                "   - Image/file loading from URLs\n"
                "   - XML/YAML parsers with external entity resolution enabled\n\n"
                "5. Deserialization Sinks:\n"
                "   - Unsafe deserialization: pickle.loads, yaml.load (non-safe), unserialize\n"
                "   - JSON parsing with reviver/custom classes\n"
                "   - XML deserialization with type handling\n\n"
                "6. Path Traversal Sinks:\n"
                "   - File operations with user paths: open(), readFile(), fs.read()\n"
                "   - Directory traversal in file downloads\n"
                "   - Static file serving without path normalization\n\n"
                "For each sink, document:\n"
                "- Sink type (xss, sql_injection, command_injection, ssrf, deserialization, path_traversal)\n"
                "- Exact file location and line number\n"
                "- Code context (5-10 lines showing the dangerous pattern)\n"
                "- Potential input sources (route params, query strings, request body, headers)\n"
                "- Mitigation status (whether sanitization/validation is present)\n"
                "- Evidence level (HIGH for clear dangerous usage, MEDIUM for potentially mitigated, LOW for uncertain)\n"
                "- Scope classification (in_scope if network-reachable, out_of_scope if CLI/test only)\n\n"
                "Search strategy:\n"
                "1. Use targeted grep patterns for dangerous functions\n"
                "2. Trace user input flow from routes to sinks\n"
                "3. Check for presence of sanitization/validation middleware\n"
                "4. Prioritize in_scope (network-reachable) sinks over out_of_scope\n\n"
                "Return only verified sinks with strong evidence. Do not fabricate vulnerabilities.\n"
            ),
        },
        {
            "name": "data-auditor",
            "description": "Specialized subagent for tracing sensitive data flows through the application for security and compliance analysis.",
            "prompt": (
                "You are a data security and compliance specialist for application analysis.\n"
                "Your mission: Trace how sensitive data moves through the codebase for security and regulatory compliance.\n\n"
                "Sensitive data categories to trace:\n\n"
                "1. Credentials & Secrets:\n"
                "   - Passwords, password hashes, salts\n"
                "   - API keys, access tokens, refresh tokens\n"
                "   - Session identifiers, JWT secrets\n"
                "   - Encryption keys, private keys, certificates\n"
                "   - Database credentials, service account keys\n"
                "   - OAuth tokens, API secrets\n\n"
                "2. Personal Identifiable Information (PII):\n"
                "   - Email addresses, phone numbers\n"
                "   - Full names, addresses, birthdates\n"
                "   - Social security numbers, national IDs\n"
                "   - IP addresses, geolocation data\n"
                "   - User preferences, behavioral data\n"
                "   - Profile photos, biometric data\n\n"
                "3. Financial Data:\n"
                "   - Credit card numbers, CVV codes, expiry dates\n"
                "   - Bank account numbers, routing numbers\n"
                "   - Payment tokens, transaction history\n"
                "   - Billing addresses, invoice data\n\n"
                "4. Health Records (if applicable):\n"
                "   - Medical records, diagnoses, prescriptions\n"
                "   - Health insurance information\n"
                "   - Biometric health data (fitness, vitals)\n\n"
                "For each data type, trace the complete flow:\n\n"
                "1. Sources (where data enters the system):\n"
                "   - Form inputs, API request bodies\n"
                "   - OAuth providers, third-party integrations\n"
                "   - File uploads, imports\n"
                "   - Webhooks, external APIs\n\n"
                "2. Sinks (where data is consumed/stored):\n"
                "   - Database tables and columns\n"
                "   - Cache stores (Redis, Memcached)\n"
                "   - Session storage\n"
                "   - File system locations\n"
                "   - Third-party services (analytics, CRMs, payment processors)\n"
                "   - Logs (warn if sensitive data is logged)\n\n"
                "3. Encryption status:\n"
                "   - encrypted: Data protected in transit (TLS) and at rest (database encryption)\n"
                "   - plaintext: No encryption detected\n"
                "   - mixed: Some protections but not comprehensive\n"
                "   - unknown: Cannot determine from code inspection\n\n"
                "4. Compliance concerns:\n"
                "   - GDPR (EU data protection): right to deletion, consent, data portability\n"
                "   - HIPAA (US health data): PHI handling, encryption, audit logs\n"
                "   - PCI-DSS (payment cards): tokenization, encryption, scope reduction\n"
                "   - SOX (financial reporting): data integrity, access controls\n"
                "   - CCPA (California privacy): data disclosure, opt-out\n\n"
                "Document each pattern:\n"
                "- Data type (credentials, pii, financial, health_records)\n"
                "- Sources (file locations where data is collected)\n"
                "- Sinks (file locations where data is stored/transmitted)\n"
                "- Encryption status (encrypted, plaintext, mixed, unknown)\n"
                "- Storage locations (database, file, cache, session, third_party)\n"
                "- Compliance concerns (gdpr, hipaa, pci_dss, sox, ccpa)\n"
                "- Evidence level (HIGH for explicit handling, MEDIUM for inferred, LOW for assumed)\n\n"
                "Search strategy:\n"
                "1. Identify database schema files for sensitive columns\n"
                "2. Trace form fields and API endpoints collecting sensitive data\n"
                "3. Check for encryption libraries usage\n"
                "4. Look for password hashing (bcrypt, argon2, scrypt)\n"
                "5. Check for PCI-compliant tokenization for payment data\n"
                "6. Verify GDPR compliance features (data export, deletion)\n\n"
                "Return only evidence-backed data flows. Flag compliance gaps as warnings.\n"
            ),
        },
    ]


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
        "- Use specialized subagents for comprehensive analysis:\n"
        "  * architecture-scanner: Framework detection, entry points, configuration analysis\n"
        "  * entry-point-mapper: Complete route and API endpoint discovery\n"
        "  * sink-hunter: Vulnerability sink identification (XSS, injection, SSRF, deserialization, path traversal)\n"
        "  * data-auditor: Sensitive data flow tracing and compliance analysis (PII, credentials, financial data)\n"
        "- Use deep filesystem tools only under the authorized repo_virtual_path.\n"
        "- Do not fabricate frameworks, routes, auth flows, or vulnerability findings.\n"
        "- Prefer concrete file-backed evidence with file paths and line numbers.\n"
        "- Produce a complete structured PreReconReport including vulnerability_sinks and data_flow_patterns.\n"
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
            "framework_signals": _dedupe_framework_signals(report.framework_signals),
            "candidate_routes": _dedupe_candidate_routes(report.candidate_routes),
            "auth_signals": _dedupe_auth_signals(report.auth_signals),
            "schema_files": _dedupe_schema_files(report.schema_files),
            "external_integrations": _dedupe_external_integrations(report.external_integrations),
            "security_config": _dedupe_security_config(report.security_config),
            "vulnerability_sinks": _dedupe_vulnerability_sinks(report.vulnerability_sinks),
            "data_flow_patterns": _dedupe_data_flow_patterns(report.data_flow_patterns),
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


def _dedupe_framework_signals(items: list[FrameworkSignal]) -> list[FrameworkSignal]:
    deduped = {
        (item.name, item.evidence, item.evidence_level): item
        for item in items
    }
    return sorted(deduped.values(), key=lambda item: (item.name, item.evidence, item.evidence_level))[:20]


def _dedupe_candidate_routes(items: list[RouteSurface]) -> list[RouteSurface]:
    deduped = {
        (item.path, item.kind, item.scope_classification, item.evidence, item.evidence_level): item
        for item in items
    }
    return sorted(
        deduped.values(),
        key=lambda item: (item.path, item.kind, item.scope_classification, item.evidence_level, item.evidence),
    )[:50]


def _dedupe_auth_signals(items: list[AuthSignal]) -> list[AuthSignal]:
    deduped = {
        (item.signal, item.location, item.evidence, item.evidence_level): item
        for item in items
    }
    return sorted(deduped.values(), key=lambda item: (item.signal, item.location, item.evidence_level))[:30]


def _dedupe_schema_files(items: list[SchemaFile]) -> list[SchemaFile]:
    deduped = {
        (item.path, item.schema_type, item.evidence_level): item
        for item in items
    }
    return sorted(deduped.values(), key=lambda item: (item.path, item.schema_type, item.evidence_level))[:30]


def _dedupe_external_integrations(items: list[ExternalIntegration]) -> list[ExternalIntegration]:
    deduped = {
        (item.name, item.location, item.kind, item.evidence, item.evidence_level): item
        for item in items
    }
    return sorted(
        deduped.values(),
        key=lambda item: (item.name, item.location, item.kind, item.evidence_level),
    )[:30]


def _dedupe_security_config(items: list[SecurityConfigSignal]) -> list[SecurityConfigSignal]:
    deduped = {
        (item.signal, item.location, item.evidence, item.evidence_level): item
        for item in items
    }
    return sorted(deduped.values(), key=lambda item: (item.signal, item.location, item.evidence_level))[:30]


def _dedupe_vulnerability_sinks(items: list[VulnerabilitySink]) -> list[VulnerabilitySink]:
    """
    Deduplicate vulnerability sinks while preserving all meaningful fields.
    
    Two sinks are considered duplicates only if ALL significant fields match:
    sink_type, location, context, input_sources, mitigation_present, evidence_level, scope_classification
    """
    deduped = {
        (
            item.sink_type,
            item.location,
            item.context,
            tuple(sorted(item.input_sources)),
            item.mitigation_present,
            item.evidence_level,
            item.scope_classification,
        ): item
        for item in items
    }
    return sorted(
        deduped.values(),
        key=lambda item: (
            item.scope_classification,  # in_scope first
            item.sink_type,
            item.evidence_level,  # high, medium, low
            item.location,
        ),
    )[:50]


def _dedupe_data_flow_patterns(items: list[DataFlowPattern]) -> list[DataFlowPattern]:
    """
    Deduplicate data flow patterns while preserving compliance and storage metadata.
    
    Two patterns are considered duplicates only if ALL significant fields match:
    data_type, sources, sinks, encryption_status, storage_locations, compliance_concerns
    """
    deduped = {
        (
            item.data_type,
            tuple(sorted(item.sources)),
            tuple(sorted(item.sinks)),
            item.encryption_status,
            tuple(sorted(item.storage_locations)),
            tuple(sorted(item.compliance_concerns)),
        ): item
        for item in items
    }
    return sorted(
        deduped.values(),
        key=lambda item: (
            item.data_type,
            item.encryption_status,  # encrypted, plaintext, mixed, unknown
            item.evidence_level,
        ),
    )[:30]
