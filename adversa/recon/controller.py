"""Recon phase controller.

Orchestrates the recon agent: loads upstream markdown artifacts from prerecon and
netdisc phases, spins up an isolated Playwright browser session via MCP, builds a
DeepAgent with four code-analysis subagents + browser tools, and returns a validated
ReconReport.
"""

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
from adversa.agent_runtime.browser import RECON_BROWSER_TOOLS, playwright_tools_context
from adversa.security.scope import ScopeViolationError, ensure_repo_in_repos_root
from adversa.state.models import ReconReport
from adversa.utils.markdown import load_upstream_markdown


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RECON_PROMPT_PATH = PROJECT_ROOT / "adversa" / "prompts" / "recon.txt"


@dataclass(frozen=True)
class ReconInputs:
    target_url: str
    canonical_url: str
    repo_path: str
    repo_virtual_path: str
    host: str
    path: str
    prerecon_markdown: str
    netdisc_markdown: str
    scope_inputs: dict[str, Any]
    plan_inputs: dict[str, Any]


async def build_recon_report(
    *,
    workspace_root: str,
    workspace: str,
    run_id: str,
    repo_path: str,
    url: str,
    config_path: str,
) -> ReconReport:
    context = AdversaAgentContext(
        phase="recon",
        url=url,
        repo_path=repo_path,
        workspace=workspace,
        run_id=run_id,
        workspace_root=workspace_root,
        config_path=config_path,
    )
    cfg = load_config(config_path)
    inputs = load_recon_inputs(
        workspace_root=workspace_root,
        workspace=workspace,
        run_id=run_id,
        repo_path=repo_path,
        url=url,
        config_path=config_path,
    )
    model = ProviderClient(cfg.provider).build_chat_model(temperature=0)

    async with playwright_tools_context(allowed_tools=RECON_BROWSER_TOOLS, headless=True, run_id=run_id) as browser_tools:
        agent = create_deep_agent(
            model=model,
            tools=browser_tools,
            system_prompt=RECON_PROMPT_PATH.read_text(encoding="utf-8"),
            middleware=[
                load_rules_middleware(context),
                load_runtime_boundary_middleware(
                    context, allowed_repo_virtual_prefix=inputs.repo_virtual_path
                ),
            ],
            subagents=_recon_subagents(),
            response_format=ReconReport,
            backend=FilesystemBackend(root_dir=PROJECT_ROOT, virtual_mode=True),
            name="adversa-recon",
        )
        result = await agent.ainvoke(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": _build_recon_request(inputs),
                    }
                ]
            }
        )

    structured = result.get("structured_response")
    if structured is None:
        raise ValueError("DeepAgent recon run did not return a structured_response.")
    if isinstance(structured, ReconReport):
        report = structured
    else:
        report = ReconReport.model_validate(structured)
    return _normalize_report(report, inputs)


def load_recon_inputs(
    *,
    workspace_root: str,
    workspace: str,
    run_id: str,
    repo_path: str,
    url: str,
    config_path: str,
) -> ReconInputs:
    cfg = load_config(config_path)
    config_parent = Path(config_path).resolve().parent
    repos_root = Path(cfg.run.repos_root)
    if not repos_root.is_absolute():
        repos_root = (config_parent / repos_root).resolve()

    try:
        repo_resolved = ensure_repo_in_repos_root(Path(repo_path), repos_root)
    except ScopeViolationError as exc:
        raise ValueError(
            f"Recon cannot inspect repo '{repo_path}'. Ensure it is inside '{repos_root}'."
        ) from exc
    try:
        repo_relative_to_project = repo_resolved.relative_to(PROJECT_ROOT)
    except ValueError as exc:
        raise ValueError(
            f"Recon repo '{repo_resolved}' must live under the Adversa project root '{PROJECT_ROOT}'."
        ) from exc

    run_dir = Path(workspace_root) / workspace / run_id
    prerecon_markdown = load_upstream_markdown(run_dir / "prerecon", "pre_recon_analysis.md")
    netdisc_markdown = load_upstream_markdown(run_dir / "netdisc", "network_discovery.md")

    scope_inputs, plan_inputs = _load_phase_inputs(
        workspace_root=workspace_root,
        workspace=workspace,
        run_id=run_id,
    )
    parsed = urlparse(url)
    repo_virtual_path = "/" + repo_relative_to_project.as_posix()
    return ReconInputs(
        target_url=url,
        canonical_url=_canonical_url(url),
        repo_path=repo_path,
        repo_virtual_path=repo_virtual_path,
        host=(parsed.hostname or "").lower(),
        path=parsed.path or "/",
        prerecon_markdown=prerecon_markdown,
        netdisc_markdown=netdisc_markdown,
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
        recon_expectation = next(
            (
                item
                for item in plan_payload.get("phase_expectations", [])
                if item.get("phase") == "recon"
            ),
            {},
        )
        plan_inputs = {
            "selected_analyzers": recon_expectation.get("selected_analyzers", []),
            "required_artifacts": recon_expectation.get("required_artifacts", []),
            "constraints": recon_expectation.get("constraints", []),
            "goals": recon_expectation.get("goals", []),
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


def _build_recon_request(inputs: ReconInputs) -> str:
    prerecon_section = (
        inputs.prerecon_markdown
        if inputs.prerecon_markdown
        else "_Pre-recon report not available — run prerecon phase first._"
    )
    netdisc_section = (
        inputs.netdisc_markdown
        if inputs.netdisc_markdown
        else "_Network discovery report not available — run netdisc phase first._"
    )
    return (
        "Run a recon (attack surface mapping) analysis for Adversa.\n\n"
        "Authorized target:\n"
        f"- target_url: {inputs.target_url}\n"
        f"- canonical_url: {inputs.canonical_url}\n"
        f"- repo_virtual_path: {inputs.repo_virtual_path}\n"
        f"- normalized_host: {inputs.host}\n"
        f"- normalized_path: {inputs.path}\n"
        "\nIntake scope inputs:\n"
        f"{json.dumps(inputs.scope_inputs, indent=2, sort_keys=True)}\n"
        "\nPlanner recon inputs:\n"
        f"{json.dumps(inputs.plan_inputs, indent=2, sort_keys=True)}\n"
        "\n== PRE-RECON REPORT ==\n"
        f"{prerecon_section}\n"
        "\n== NETWORK DISCOVERY REPORT ==\n"
        f"{netdisc_section}\n"
        "\nRequirements:\n"
        "- Use all four specialized subagents for parallel code analysis:\n"
        "  * route-mapper: Deep endpoint-to-handler mapping with auth requirements\n"
        "  * auth-architect: Auth flows, session management, role hierarchy, authorization guards\n"
        "  * input-tracer: All user-controlled input vectors with file locations\n"
        "  * network-mapper: Service dependencies, external integrations, entity/flow mapping\n"
        "- Use browser tools to verify top endpoints and observe live behavior.\n"
        "- Only navigate to the authorized target_url and hosts from the network discovery report.\n"
        "- Do not fabricate endpoints, roles, or auth flows without code evidence.\n"
        "- Produce a complete structured ReconReport including authz_candidates and live_observations.\n"
        "- If something is unknown, leave it out of lists and explain in warnings/remediation_hints.\n"
    )


def _recon_subagents() -> list[dict[str, Any]]:
    return [
        {
            "name": "route-mapper",
            "description": (
                "Specialist for deep API endpoint discovery: traces routes to handlers, "
                "maps auth middleware per route, identifies object ID parameters."
            ),
            "prompt": (
                "You are a route-to-handler mapping specialist for security reconnaissance.\n"
                "Your mission: Build a complete inventory of network-accessible endpoints with precise auth requirements.\n\n"
                "For each endpoint, determine:\n"
                "1. HTTP method and exact path pattern (including path parameters like {user_id})\n"
                "2. Handler file and line number\n"
                "3. Auth middleware applied to this specific route (not just the router group)\n"
                "4. Required role: public/anon, authenticated user, specific role (admin, moderator, etc.)\n"
                "5. Object ID parameters — path/query params that identify a specific resource (IDOR risk)\n"
                "6. Short description of what the endpoint does\n\n"
                "Search patterns by framework:\n"
                "- Express: router.get/post/put/delete, app.METHOD, check for middleware args before handler\n"
                "- FastAPI: @app.get/post, @router.METHOD, check Depends() for auth\n"
                "- Django: urlpatterns, path(), check @login_required, @permission_required decorators\n"
                "- Rails: routes.rb resources/get/post, check before_action filters\n"
                "- Next.js: pages/api/*, app/api/*, check getServerSideProps auth\n"
                "- Spring: @GetMapping/@PostMapping, check @PreAuthorize, @Secured\n\n"
                "Evidence levels:\n"
                "- HIGH: Route definition + middleware code visible at handler\n"
                "- MEDIUM: Route visible but auth inferred from router group or convention\n"
                "- LOW: Route inferred from framework convention without explicit registration\n\n"
                "Return only routes with code evidence. Note ambiguous auth in the parent agent's warnings.\n"
            ),
        },
        {
            "name": "auth-architect",
            "description": (
                "Specialist for authentication flows, session management, role hierarchy, "
                "privilege storage, and authorization guard mapping."
            ),
            "prompt": (
                "You are an authentication and authorization architecture specialist.\n"
                "Your mission: Map the complete auth system — from login to privilege enforcement.\n\n"
                "Analyze:\n"
                "1. Authentication mechanisms: JWT, session cookies, API keys, OAuth/OIDC, basic auth\n"
                "   - Token creation: where are tokens issued, signed, and with what claims?\n"
                "   - Token validation: middleware file and line, what claims are checked?\n"
                "   - Session storage: cookies (flags: httpOnly, secure, sameSite), Redis, database\n"
                "   - Expiry and refresh: token TTL, refresh token flow\n\n"
                "2. Role/privilege system:\n"
                "   - How are roles stored? (JWT claim, database column, session key)\n"
                "   - How are roles assigned? (registration, admin panel, seed data)\n"
                "   - What roles exist? (list all found in code: anon, user, admin, etc.)\n"
                "   - Privilege level: assign 0–10 (0=public, 5=authenticated user, 8=moderator, 10=superadmin)\n"
                "   - Middleware location: exact file:line where role is enforced\n\n"
                "3. Authorization guards:\n"
                "   - Named middleware functions that enforce access (e.g. requireAuth, isAdmin, checkOwnership)\n"
                "   - Object ownership checks (does handler verify user owns the resource?)\n"
                "   - Network guards (IP allowlists, VPC-only routes)\n\n"
                "4. Role switching / impersonation:\n"
                "   - Any admin-as-user or impersonation features?\n"
                "   - Sudo/elevation flows?\n\n"
                "Evidence levels:\n"
                "- HIGH: Explicit code showing token claims, role checks, guard functions\n"
                "- MEDIUM: Config patterns, named middleware with standard conventions\n"
                "- LOW: Inferred from dependencies or naming alone\n\n"
                "Return only auth patterns with code evidence. Prefer precision over completeness.\n"
            ),
        },
        {
            "name": "input-tracer",
            "description": (
                "Specialist for cataloging all user-controlled input vectors "
                "with file locations, validation status, and sink flow analysis."
            ),
            "prompt": (
                "You are an input surface mapping specialist for security reconnaissance.\n"
                "Your mission: Catalog every user-controlled input vector with its code location and risk profile.\n\n"
                "Input vector types to find:\n"
                "1. URL parameters: path variables ({id}, :id) and query strings (?search=, ?filter=)\n"
                "2. POST body fields: JSON body fields, form fields, multipart form data\n"
                "3. HTTP headers: custom headers used as input (X-User-Id, X-Tenant, X-Forwarded-For)\n"
                "4. Cookies: cookies read as application logic input (not just session auth)\n"
                "5. File upload content: file name, file content, content-type header\n"
                "6. GraphQL arguments: query/mutation arguments\n"
                "7. WebSocket messages: message fields processed by handlers\n\n"
                "For each input vector:\n"
                "- vector_type: url_param, post_body, header, cookie, file_upload, graphql_arg, websocket_msg\n"
                "- name: exact field/parameter name\n"
                "- endpoint: which endpoint receives this input (e.g. POST /api/users)\n"
                "- location: file:line where this input is first read/extracted\n"
                "- validation_present: true if any sanitization, validation, or schema parsing is applied\n"
                "- flows_to_sink: true if this input reaches a dangerous pattern (SQL query, shell command,\n"
                "  HTML render, file path, external URL, deserialization) — cross-reference with pre-recon sinks\n\n"
                "Evidence levels:\n"
                "- HIGH: Input read from request + usage clearly traced to handler or sink\n"
                "- MEDIUM: Input found in schema/validator but trace to sink is partial\n"
                "- LOW: Input inferred from framework convention without explicit extraction code\n\n"
                "Focus on in-scope (network-reachable) inputs. Skip CLI args, env vars, build-time config.\n"
                "Return only inputs with code evidence. Note untraceable inputs in warnings.\n"
            ),
        },
        {
            "name": "network-mapper",
            "description": (
                "Specialist for mapping service dependencies, external integrations, "
                "and the network entity/flow graph."
            ),
            "prompt": (
                "You are a network topology and service dependency specialist.\n"
                "Your mission: Map all services, datastores, and external dependencies that the application interacts with.\n\n"
                "Identify network entities:\n"
                "1. Services: the application itself, microservices, background workers, job queues\n"
                "2. DataStores: databases (PostgreSQL, MySQL, MongoDB, Redis, S3, etc.)\n"
                "3. Identity providers: OAuth2/OIDC providers (Auth0, Cognito, Google, GitHub)\n"
                "4. ThirdParty APIs: payment processors, email/SMS providers, analytics, CDNs\n"
                "5. AdminPlane: admin dashboards, management APIs, internal tooling\n"
                "6. ExternAsset: user-supplied URLs, external content fetched by the app\n\n"
                "For each entity, document:\n"
                "- title: human-readable name\n"
                "- entity_type: Service | DataStore | Identity | ThirdParty | AdminPlane | ExternAsset\n"
                "- zone: Internet | Edge | App | Data | Admin | ThirdParty\n"
                "- tech: technology stack (e.g. 'PostgreSQL 15', 'Redis 7', 'Auth0')\n"
                "- data_sensitivity: list of data types: PII, Tokens, Payments, Secrets, Public\n"
                "- notes: connection method, credentials source, relevant security notes\n\n"
                "For each communication flow between entities:\n"
                "- from_entity: source entity title\n"
                "- to_entity: destination entity title\n"
                "- channel: HTTPS, TCP, Message (queue/pubsub), File, gRPC, WebSocket\n"
                "- path_port: path qualifier or port (e.g. ':5432', ':443 /oauth/token')\n"
                "- guards: security controls on this channel (auth:user, vpc-only, mTLS, api-key)\n"
                "- touches: data sensitivity types that flow through (PII, Tokens, Payments, Secrets)\n\n"
                "Evidence levels:\n"
                "- HIGH: Database connection string, API client instantiation, HTTP client call with URL\n"
                "- MEDIUM: Environment variable names suggesting a service, package import\n"
                "- LOW: Config key names or comment references alone\n\n"
                "Cross-reference with the network discovery report hosts and service fingerprints.\n"
                "Return only entities and flows with code evidence. Skip speculative integrations.\n"
            ),
        },
    ]


def _normalize_report(report: ReconReport, inputs: ReconInputs) -> ReconReport:
    """Ensure report has canonical URL fields set from inputs."""
    return ReconReport(
        target_url=inputs.target_url,
        canonical_url=inputs.canonical_url,
        host=inputs.host,
        path=inputs.path,
        executive_summary=report.executive_summary,
        frontend_tech=report.frontend_tech,
        backend_tech=report.backend_tech,
        infrastructure=report.infrastructure,
        endpoints=report.endpoints[:50],
        input_vectors=report.input_vectors[:100],
        network_entities=report.network_entities[:30],
        network_flows=report.network_flows[:50],
        authorization_guards=report.authorization_guards[:20],
        privilege_roles=report.privilege_roles[:15],
        authz_candidates=report.authz_candidates[:25],
        live_observations=report.live_observations[:20],
        scope_inputs=inputs.scope_inputs,
        plan_inputs=inputs.plan_inputs,
        warnings=report.warnings,
        remediation_hints=report.remediation_hints,
    )
