# Recon Runtime

This document describes how Adversa's Recon phase currently executes, what middleware it uses, what inputs it consumes, and which artifacts it writes.

## Overview

Recon is the attack surface mapping phase. It sits after Network Discovery and before Vulnerability:

```
intake → prerecon → netdisc → recon → vuln → report
```

Its job is to **correlate** the static code intelligence from Pre-Recon with the live network surface from Network Discovery, producing a comprehensive attack surface map that the Vulnerability phase can consume. The current implementation uses:

- Temporal for outer orchestration
- a Temporal activity for phase execution
- DeepAgents inside the activity for multi-specialist analysis
- Playwright MCP via `langchain-mcp-adapters` for live browser verification
- deterministic normalization and artifact writing outside the agent

The important design rule is:

- the agent and its subagents analyze, propose, and observe
- the activity/controller layer remains the enforcement boundary for scope, schema validation, and artifact persistence
- upstream markdown artifacts from Pre-Recon and Network Discovery are passed inline to the agent — no extra tool calls needed to access prior phase context

## Execution Flow

The current flow is:

1. Temporal workflow enters the `recon` phase.
2. `run_phase_activity(...)` in `adversa/workflow_temporal/activities.py` dispatches recon handling.
3. `_write_recon_artifacts(...)` awaits `build_recon_report(...)` in `adversa/recon/controller.py`.
4. `build_recon_report(...)`:
   - loads upstream markdown from `prerecon/pre_recon_analysis.md` and `netdisc/network_discovery.md`
   - loads scope and plan inputs from `intake/scope.json` and `intake/plan.json`
   - opens a session-isolated Playwright browser via `playwright_tools_context(...)`
   - constructs a DeepAgent with the recon prompt, browser tools, four specialist subagents, and two middleware layers
   - invokes the agent with `response_format=ReconReport`
   - normalizes and caps the structured output deterministically
5. The activity generates `recon_analysis.md` from the report and writes all artifacts to disk.
6. The phase output is indexed into the run artifact store.

## Inputs

Recon depends on:

- target URL
- workspace root / run directory
- repository path
- effective config path
- Pre-Recon artifacts:
  - `prerecon/pre_recon_analysis.md` — full static code intelligence report
- Network Discovery artifacts:
  - `netdisc/network_discovery.md` — live network surface map
- Intake artifacts:
  - `intake/scope.json`
  - `intake/plan.json`

`load_recon_inputs(...)` in `adversa/recon/controller.py` loads all of these. The full markdown content of both upstream reports is embedded **inline** in the agent's user message, giving the agent immediate context without requiring it to make additional file reads for prior phase data.

It also enforces repository safety:

- the repo must be inside the configured `repos/` root
- the repo must be reachable under the Adversa project root used by the DeepAgents filesystem backend

If either constraint fails, recon aborts with an actionable error.

## Agent Runtime

The recon controller uses DeepAgents with four specialist subagents and a Playwright MCP browser integration.

Current implementation location:

- `adversa/recon/controller.py`

The DeepAgent is created with:

- the recon prompt from `adversa/prompts/recon.txt`
- a provider-backed chat model from `ProviderClient.build_chat_model(...)`
- a filesystem backend rooted to the Adversa project root in virtual mode
- Playwright MCP browser tools from `playwright_tools_context(...)`
- four specialist subagents (see below)
- typed structured output via `response_format=ReconReport`

The current architecture is intentionally split like this:

- prompt + subagents + browser tools: multi-specialist analysis and live surface observation
- controller/activity layer: deterministic normalization, capping, and enforcement

## Subagents

The main recon agent delegates to four specialist subagents that run in parallel:

### 1. route-mapper

Purpose:

- deep API endpoint-to-handler mapping
- traces each route to its handler file and line
- identifies auth middleware applied per route (not just the router group)
- flags object ID parameters that are IDOR candidates

Framework patterns covered: Express, FastAPI, Django, Rails, Next.js, Spring.

### 2. auth-architect

Purpose:

- maps the complete auth system from login to privilege enforcement
- traces token creation, signing, and claim structure
- identifies session storage mechanism and cookie security flags
- enumerates all roles and their privilege levels (0–10 scale)
- maps named authorization guard functions with file and line locations

### 3. input-tracer

Purpose:

- catalogs every user-controlled input vector reachable over the network
- covers URL parameters, POST body fields, HTTP headers, cookies, file uploads, GraphQL arguments, and WebSocket messages
- records the exact extraction point (file:line) for each input
- flags inputs that flow to dangerous sinks (SQL, shell, HTML render, file path, external URL)

Cross-references with Pre-Recon vulnerability sink data.

### 4. network-mapper

Purpose:

- maps all services, datastores, and external dependencies the application interacts with
- identifies entity types: Service, DataStore, Identity, ThirdParty, AdminPlane, ExternAsset
- records data sensitivity classifications (PII, Tokens, Payments, Secrets)
- maps communication flows between entities with guard and data-touch annotations

Cross-references with Network Discovery host and fingerprint data.

## Browser Tools

Recon uses Playwright MCP for live browser verification of the target surface.

Current implementation location:

- `adversa/recon/browser.py`

The `playwright_tools_context(...)` async context manager:

- spawns a headless Playwright MCP subprocess via `npx @playwright/mcp@latest --headless`
- uses the `stdio` transport from `langchain-mcp-adapters` (`MultiServerMCPClient`)
- kills the subprocess when the context exits — zero cookie or session leakage between runs

Allowed browser tool actions:

- `browser_navigate`, `browser_snapshot`, `browser_take_screenshot`
- `browser_network_requests`, `browser_console_messages`
- `browser_click`, `browser_type`, `browser_press_key`, `browser_hover`
- `browser_wait_for`, `browser_tabs`, `browser_navigate_back`

Excluded actions: `browser_evaluate` (arbitrary JS execution) and `browser_file_upload`.

The agent is instructed to only navigate to the authorized target URL and hosts confirmed by the Network Discovery report.

## Middleware

Recon uses the same two middleware layers as Pre-Recon.

### 1. Rules Middleware

Factory:

- `load_rules_middleware(context)`

Purpose:

- inject compiled focus/avoid rules into the model prompt
- enforce rule-based runtime boundaries on tool calls

How prompt injection works:

- `RulesGuardrailMiddleware.wrap_model_call(...)` builds a policy prompt with:
  - current phase
  - base URL
  - repo path
  - compiled focus/avoid rules
- that policy prompt is inserted as the system message before model execution

How runtime enforcement works:

- `RulesGuardrailMiddleware.wrap_tool_call(...)` checks tool requests against compiled runtime rules
- blocked requests fail at runtime even if the model attempts them

This means the rules are both:

- visible to the model as prompt context
- enforced as actual runtime guardrails

### 2. Runtime Boundary Middleware

Factory:

- `load_runtime_boundary_middleware(context, allowed_repo_virtual_prefix=...)`

Purpose:

- enforce filesystem path boundaries for the recon agent and its subagents
- keep repository inspection scoped to the authorized repo subtree

How it works:

- `wrap_tool_call(...)` verifies that filesystem-oriented tool requests stay under the allowed virtual repo prefix
- this prevents recon from wandering outside the authorized repository area

## Prompt

Current prompt location:

- `adversa/prompts/recon.txt`

The recon prompt is designed to:

- treat upstream Pre-Recon and Network Discovery reports as the starting context
- focus on attack surface mapping, not vulnerability discovery (that is the vuln phase's job)
- use all four subagents for parallel code analysis before synthesizing findings
- use browser tools to verify and observe live endpoint behavior
- avoid speculation and fabrication — every finding requires code or live evidence
- produce a complete `ReconReport` including authz candidates and live observations

The prompt defines a four-phase working method:

1. synthesize upstream Pre-Recon and Network Discovery data
2. delegate to the four specialist subagents for parallel code analysis
3. use browser tools to verify top endpoints live
4. synthesize all findings into a structured `ReconReport`

## Expected Structured Output

The recon agent must return a schema-valid `ReconReport`.

Current model location:

- `adversa/state/models.py`

The report currently includes:

- target and canonical URL information
- normalized host and path
- executive summary
- frontend, backend, and infrastructure technology lists
- typed endpoint inventory with auth requirements and object ID parameters
- typed input vectors with validation and sink-flow flags
- typed network entities with zone and data sensitivity classifications
- typed network flows between entities
- typed authorization guards with category and statement
- typed privilege roles with privilege level (0–10) and middleware location
- typed authorization vulnerability candidates (horizontal, vertical, context-based)
- live browser observations
- preserved `scope_inputs` and `plan_inputs`
- warnings and remediation hints

Important nested structures include:

- `ReconEndpoint`
- `InputVector`
- `NetworkEntity`
- `NetworkFlow`
- `AuthorizationGuard`
- `PrivilegeRole`
- `AuthzCandidate`

After the agent returns its result, `_normalize_report(...)` sets canonical URL fields from the verified inputs and caps list sizes (endpoints: 50, input_vectors: 100, network_entities: 30, etc.) before writing to disk.

## Artifacts Written

Recon writes into the run workspace under:

- `runs/<workspace>/<run_id>/recon/`

Current phase artifacts include:

- `recon_analysis.md`
- `recon.json`
- `output.json`
- `summary.md`
- `coverage.json`
- `evidence/baseline.json`

### `recon_analysis.md`

The **primary deliverable** — a pentester-friendly 9-section markdown report generated deterministically from the `ReconReport`. No tokens are spent on this; it is generated programmatically by `generate_recon_markdown(...)` in `adversa/recon/reports.py`.

The report contains nine sections:

1. Executive Summary — overall posture, counts table (endpoints, roles, authz candidates)
2. Technology & Service Map — frontend, backend, and infrastructure technology tables
3. Authentication & Session Management — auth mechanisms, privilege roles table, authorization guards directory
4. API Endpoint Inventory — full table: Method | Path | Required Role | Object IDs | Auth Mechanism | Handler
5. Input Vectors — all input vectors; risky (unvalidated + flows to sink) surfaced first
6. Network & Interaction Map — network entities table, network flows table
7. Role & Privilege Architecture — privilege roles table, ASCII privilege lattice diagram, authorization candidates
8. Authorization Vulnerability Candidates — horizontal (IDOR), vertical (privilege escalation), and context-based candidates in prioritized tables
9. Live Browser Observations — findings from live Playwright browser verification; omitted if empty

This file is the primary input consumed by the Vulnerability phase.

### `recon.json`

Minimal workflow metadata artifact.

Contents:

- the normalized `ReconReport`

### `output.json`

The phase-level shared output contract.

Contents include:

- phase metadata
- summary
- evidence references
- a recon data section with selected recon slices
- agent runtime metadata (including `RulesGuardrailMiddleware` in middleware list)

### `summary.md`

A human-readable phase summary written as part of the shared phase artifact contract.

### `coverage.json`

Coverage and execution accounting for the recon phase.

Current contents include counts for:

- endpoints
- input vectors
- network entities
- network flows
- authorization candidates

### `evidence/baseline.json`

A compact evidence pack for recon.

Current contents include:

- target URL and canonical URL
- all endpoints
- all input vectors
- all network entities and flows
- all authorization guards and privilege roles
- all authz candidates
- `scope_inputs` and `plan_inputs`

## Schema and Validation

Recon output is not trusted just because the model returned it.

Validation layers:

1. DeepAgent structured response with `response_format=ReconReport`
2. Pydantic validation against `ReconReport`
3. deterministic normalization and list-capping in `_normalize_report(...)`
4. shared phase artifact writing and indexing
5. schema export coverage in `adversa/state/schemas.py`
6. pytest coverage in `tests/test_recon_markdown.py`, `tests/test_phase_outputs.py`, and `tests/test_phase_schemas.py`

## Failure Handling

Provider and runtime failures are handled at the activity boundary in `adversa/workflow_temporal/activities.py`.

Current behavior:

- recon exceptions are classified with `classify_provider_error(...)`
- activity failures are raised as typed Temporal `ApplicationError`s
- config-required failures can trigger the workflow's waiting-for-config path
- transient failures remain retryable under the Temporal retry policy
- fatal failures stop phase execution

## Where To Look In Code

Primary files:

- `adversa/recon/controller.py`
- `adversa/recon/browser.py`
- `adversa/recon/reports.py`
- `adversa/agent_runtime/middleware.py`
- `adversa/workflow_temporal/activities.py`
- `adversa/prompts/recon.txt`
- `adversa/state/models.py`
- `tests/test_recon_markdown.py`

## Current Boundaries

What recon does now:

- correlates Pre-Recon static code intelligence with Network Discovery live surface data
- maps API endpoints, input vectors, network entities, auth architecture, and privilege roles
- verifies live endpoint behavior with a session-isolated Playwright browser
- produces a structured `ReconReport` and a markdown attack surface map
- enforces scope and rules constraints via middleware

What recon does not do:

- discover vulnerabilities (that is the vuln phase's job)
- generate exploit payloads or perform active exploitation
- navigate outside the authorized scope
- share browser sessions or cookies between runs
- bypass rules via prompt-only policy

The Vulnerability phase should consume `recon_analysis.md` and `evidence/baseline.json` as upstream artifacts rather than recomputing the attack surface from scratch.
