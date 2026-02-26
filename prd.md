# PRD: Adversa CLI — Agentic Whitebox Pentest (Phased, Results-as-a-Service Ready)


1. **Provider configuration + routing** (Anthropic/OpenAI-compatible/custom base URLs)
2. **Rules to steer the agent** (“avoid logout”, “focus /api”, budgets, concurrency)

Shannon’s README explicitly supports optional config for authenticated testing + rules (`avoid`/`focus`) and also “Router mode” for alternative providers (experimental), plus pipeline concurrency knobs to manage rate limits. ([GitHub][1])

Below is an **updated PRD** (only the parts that change/add) and an **updated Codex prompt** that will create epics/tasks in Linear including `adversa.toml`, provider routing, and rules.

---

## Updated PRD Additions for Adversa

### A) New: Configuration system (`adversa.toml`)

**Goal:** Provide a stable, explicit configuration contract for:

* LLM provider + model selection
* API keys / tokens (via env var references)
* optional router mode (OpenAI-compatible / Anthropic-compatible / custom base URL)
* auth flows for the target app (optional)
* rules: focus/avoid targets, budgets, concurrency

**Why:** Shannon uses config files to enable authenticated testing and rules, and supports alternative providers via a router mode (experimental). ([GitHub][1])

#### Config precedence

1. CLI flags (highest)
2. `adversa.toml` (project root or `~/.config/adversa/adversa.toml`)
3. environment variables
4. defaults (safe-by-default)

#### Proposed `adversa.toml` (example)

```toml
[project]
name = "my-staging-audit"
output_dir = "./runs"
workspace = "q1-audit"     # enables resume
safe_mode = true

[llm]
provider = "anthropic"      # "anthropic" | "openai" | "openai_compatible" | "router"
model = "claude-sonnet-4.5" # or "gpt-5.2" etc.
max_output_tokens = 64000
timeout_s = 60

# Keys should be loaded from env vars, not stored plaintext
[llm.auth]
api_key_env = "ANTHROPIC_API_KEY"

# OpenAI-compatible / custom inference servers (vLLM, LiteLLM, OpenRouter, etc.)
[llm.openai_compatible]
base_url = "https://api.my-llm-gateway.com/v1"
api_key_env = "OPENAI_API_KEY"
default_headers = { "X-Org" = "acme" }

[pipeline]
max_concurrent_pipelines = 2     # throttle parallel vuln analyzers
retry_preset = "standard"        # "standard" | "subscription" (long backoff)
max_requests = 2000
max_rps = 5

[targets]
url = "https://staging.example.com"
repo_path = "./repos/my-repo"

[rules]
# Like Shannon: steer the agent away/focus areas. :contentReference[oaicite:2]{index=2}
[[rules.avoid]]
type = "path"
url_path = "/logout"
description = "Avoid logout functionality"

[[rules.focus]]
type = "path"
url_path = "/api"
description = "Emphasize API endpoints"

[auth]
# Optional authenticated testing (safe, but powerful)
login_type = "form"
login_url = "https://staging.example.com/login"
username_env = "ADVERSA_USER"
password_env = "ADVERSA_PASS"
totp_secret_env = "ADVERSA_TOTP"  # optional
login_flow = [
  "Type $username into the email field",
  "Type $password into the password field",
  "Click 'Sign In'"
]
success_condition = { type = "url_contains", value = "/dashboard" }
```

**PRD requirement:** The config must validate against a schema and show user-friendly errors.

---

### B) New: Provider abstraction (Anthropic + OpenAI-compatible + custom)

**Goal:** Make the CLI work with:

* Anthropic (first-class)
* OpenAI-compatible endpoints (custom inference gateways)
* optional “router mode” (experimental) similar to Shannon’s concept of routing to alternate providers ([GitHub][1])

**Design:**

* `LLMClient` interface:

  * `generate(messages, tools?, response_format?, timeout?)`
* Implementations:

  * `AnthropicClient`
  * `OpenAICompatibleClient` (base_url configurable)
  * Optional: `RouterClient` (wraps a gateway selection strategy)

**PRD requirement:** Provider config must be usable without code changes; the only difference should be config.

---

### C) New: Rules engine (focus/avoid + budgets + scope safety)

**Goal:** A simple rule system that influences planning and tool execution.

**Rule types (MVP):**

* `path`: match URL paths
* `host`: match hostnames
* `method`: match HTTP methods
* `tag`: match endpoint tags (from OpenAPI)
* `repo_path`: avoid scanning certain folders

**Actions:**

* `focus`: increase priority weight
* `avoid`: disallow (hard block) or “soft avoid” (deprioritize)

**Where rules apply:**

* Recon prioritization (what to map first)
* Vuln analyzers selection and endpoint ranking
* Tool execution gate (hard blocks)

This mirrors Shannon’s config example of “avoid” and “focus” rules. ([GitHub][1])

---

### D) New: Workspaces + resume (run continuation)

Shannon supports resuming runs via “workspaces” and rejects mismatched URLs to prevent cross-target contamination. ([GitHub][1])

**Adversa requirement (MVP or v1):**

* `workspace` concept:

  * stored under `runs/<workspace>/...`
* Resume behavior:

  * if a phase completed and artifacts exist + schema validated, skip it
* Safety check:

  * `targets.url` must match the original workspace URL (or explicit `--force`)

---

### E) New: Output reproducibility artifacts

Shannon stores prompt snapshots and per-agent logs. ([GitHub][1])

**Adversa requirement:**

* `runs/<id>/prompts/<agent>_<timestamp>.txt`
* `runs/<id>/agents/<agent>/events.jsonl`
* `runs/<id>/deliverables/…` (your existing structure is fine)

---

### F) New: “Disclaimers & safety”

Shannon’s README is explicit: don’t run on prod, must have authorization, LLM caveats, cost/time caveats. ([GitHub][1])

**Adversa requirement:**

* On `adversa run`, print a one-time warning requiring `--i-acknowledge` unless configured.
* Document:

  * staging/sandbox only
  * written authorization
  * human verification required

---

## Updated “PRD Sections” to insert (where to place)

* Add **Section 7A**: Configuration (`adversa.toml`)
* Add **Section 7B**: LLM Provider Abstraction
* Add **Section 9**: Rules Engine + Policy Gates (expand)
* Add **Section 10**: Workspaces/Resume
* Add **Section 11**: Reproducibility (prompt snapshots, logs)
* Add **Section 12**: Disclaimers & Acknowledgement

---

# Updated Codex Prompt (Linear MCP) — includes adversa.toml + providers + rules

Copy/paste to your coding agent:

---

You are a senior staff engineer + TPM. Convert the PRD below into an execution plan in Linear (Epics → Issues → Tasks), ordered for implementation.

**Project:** Adversa
**Product:** Open-source codex-style CLI for authorized **whitebox** security assessments of web apps/APIs. Phases: Intake/Scope → Pre-Recon → Recon → Vuln Analysis (safe verification) → Reporting. Built with LangGraph + skill registry (DeepAgents-style). Safe-by-default, audit-first.

## Stack decisions (MVP)

* Python 3.11+
* Typer CLI
* Pydantic v2 schemas (+ JSON schema export)
* LangGraph orchestration
* Local artifacts in `runs/<run_id>/...`
* Logs in JSONL (`tool_calls.jsonl`, `agent_events.jsonl`)
* pytest, ruff
* Config file: `adversa.toml` (+ env var support)

## NEW: Configuration requirements

Implement `adversa.toml` with:

* LLM provider config:

  * `anthropic`
  * `openai_compatible` with `base_url` and `api_key_env`
  * optional `router` mode flagged “experimental” (like Shannon’s router mode concept) ([GitHub][1])
* Model selection, timeouts, max tokens
* Pipeline settings:

  * `max_concurrent_pipelines` and retry presets (like Shannon’s concurrency/rate limit controls) ([GitHub][1])
* Target settings: `repo_path`, `url`
* Auth settings (optional): login flow + TOTP secret env var
* Rules engine:

  * `rules.focus[]` and `rules.avoid[]` with types like `path`, `host`, `method`
  * These steer prioritization and enforce hard blocks (like Shannon’s rules example) ([GitHub][1])
* Config precedence: CLI flags > adversa.toml > env vars > defaults

## NEW: Workspaces/resume

Add `workspace` support:

* Runs stored under `runs/<workspace>/...`
* Resuming should skip completed phases
* Must reject mismatched URL vs original workspace unless `--force` (similar safety pattern) ([GitHub][1])

## Safety requirements (hard)

* No destructive testing in OSS default
* No weaponized exploit payload generation in default prompts
* Network discovery skills disabled by default; require explicit scope/policy enable
* Every network action must be scope-validated, rate-limited, and logged
* Must show a disclaimer requiring acknowledgement (staging only, authorization required) ([GitHub][1])

## MVP v0 deliverables

Commands:

* `adversa init`
* `adversa run --scope scope.json --repo <path> --url <staging>`
* `adversa run --phase intake|prerecon|recon|vuln|report`
* `adversa report --run <id>`
* `adversa workspaces` (list) / `adversa resume --workspace <name>` (or equivalent)

Outputs:

* Phase 0: `scope.json`, `plan.json`, `coverage_intake.json`, summary.md
* Phase 1: `pre_recon.json`, `coverage_pre_recon.json`, evidence/
* Phase 2: `system_map.json`, `attack_surface.json`, `auth_model.json`, `authz_model.json`, `data_flow.json`, `coverage_recon.json`
* Phase 3: `findings.json`, `risk_register.json`, `coverage_vuln.json`, evidence/
* Phase 4: `report.md`, `exec_summary.md`, `retest_plan.json`, `report_bundle.json`

Also:

* Prompt snapshots stored per run (reproducibility) ([GitHub][1])
* Skill registry with policy tags and schemas
* 4 vuln analyzers (safe verification): AuthZ, Injection, XSS, SSRF

## Your tasks in Linear

Create:

1. Epics for major milestones (MVP v0 and v1)
2. Issues under each epic with:

   * Goal
   * Implementation notes
   * Files/modules expected
   * Acceptance criteria (DoD)
   * Dependencies
   * Size estimate (S/M/L)
3. Labels: `phase:intake`, `phase:prerecon`, `phase:recon`, `phase:vuln`, `phase:report`, `config`, `llm`, `rules`, `workspaces`, `skills`, `schemas`, `cli`, `tests`, `docs`, `security`

## PRD (authoritative)

[PASTE UPDATED PRD HERE — include adversa.toml, provider abstraction, rules engine, workspaces/resume, reproducibility requirements]

Now:

1. Summarize architecture in <=10 bullets
2. Create epics + issues in Linear in correct order
3. Output suggested implementation order list


## 1) Overview

### Product Vision

Build an open-source, codex-style CLI that performs **phased, authorized whitebox security assessments** against a target system (typically “repo + staging URL”), producing **high-quality structured deliverables** suitable for:

* developer triage
* compliance evidence
* repeatable regression validation
* later “Results-as-a-Service” (hosted runs + dashboards)

### Core principles

1. **Phase contracts**: Every phase emits a deliverable bundle that the next phase consumes.
2. **Agent recommends, controller executes**: agents propose actions; controllers enforce policy gates.
3. **Skills > ad-hoc tools**: tools are exposed through “skills” with strict I/O + policy tags.
4. **Non-destructive by default** (`--safe`): verification > exploitation.
5. **Audit-first**: all tool calls and outputs are recorded, reproducible, and scoped.

---

## 2) Goals and Non-Goals

### Goals

* CLI runs a full assessment pipeline: **Pre-Recon → Recon → Vulnerability Analysis → Reporting**
* Supports “repo + staging URL only” scenario
* Produces consistent, schema-validated JSON deliverables + human reports
* Provides a skill registry so DeepAgents can choose methods safely
* Parallelizable vulnerability analysis via separate analyzers (pipelines)

### Non-Goals (Open-source default)

* No automatic destructive testing (DoS, data exfiltration, mass credential attacks)
* No “weaponized exploit payloads” output by default
* No autonomous out-of-scope scanning

---

## 3) Target Users & Use Cases

### Personas

* **Security engineer / red team** (authorized)
* **Platform engineer / SRE** validating staging posture
* **Engineering manager** wanting summarized risk + backlog tickets

### Primary workflows

1. “Repo + staging URL” → generate inventory, map surface, produce findings + report
2. Re-run after fixes → compare deltas, validate regressions
3. CI mode (later) → run specific analyzers on PRs (SAST/config/deps)

---

## 4) CLI UX (Codex-style)

### Commands

* `adversa init`
  Creates config + scope template, selects default skills and constraints.
* `adversa run --scope scope.json --repo . --url https://staging...`
  Runs full pipeline (or phase subset).
* `adversa run --phase recon` / `--phase vuln`
  Runs specific phase(s).
* `adversa report --run <run_id>`
  Generates reports from stored artifacts.
* `adversa replay --run <run_id>`
  Replays from artifacts (offline, deterministic).

### Modes

* `--safe` (default): bounded checks, rate-limited, no destructive actions
* `--internal` (optional later): enables additional skills with explicit RoE approval
* `--offline`: no network tools; use repo/docs only

---

## 5) System Architecture

### Components

1. **CLI Orchestrator**

   * Loads config/scope
   * Starts run, manages logs, prints progress
2. **LangGraph Workflow**

   * Phase controllers + specialist nodes
   * State = typed schema (Pydantic strongly recommended)
3. **DeepAgents Skill Layer**

   * Skill registry + routing
   * Agents request skills; controllers approve
4. **Sandbox / Executor**

   * Runs tools with allowlists, rate limits, timeouts
5. **Artifact Store**

   * Local filesystem structure, later S3 + DB index
6. **Reporter**

   * Converts `findings.json` → `report.md`, `exec_summary.md`, `tickets.json`

---

## 6) Data Model & Deliverable Contracts

### Universal deliverable bundle (every phase)

* `phase_<name>_output.json` (schema-validated)
* `phase_<name>_summary.md`
* `evidence/` references (tool logs, traces)
* `coverage_<name>.json` (what was done vs not)

### Standard Finding Schema (core)

`findings.json` stores a list of `Finding` objects with:

* id, title, category, severity, confidence
* affected components (repo paths, endpoints)
* impact, evidence_refs, recommendation
* reproduction_guidance (redacted by default)
* timestamps + run metadata

---

# 7) Phases: Agents, Skills, Tools, Deliverables

## Phase 0 — Intake & Scope (Pre-Recon Planning)

**Objective:** Convert inputs into enforceable scope + run plan; compute confidence gaps.

### Inputs

* repo path(s)
* staging URL(s)
* optional: OpenAPI spec, architecture docs, credentials, RoE constraints

### Agents

1. **Scope Agent**

   * Normalizes targets (domains, services, repos)
   * Marks explicit in-scope / out-of-scope
2. **Policy Agent**

   * Enforces RoE: rate limits, allowed hours, scanning allowed?
3. **Plan Agent**

   * Computes which phases/analyzers to run
   * Outputs run plan + budgets

### Skills provided (Phase 0)

* `skill.parse_target_url` (extract domain/root domain/redirect hints)
* `skill.repo_detect_stack` (framework, language, auth libs)
* `skill.load_openapi_if_present`
* `skill.generate_scope_template`
* `skill.policy_validate_scope`

### Tools underlying these skills

* URL parser
* repo scanners (package manifests)
* OpenAPI parser
* config templater

### Deliverables

* `scope.json` (authoritative)
* `plan.json` (phase plan, analyzer selection, budgets)
* `intake_summary.md`
* `coverage_intake.json` (missing inputs list + confidence score)

---

## Phase 1 — Pre-Recon (Lightweight Discovery & Baseline Evidence)

**Objective:** Build initial evidence about the staging surface when inventory is incomplete (repo + URL only).

### Agents

1. **Pre-Recon Controller** (orchestrator node)
2. **DNS Discovery Agent**
3. **Exposure Validation Agent**
4. **Tech Fingerprint Agent**
5. **Repo Baseline Agent** (quick static inventory)

### Skills provided (Phase 1)

**Network/DNS (gated)**

* `skill.dns_discover_subdomains` *(policy-gated)*
* `skill.resolve_dns_records`
* `skill.http_head_probe` *(rate-limited)*
* `skill.tls_certificate_inspect`

**Exposure validation (gated)**

* `skill.exposure_validate_host_ports` *(policy-gated, bounded targets only)*

**Repo baseline**

* `skill.generate_sbom_basic`
* `skill.detect_secrets_basic`
* `skill.enumerate_configs` (env files, infra hints)

### Tools (examples, wrapped as skills)

* DNS enumeration tool (optional)
* network port validation tool (optional)
* HTTP client, TLS inspector
* SBOM generator
* secret scanning library

### Controller gating rules (must implement)

* Only run network skills if `scope.json` allows `network_discovery=true`
* Only run on allowlisted domains derived from staging URL root domain
* Always store vantage point + budgets

### Deliverables

* `pre_recon.json` (discovered hosts, resolved IPs, reachable services)
* `pre_recon_summary.md`
* `evidence/` (dns outputs, port validation outputs, http probe logs)
* `coverage_pre_recon.json` (what was validated, from where, constraints)

---

## Phase 2 — Recon (Whitebox Mapping & Correlation)

**Objective:** Produce a **system map**: endpoints → handlers → auth/session → data flows.

### Agents

1. **Recon Controller**
2. **API Surface Agent**

   * OpenAPI/GraphQL + code route discovery
3. **Auth Model Agent**

   * auth flows, session/JWT handling, role claims
4. **AuthZ Architecture Agent**

   * middleware/guards/policies, permission checks
5. **Data Flow Agent**

   * sources/sinks, PII paths
6. **Dependency & Third-Party Agent**

   * dependencies, outbound calls, SaaS usage
7. **Runtime Correlation Agent**

   * correlate recon map with pre-recon observations

### Skills provided (Phase 2)

**Repo & spec**

* `skill.repo_route_enumeration`
* `skill.openapi_extract_endpoints`
* `skill.graphql_schema_extract` (if available)
* `skill.repo_symbol_search` / `skill.repo_ast_query`
* `skill.auth_flow_identify`
* `skill.authz_guard_discovery`
* `skill.dataflow_lightweight` (taint-ish heuristics)
* `skill.outbound_dependency_extract` (HTTP clients, SDKs)

**Runtime correlation (bounded)**

* `skill.endpoint_reachability_probe` *(rate-limited, safe)*
* `skill.auth_required_probe` *(safe: detects 401/403 patterns only)*

### Deliverables

* `system_map.json` (services/nodes/edges)
* `attack_surface.json` (endpoints, entrypoints, hostnames)
* `auth_model.json` (auth mechanisms, session/JWT, role claims)
* `authz_model.json` (guards/policies, permission checks locations)
* `data_flow.json` (PII flows, storage, sinks)
* `recon_summary.md`
* `coverage_recon.json` (mapped vs unknown; confidence per module)

---

## Phase 3 — Vulnerability Analysis (Parallel Analyzers)

**Objective:** Convert recon outputs into **hypotheses → verification evidence → findings**.

### Design choice

Use **separate analyzers (subgraphs)** per vuln class. DeepAgents chooses skills **within** each analyzer.

### Agents

1. **Vuln Controller** (scheduler + dedupe + gating)
2. **Auth Analyzer**
3. **AuthZ Analyzer**
4. **Injection Analyzer**
5. **XSS Analyzer**
6. **SSRF Analyzer**
7. **Secrets & Sensitive Data Analyzer**
8. **Config/IaC Analyzer** (if IaC present)
9. **Dependency/CVE Analyzer**
10. **Triage & Dedup Agent**
11. **Remediation Agent** (fix guidance + regression suggestions)

### Shared analyzer lifecycle (standard)

* **Analyze**: generate candidates/hypotheses using recon artifacts
* **Verify**: safe checks, strong evidence capture
* **Document**: emit findings in schema + remediation

### Skills (shared “vuln core”)

* `skill.generate_hypotheses_from_recon`
* `skill.repo_pattern_scan` (vuln patterns)
* `skill.endpoint_risk_rank` (prioritize)
* `skill.safe_runtime_verification` *(bounded, rate-limited)*
* `skill.evidence_packager` (store traces/snippets)
* `skill.finding_writer` (schema locked)
* `skill.dedupe_findings`

### Skills per analyzer (examples)

**Auth Analyzer skills**

* `skill.session_handling_review`
* `skill.jwt_claims_review`
* `skill.login_flow_review`
* `skill.safe_auth_verification_checks` *(non-destructive)*

**AuthZ Analyzer skills**

* `skill.access_control_invariant_mine` (owner checks, role checks)
* `skill.guard_path_trace` (route → guard → handler)
* `skill.idor_candidate_detection`

**Injection Analyzer skills**

* `skill.sql_query_construction_trace`
* `skill.orm_misuse_detection`
* `skill.input_validation_presence_check`
* `skill.safe_injection_signals_probe` *(very bounded, safe mode)*

**XSS Analyzer skills**

* `skill.template_sink_detection`
* `skill.output_encoding_check`
* `skill.csp_header_check` *(safe)*
* `skill.safe_reflection_probe` *(bounded)*

**SSRF Analyzer skills**

* `skill.outbound_request_sink_detection`
* `skill.url_param_flow_trace`
* `skill.safe_ssrf_guardrail_check` *(validation + allowlists presence)*

**Secrets/Sensitive Data**

* `skill.secret_scan_deep`
* `skill.logging_pii_check`
* `skill.config_leak_check`

**Config/IaC**

* `skill.k8s_manifest_scan`
* `skill.terraform_scan`
* `skill.least_privilege_heuristics`

**Dependency/CVE**

* `skill.sbom_generate`
* `skill.vuln_db_lookup` *(offline feed or user-provided)*

### Tool gating rules (critical)

* Network verification skills require:

  * `scope.json` allows it
  * bounded targets list generated from recon/pre-recon only
  * per-analyzer budgets and max requests
* No analyzer can expand scope; only controller can propose scope changes for user approval.

### Deliverables

* `findings.json` (schema-validated)
* `risk_register.json` (aggregated risk themes, top risks)
* `vuln_summary.md`
* `evidence/` (http traces, code snippets, screenshots if any)
* `coverage_vuln.json` (which analyzers ran, coverage confidence, skipped reasons)

---

## Phase 4 — Reporting & Metadata Injection

**Objective:** Convert findings into stakeholder-ready outputs + integration artifacts.

### Agents

1. **Report Agent**

   * assembles full technical report
2. **Executive Summary Agent**

   * top risks, business impact, quick wins
3. **Backlog/Ticket Agent** (optional)
4. **Metadata Injection Agent**

   * inject run metadata: versions, scope, timestamps, budgets, tool versions

### Skills

* `skill.report_assembler`
* `skill.exec_summary_writer`
* `skill.ticket_exporter` (Jira/GitHub JSON templates)
* `skill.run_metadata_injector`

### Deliverables

* `report.md` (technical)
* `exec_summary.md`
* `tickets.json` (optional)
* `retest_plan.json` (what to rerun after fixes)
* `report_bundle.json` (metadata, hashes, artifact index)

---

# 8) Skill Registry Specification

## Skill interface (required)

Each skill must declare:

* `name`, `description`
* `input_schema`, `output_schema`
* `policy_tags`: `network`, `dns`, `filesystem`, `secrets`, `cost`, `destructive`
* `default_budget`: max requests, timeout, concurrency
* `evidence_output`: what artifacts it writes (paths)

## Skill routing rules

* DeepAgents can propose: **skill + parameters**
* Controller validates:

  * scope compliance
  * policy tags allowed in this phase/mode
  * budget availability
* Executor runs skill in sandbox and logs:

  * args hash, outputs hash, stdout/stderr, timestamps

---

# 9) Safety, Scope, and Compliance

## Hard requirements

* Scope enforcement at execution layer (not just prompt)
* Default `--safe` mode:

  * rate limited
  * bounded targets only
  * no destructive actions
* Evidence redaction:

  * secrets, tokens, cookies
  * PII minimization
* Full audit trail:

  * `tool_calls.jsonl`
  * `agent_events.jsonl`
  * artifact hashes

---

# 10) Storage Layout (Local Artifacts)

```
runs/<run_id>/
  scope.json
  plan.json
  intake/
  pre_recon/
    pre_recon.json
    evidence/
  recon/
    system_map.json
    attack_surface.json
    auth_model.json
    authz_model.json
    data_flow.json
  vuln/
    findings.json
    risk_register.json
    evidence/
  report/
    report.md
    exec_summary.md
    tickets.json
  logs/
    tool_calls.jsonl
    agent_events.jsonl
```

---

# 11) MVP Scope & Milestones

## MVP v0 (must-have)

* Phase 0–2 end-to-end (intake → pre-recon → recon)
* Vuln phase with **4 analyzers**: AuthZ, Injection, XSS, SSRF (safe verification)
* Findings schema + report generator
* Skill registry + policy gating

## v1

* Add Secrets + Dependency analyzers
* Add Config/IaC analyzer
* Add retest mode and diffing (`findings_diff.json`)

## v2 (SaaS readiness)

* Upload run bundles to object storage
* Web dashboard to browse system map + findings
* Multi-run comparison, trending risk themes

---

# 12) Acceptance Criteria

### Functional

* Given repo + staging URL, tool produces:

  * `attack_surface.json` with endpoints and reachable hosts
  * `findings.json` with at least basic triaged findings (or explicit “no findings” with coverage explanation)
  * `report.md` summarizing results
* All JSON outputs validate against schemas
* Every network action is recorded with budgets and scope checks

### Safety

* Cannot run network discovery unless explicitly enabled in scope/policy
* Out-of-scope domains are never scanned
* Secrets are redacted in outputs

### Quality

* Recon output includes: auth model, authz mapping, data flow summary, and coverage report
* Findings include evidence_refs and remediation guidance

---

# 13) Skills-to-Agents Mapping (Quick Matrix)

## Phase 0

* Scope Agent: `parse_target_url`, `generate_scope_template`
* Policy Agent: `policy_validate_scope`
* Plan Agent: `repo_detect_stack`, `load_openapi_if_present`

## Phase 1

* DNS Discovery Agent: `dns_discover_subdomains`, `resolve_dns_records` *(gated)*
* Exposure Validation Agent: `exposure_validate_host_ports` *(gated)*
* Tech Fingerprint Agent: `http_head_probe`, `tls_certificate_inspect`
* Repo Baseline Agent: `generate_sbom_basic`, `detect_secrets_basic`, `enumerate_configs`

## Phase 2

* API Surface Agent: `openapi_extract_endpoints`, `repo_route_enumeration`
* Auth Model Agent: `auth_flow_identify`, `repo_ast_query`
* AuthZ Agent: `authz_guard_discovery`, `guard_path_trace`
* Data Flow Agent: `dataflow_lightweight`
* Runtime Correlation: `endpoint_reachability_probe`, `auth_required_probe` *(safe)*

## Phase 3

* Each analyzer: shared vuln core + analyzer-specific skills (above)
* Triage: `dedupe_findings`, `endpoint_risk_rank`
* Remediation: `finding_writer`, `regression_suggestions`

## Phase 4

* Reporting: `report_assembler`, `exec_summary_writer`
* Metadata: `run_metadata_injector`
* Tickets: `ticket_exporter`

---

If you want, I can turn this PRD into:

1. **a README-ready open-source spec** (with CLI examples + folder layout), and/or
2. **LangGraph implementation blueprint** (state schema + node graph + how controllers gate skills).
