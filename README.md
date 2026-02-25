# Adversa

Adversa is a safe-by-default, agentic whitebox security CLI for authorized testing of web apps and APIs.

## Status
- Planning complete (PRD + phased backlog in Linear).
- Implementation in progress.
- Current focus: platform foundations, intake/scope, and artifact contracts.

## Core Principles
- Safe verification first (no destructive behavior by default).
- Explicit scope enforcement at runtime.
- Reproducible artifacts and audit logs.
- Schema-validated outputs between phases.

## Planned Workflow
Adversa runs in five phases:
1. Intake & Scope
2. Pre-Recon
: Analyze code and context to understand architecture, entry points, trust boundaries, and security-relevant patterns.
3. Recon
: Explore application behavior (navigation flows, forms, requests/responses, session behavior, and feature surface mapping) to build a practical attack-surface model.
4. Vulnerability Analysis (Safe Verification Only)
: Run parallel analyzer pipelines (for example: injection, XSS, SSRF, authn, authz) using non-destructive checks, evidence collection, and confidence scoring.
5. Reporting
: Compile validated findings into technical and executive outputs, including remediation guidance and retest planning.

## Planned Outputs
Each run is designed to produce structured artifacts under a run workspace:

- Intake:
  - `scope.json`
  - `plan.json`
  - `coverage_intake.json`
- Pre-Recon:
  - `pre_recon.json`
- Recon:
  - `system_map.json`
  - `attack_surface.json`
  - auth/authz/data-flow models
- Vulnerability:
  - `findings.json`
  - `risk_register.json`
  - analyzer evidence
- Reporting:
  - `report.md`
  - `exec_summary.md`
  - `retest_plan.json`
  - bundle index/metadata

## Safety and Authorization
- Use only against systems you are explicitly authorized to test.
- Do not run against production without formal approval.
- Human validation is required for all findings and remediation decisions.
- Unsafe or destructive actions are out of scope for default OSS behavior.

## Configuration (Planned)
Adversa will support `adversa.toml` with:
- Provider/model routing (Anthropic, OpenAI-compatible, optional router mode).
- Rules (`focus`/`avoid`) for steering and policy gating.
- Concurrency and budget controls.
- Optional authenticated testing config.

Precedence:
1. CLI flags
2. `adversa.toml`
3. Environment variables
4. Safe defaults

## Artifact Layout (Planned)
Runs are expected under:

- `runs/<workspace>/<run_id>/intake/`
- `runs/<workspace>/<run_id>/prerecon/`
- `runs/<workspace>/<run_id>/recon/`
- `runs/<workspace>/<run_id>/vuln/`
- `runs/<workspace>/<run_id>/report/`
- `runs/<workspace>/<run_id>/logs/`
- `runs/<workspace>/<run_id>/prompts/`

## Development (Planned Tooling)
- Python 3.11+
- Typer
- Pydantic v2
- LangGraph
- pytest
- ruff

## Project Docs
- PRD: [`prd.md`](/Users/chandrateja/Documents/Adversa-core/prd.md)
- Linear issue export: [`adversa-prd-issues.md`](/Users/chandrateja/Documents/Adversa-core/adversa-prd-issues.md)
- Agent operating contract: [`AGENTS.md`](/Users/chandrateja/Documents/Adversa-core/AGENTS.md)
