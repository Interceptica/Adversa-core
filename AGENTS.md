# AGENTS.md

## Purpose
This project builds **Adversa**, a safe-by-default, agentic whitebox security CLI.
Use this document as the operating contract for any coding agent working in this repo.

## Product Intent
- Build a phased CLI workflow:
  1. Intake & Scope
  2. Pre-Recon
  3. Recon
  4. Vulnerability Analysis (safe verification only)
  5. Reporting
- Prioritize reproducibility, auditability, and deterministic artifacts.
- Keep defaults non-destructive and authorization-first.

## Hard Safety Rules
- Never implement destructive testing in OSS default mode.
- Never generate weaponized exploit payloads by default.
- Never support brute force, credential stuffing, or production-target assumptions.
- Require explicit acknowledgement flow (`--i-acknowledge`) before scans.
- Enforce scope at executor/runtime, not only in prompts.
- Treat findings as hypotheses until supported by evidence references.

## Core Technical Standards
- Python 3.11+.
- CLI: Typer.
- Schemas/state: Pydantic v2 (+ JSON schema export).
- Orchestration: Temporal (top-level durable state machine) + LangGraph/DeepAgents inside activities only.
- Logs: JSONL (`tool_calls.jsonl`, `agent_events.jsonl`).
- Testing: pytest.
- Lint/format: ruff.

## Repository Access Guardrail
- Adversa must only operate on target repos inside the local `repos/` folder.
- Any `--repo` path outside `repos/` must be rejected at runtime.
- This applies to all sessions and all commands (`run`, `resume`, analyzers, tools).

## Ticket + Branch Workflow (Required)
- Before starting implementation for a ticket, move that Linear issue to `In Progress`.
- Only move tickets that are actively being worked in the current branch/session.
- One implementation ticket per branch whenever practical.
- Branch naming must follow: `codex/<linear-id>-<short-kebab-summary>`.
- PR title should include the Linear ID and map to the same scope as the branch.
- If scope expands, create/attach a new ticket instead of silently broadening a PR.
- Before handing off, ensure Linear status, dependencies, and labels reflect real code status.

## Configuration Contract
- Primary file: `adversa.toml`.
- Precedence:
  1. CLI flags
  2. `adversa.toml`
  3. Environment variables
  4. Safe defaults
- Provider support:
  - `anthropic`
  - `openai_compatible` (custom `base_url`)
  - optional `router` mode (experimental)
- Secrets must come from env var references, not plaintext config.

## Workspace, Resume, and Artifacts
- Runs must be stored as `runs/<workspace>/<run_id>/...`.
- Resume must skip completed phases only if artifacts pass schema validation.
- Reject workspace resume when URL mismatches original target unless forced.
- Expected top-level run directories:
  - `intake/`, `prerecon/`, `recon/`, `vuln/`, `report/`, `logs/`, `prompts/`

## Deliverable Contracts
Each phase must emit schema-valid artifacts with evidence references.

- Intake:
  - `scope.json`
  - `plan.json`
  - `coverage_intake.json`
- Pre-Recon:
  - `pre_recon.json`
  - coverage + evidence pack
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

## Skills and Policy Gates
- Every skill must declare strict input/output schema.
- Skills must include policy tags (e.g., `network`, `dns`, `filesystem`, `secrets`, `cost`, `destructive`).
- Rules engine must support `focus` and `avoid` actions and influence:
  - planning priority
  - recon/analyzer selection
  - runtime gating

## Linear Backlog Conventions
- Epics are parent issues; implementation tickets are sub-issues.
- Maintain dependencies (`blockedBy`) explicitly.
- Keep labels aligned to taxonomy:
  - `phase:intake`, `phase:prerecon`, `phase:recon`, `phase:vuln`, `phase:report`
  - cross-cut: `cli`, `schemas`, `tests`, `security`, `docs`, `skills`, `config`, `llm`, `rules`, `workspaces`
- Issue descriptions should always include:
  - Goal
  - Implementation notes
  - Files/modules expected
  - Acceptance criteria (DoD)
  - Dependencies

## Definition of Done (Global)
A ticket is done only when all are true:
- Code merged with tests.
- `ruff check .` passes.
- `pytest` passes.
- New/changed artifacts are schema-valid.
- Safety rules are preserved.
- Logs/evidence are present where required.
- Docs/config examples are updated if behavior changed.

## Agent Execution Checklist
Before coding:
- Confirm target phase and expected artifacts.
- Confirm scope and safety constraints.

During coding:
- Keep changes minimal and testable.
- Favor deterministic outputs and explicit schemas.
- Add/extend tests with each behavior change.

Before finishing:
- Run lint/tests.
- Verify artifact paths and naming.
- Verify no secret leakage to disk/logs.
- Confirm ticket DoD is fully addressed.
