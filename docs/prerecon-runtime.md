# Pre-Recon Runtime

This document describes how Adversa's Pre-Recon phase currently executes, what middleware it uses, what inputs it consumes, and which artifacts it writes.

## Overview

Pre-Recon is the first code-intelligence phase after Intake.

Its job is to inspect the authorized repository and produce a schema-valid `PreReconReport` that downstream Recon can consume. The current implementation uses:

- Temporal for outer orchestration
- a Temporal activity for phase execution
- DeepAgents inside the activity for repository analysis
- deterministic validation and artifact writing outside the agent

The important design rule is:

- the agent can analyze and propose structured findings
- the activity/controller layer remains the enforcement boundary for scope, filesystem access, schema validation, and artifact persistence

## Execution Flow

The current flow is:

1. Temporal workflow enters the `prerecon` phase.
2. `run_phase_activity(...)` in `adversa/workflow_temporal/activities.py` dispatches prerecon handling.
3. `_write_prerecon_artifacts(...)` calls `build_prerecon_report(...)` in `adversa/prerecon/controller.py`.
4. `build_prerecon_report(...)`:
   - loads and validates prerecon inputs
   - constructs a DeepAgent with the prerecon prompt
   - applies rules middleware and runtime boundary middleware
   - invokes the model with `response_format=PreReconReport`
   - normalizes the structured output deterministically
5. The activity writes the prerecon artifacts to disk.
6. The phase output is indexed into the run artifact store and exposed through workflow status/query state.

## Inputs

Pre-Recon currently depends on:

- target URL
- workspace root / run directory
- repository path
- effective config path
- Intake artifacts:
  - `intake/scope.json`
  - `intake/plan.json`

`load_prerecon_inputs(...)` in `adversa/prerecon/controller.py` is responsible for loading and validating these values.

It also enforces repository safety:

- the repo must be inside the configured `repos/` root
- the repo must also be reachable under the Adversa project root used by the DeepAgents filesystem backend

If these constraints fail, prerecon aborts with an actionable error.

## Agent Runtime

The prerecon controller uses DeepAgents, not a hand-authored LangGraph flow.

Current implementation location:

- `adversa/prerecon/controller.py`

The DeepAgent is created with:

- the prerecon prompt from `adversa/prompts/pre-recon-code.txt`
- a provider-backed chat model from `ProviderClient.build_chat_model(...)`
- a filesystem backend rooted to the Adversa project root in virtual mode
- a specialist prerecon repository-analysis subagent
- typed structured output via `response_format=PreReconReport`

The current architecture is intentionally split like this:

- prompt + agent runtime: code-intelligence and structured reasoning
- controller/activity layer: deterministic normalization and enforcement

## Middleware

Pre-Recon currently uses two middleware layers from `adversa/agent_runtime/middleware.py`.

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

- enforce filesystem path boundaries for the prerecon agent
- keep repository inspection scoped to the authorized repo subtree

How it works:

- `wrap_tool_call(...)` verifies that filesystem-oriented tool requests stay under the allowed virtual repo prefix
- this prevents prerecon from wandering outside the authorized repository area

This is additive to the broader repo-root validation done before agent execution starts.

## Prompt

Current prompt location:

- `adversa/prompts/pre-recon-code.txt`

The prerecon prompt is designed to:

- treat source code and config as ground truth
- avoid speculation
- produce structured output, not a prose report
- identify high-signal prerecon findings that Recon can build on

The prompt currently asks the agent to extract and reason about:

- framework/runtime signals
- candidate routes and surfaces
- auth/session/authz indicators
- schema files
- external integrations
- security configuration signals
- warnings and remediation hints

The prompt is intentionally richer than the earlier scaffold version, but it is still constrained by the typed `PreReconReport` schema.

## Expected Structured Output

The prerecon agent must return a schema-valid `PreReconReport`.

Current model location:

- `adversa/state/models.py`

The report currently includes:

- target and canonical URL information
- normalized host and path
- repo path and repo-root validation state
- top-level repo entries
- typed framework signals
- typed candidate routes
- typed auth signals
- typed schema files
- typed external integrations
- typed security configuration signals
- preserved `scope_inputs`
- preserved `plan_inputs`
- warnings
- remediation hints

Important nested structures include:

- `FrameworkSignal`
- `RouteSurface`
- `AuthSignal`
- `SchemaFile`
- `ExternalIntegration`
- `SecurityConfigSignal`

Several of these include:

- `evidence`
- `evidence_level`
- scope classification where relevant

After the agent returns its result, `_normalize_report(...)` deterministically sorts and deduplicates the report content before it is written to disk.

## Artifacts Written

Pre-Recon writes into the run workspace under:

- `runs/<workspace>/<run_id>/prerecon/`

Current phase artifacts include:

- `pre_recon.json`
- `output.json`
- `summary.md`
- `coverage.json`
- `evidence/baseline.json`

### `pre_recon.json`

The canonical prerecon artifact.

Contents:

- the normalized `PreReconReport`

### `output.json`

The phase-level shared output contract.

Contents include:

- phase metadata
- summary
- evidence references
- a prerecon data section with selected prerecon slices
- agent runtime metadata

For prerecon, `output.json` currently includes structured summaries for:

- `framework_signals`
- `candidate_routes`
- `auth_signals`
- `schema_files`
- `external_integrations`
- `security_config`
- `warnings`

### `summary.md`

A human-readable phase summary written as part of the shared phase artifact contract.

### `coverage.json`

Coverage and execution accounting for the prerecon phase.

Current contents include counts for:

- framework signals
- candidate routes
- auth signals
- schema files
- external integrations
- security configuration signals

### `evidence/baseline.json`

A compact evidence pack for prerecon.

Current contents include:

- target URL and canonical URL
- framework signals
- candidate routes
- auth signals
- schema files
- external integrations
- security configuration
- `scope_inputs`
- `plan_inputs`

## Schema and Validation

Pre-Recon output is not trusted just because the model returned it.

Validation layers:

1. DeepAgent structured response with `response_format=PreReconReport`
2. Pydantic validation against `PreReconReport`
3. deterministic normalization in `_normalize_report(...)`
4. shared phase artifact writing and indexing
5. schema export coverage in `adversa/state/schemas.py`
6. pytest coverage in `tests/test_prerecon.py`, `tests/test_phase_outputs.py`, and `tests/test_phase_schemas.py`

This preserves the product requirement that downstream phases consume deterministic, schema-valid artifacts.

## Failure Handling

Provider and runtime failures are handled at the activity boundary in `adversa/workflow_temporal/activities.py`.

Current behavior:

- prerecon exceptions are classified with `classify_provider_error(...)`
- activity failures are raised as typed Temporal `ApplicationError`s
- config-required failures can trigger the workflow's waiting-for-config path
- transient failures remain retryable under the Temporal retry policy
- fatal failures stop phase execution

This keeps the DeepAgent runtime inside the activity while preserving Temporal's durable execution model.

## Where To Look In Code

Primary files:

- `adversa/prerecon/controller.py`
- `adversa/agent_runtime/middleware.py`
- `adversa/workflow_temporal/activities.py`
- `adversa/prompts/pre-recon-code.txt`
- `adversa/state/models.py`
- `tests/test_prerecon.py`

## Current Boundaries

What prerecon does now:

- analyzes the authorized repository with DeepAgents
- returns structured prerecon intelligence
- writes deterministic prerecon artifacts
- preserves runtime safety boundaries

What prerecon does not do yet:

- perform active network recon
- own full Recon deliverable generation
- bypass rules via prompt-only policy
- write outside the authorized run workspace

Recon should consume `pre_recon.json` as an upstream artifact rather than recomputing prerecon findings from scratch.
