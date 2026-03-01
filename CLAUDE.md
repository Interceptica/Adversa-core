# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Commands

### Using mise (Recommended)

```bash
# Install mise: https://mise.jdx.dev/getting-started.html
curl https://mise.run | sh

# Install dependencies (Python, uv, and project packages)
mise install
mise run install

# Run the CLI
adversa --help
python -m adversa

# Initialize config
adversa init [--force]

# Run a security scan
adversa run \
  --repo repos/my-target-repo \
  --url https://staging.example.com \
  --workspace my-workspace \
  --i-acknowledge

# Status/management commands
adversa status --workspace <name> [--run-id <id>]
adversa resume --workspace <name> [--run-id <id>]
adversa cancel --workspace <name> [--run-id <id>]

# Run tests
mise run test

# Run a specific test
pytest tests/test_module.py::test_function

# Linting
mise run lint
mise run lint-fix  # With auto-fix

# Run Temporal worker (separate process for workflow execution)
mise run worker

# See all available tasks
mise tasks
```

### Traditional Commands (without mise)

```bash
# Install dependencies
uv sync

# Run tests
pytest

# Linting
ruff check .

# Run Temporal worker
python -m adversa.workflow_temporal.worker
```

## High-Level Architecture

Adversa is a **Temporal-based durable workflow CLI** for authorized security testing. The system orchestrates agents through five phases with validated artifacts between each stage.

### Architecture Pattern

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI (Typer)                           │
│  adversa run → submits job to Temporal                       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Temporal Workflow (workflows.py)                │
│  AdversaRunWorkflow sequences phases → activities            │
│  Handles: pause/resume/cancel, config errors, state mgmt     │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│               Activities (activities.py)                     │
│  run_phase_activity → executes agents for each phase         │
│  provider_health_check → validates LLM configuration          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                 Artifact Store (artifacts/)                  │
│  Schema-validated outputs under runs/<workspace>/<run_id>/   │
│  SHA256-indexed catalog with resume support                  │
└─────────────────────────────────────────────────────────────┘
```

### Key Components

1. **CLI Entry Point** (`adversa/cli.py`)
   - Typer-based commands: `init`, `run`, `status`, `resume`, `cancel`
   - Safety gate: `--i-acknowledge` flag required before running scans
   - Repository path validation via `security/scope.py`

2. **Temporal Workflow** (`workflow_temporal/workflows.py`)
   - Durable state machine sequencing through phases: `intake` → `prerecon` → `netdisc` → `recon` → `vuln` → `report`
   - Signal handlers: `pause()`, `resume()`, `cancel()`, `update_config()`
   - Config error recovery: enters "waiting for config" state (up to 24 hours) for missing API keys / 401 errors
   - State tracking: current phase, completed phases, paused/canceled status, last error

3. **Temporal Activities** (`workflow_temporal/activities.py`)
   - `run_phase_activity`: Executes a single phase with 10-minute timeout and 3-retry policy
   - `provider_health_check`: Validates LLM provider configuration

4. **Artifact Store** (`artifacts/store.py`)
   - Manages all run artifacts with schema validation using Pydantic
   - Directory structure per run:
     ```
     runs/<workspace>/<run_id>/
     ├── artifacts/manifest.json      # Run metadata and state
     ├── artifacts/index.json         # SHA256-indexed artifact catalog
     ├── intake/                      # Phase outputs
     ├── prerecon/
     ├── recon/
     ├── vuln/
     ├── report/
     ├── logs/                        # JSONL logs
     └── prompts/                     # LLM prompts/responses
     ```
   - Resume support: skips phases if valid artifacts exist
   - Incremental index building with SHA256 checksums

5. **State Models** (`state/models.py`)
   - Pydantic models: `ManifestState`, `PhaseOutput`, `WorkflowInput`, `WorkflowStatus`, `ArtifactEntry`, `ArtifactIndex`
   - All state is schema-validated with JSON schema export

6. **Configuration** (`config/load.py`, `config/models.py`)
   - Precedence: CLI flags → `adversa.toml` → Environment variables → Defaults
   - Config sections: `[provider]`, `[safety]`, `[run]`
   - Provider support: `anthropic`, `openai_compatible` (custom `base_url`)

7. **Safety Layer** (`security/scope.py`)
   - **Critical**: All target repos must be inside `repos/` directory
   - `ensure_repo_in_repos_root()` validates paths at runtime
   - Raises `ScopeViolationError` if violated

8. **LLM Provider** (`llm/providers.py`)
   - `ProviderClient` validates API keys from environment variables
   - Error classification: `CONFIG_REQUIRED`, `TRANSIENT`, `FATAL`
   - Currently stub implementation (returns "stub-response")

### Configuration System

**Environment overrides:**
- `ADVERSA_PROVIDER` - Provider selection
- `ADVERSA_MODEL` - Model selection

**adversa.toml sections:**
- `[provider]` - LLM provider settings (anthropic/openai_compatible)
- `[safety]` - Safety controls (acknowledgement, safe_mode, network_discovery)
- `[run]` - Runtime settings (workspace_root, repos_root, task_queue)

### Workflow Signals

The workflow supports complex state transitions via Temporal signals:

```
Running → Paused → (resume signal) → Running
Running → WaitingForConfig → (update_config signal) → Running
Running/Paused/Waiting → (cancel signal) → Canceled
```

Signal definitions in `workflow_temporal/signals.py`.

## Development Workflow

### Branch Naming
- Format: `codex/<linear-id>-<short-kebab-summary>`
- One implementation ticket per branch whenever practical

### Definition of Done
- Code merged with tests
- `ruff check .` passes
- `pytest` passes
- New/changed artifacts are schema-valid
- Safety rules are preserved
- Logs/evidence are present where required
- Docs/config examples are updated if behavior changed

### Hard Safety Rules
- Never implement destructive testing in OSS default mode
- Never generate weaponized exploit payloads by default
- Never support brute force, credential stuffing, or production-target assumptions
- Require explicit `--i-acknowledge` flag before scans
- Enforce scope at runtime: all repos must be inside `repos/` directory
- Treat findings as hypotheses until supported by evidence references

## Phase Artifacts

**Markdown-First Architecture**: Phases generate human-readable markdown reports as primary deliverables with minimal JSON for workflow metadata.

Each phase must emit schema-valid artifacts:

- **Intake**: `scope.json`, `plan.json`, `coverage_intake.json`
- **Pre-Recon**: **Markdown-first** with:
  - **Primary**: `pre_recon_analysis.md` - Pentester-friendly 10-section report (architecture, auth, data security, attack surface, vulnerability sinks, etc.)
  - **Metadata**: `pre_recon.json` - Minimal workflow metadata (structured Pydantic validation)
  - **Evidence**: `evidence/baseline.json` - Framework signals, candidate routes, auth signals, vulnerability sinks, data flows
  - **Benefits**: ~40-60% token savings vs dual JSON+markdown format, human-readable/editable, table-formatted
- **Network Discovery**: **Markdown-first** with:
  - **Primary**: `network_discovery.md` - Pentester-friendly 5-section report (hosts, service fingerprints, TLS analysis, port services)
  - **Metadata**: `network_discovery.json` - Minimal workflow metadata
  - **Evidence**: `evidence/baseline.json` - Raw discovery data
  - Tool coverage: subfinder (passive subdomain enum), httpx/curl (HTTP fingerprinting), openssl (TLS), nmap (active port scan - requires explicit opt-in)
  - Scope-enforced host classification (in_scope / out_of_scope)
- **Recon**: `system_map.json`, `attack_surface.json`, auth/authz/data-flow models
- **Vulnerability**: `findings.json`, `risk_register.json`, analyzer evidence
- **Reporting**: `report.md`, `exec_summary.md`, `retest_plan.json`, bundle index/metadata

**Downstream Consumption**: Phases can parse markdown artifacts using `adversa/utils/markdown.py` helpers (`parse_markdown_section`, `extract_tables_from_section`, `extract_file_paths_from_section`)

## Tech Stack

- **Language**: Python 3.11+
- **CLI Framework**: Typer
- **Schema/Validation**: Pydantic v2
- **Orchestration**: Temporal (durable workflows)
- **Agent Framework**: LangChain + LangGraph + DeepAgents
- **Testing**: pytest
- **Linting/Formatting**: ruff
- **Package Manager**: uv
- **Environment Management**: mise-en-place (optional, recommended)
