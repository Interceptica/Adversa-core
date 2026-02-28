# adversa.toml Reference

This document describes the currently supported configuration fields for Adversa.

## Location

By default, Adversa reads `adversa.toml` from the current working directory.

You can override it with:

```bash
adversa run --config /path/to/adversa.toml
```

## Precedence

Configuration precedence is:

1. CLI flags
2. `adversa.toml`
3. Environment variables
4. Safe defaults

Currently implemented environment overrides:

- `ADVERSA_PROVIDER` (`anthropic`, `openai_compatible`, or `router`)
- `ADVERSA_MODEL`

## Full Example

```toml
[provider]
provider = "anthropic"
model = "claude-3-5-sonnet-latest"
api_key_env = "ANTHROPIC_API_KEY"
base_url = "https://api.openai.com/v1"

[safety]
acknowledgement = false
safe_mode = true
network_discovery_enabled = false

[run]
workspace_root = "runs"
repos_root = "repos"
task_queue = "adversa-task-queue"

[[rules.focus]]
description = "Prioritize beta admin API"
type = "subdomain"
value = "beta-admin"
phases = ["recon", "vuln"]

[[rules.focus]]
description = "Focus on profile endpoints"
type = "path"
value = "/api/v2/user-profile*"
phases = ["recon", "vuln"]

[[rules.avoid]]
description = "Do not touch logout"
type = "path"
value = "/logout"

[[rules.avoid]]
description = "Keep analysis inside authorized repository roots"
type = "repo_path"
value = "repos/target"
phases = ["intake", "prerecon", "recon", "vuln", "report"]
```

## [provider]

- `provider` (string, default: `"anthropic"`)
  - Supported values:
    - `anthropic`
    - `openai_compatible`
    - `router`

- `model` (string, default: `"claude-3-5-sonnet-latest"`)
  - Model identifier passed to provider client logic.

- `api_key_env` (string, default: `"ANTHROPIC_API_KEY"`)
  - Name of the environment variable that stores the provider key.
  - Do not put raw secret values in `adversa.toml`.

- `base_url` (string, optional)
  - Used for `openai_compatible` style endpoints.

## [safety]

- `acknowledgement` (bool, default: `false`)
  - If `false`, `adversa run` requires `--i-acknowledge`.
  - If `true`, explicit flag is not required.

- `safe_mode` (bool, default: `true`)
  - Keeps run behavior in safe verification mode.

- `network_discovery_enabled` (bool, default: `false`)
  - Reserved for controlled opt-in network discovery behavior.

## [run]

- `workspace_root` (string, default: `"runs"`)
  - Root output directory for run artifacts.

- `repos_root` (string, default: `"repos"`)
  - Allowed root for target repositories.
  - `adversa run --repo ...` must resolve inside this path.

- `task_queue` (string, default: `"adversa-task-queue"`)
  - Temporal task queue for workflow/activities.

## [rules]

Adversa now exposes user-facing rule groups:

- `[[rules.focus]]`
- `[[rules.avoid]]`

Each rule entry supports:

- `description` (string, optional)
  - Human-readable audit text shown when the rule is applied.

- `type` (string, required)
  - Supported operator-facing values:
    - `subdomain`
    - `path`
    - `host`
    - `method`
    - `repo_path`
    - `tag`
  - Internal targeting values still accepted when you need direct execution control:
    - `phase`
    - `analyzer`

- `value` (string, required)
  - Match expression for the selected `type`.
  - Glob matching is supported for `host`, `subdomain`, `path`, `method`, and `repo_path`.
  - `url_path` is accepted as an alias for `value` in TOML.

- `phases` (array of strings, optional)
  - Restricts the rule to the listed phases.
  - If omitted, the rule applies to all phases.

Behavior notes:

- `focus` deterministically prioritizes analyzers whose execution surfaces overlap the matched runtime target. Name ordering remains the stable tie-breaker.
- `avoid` is a hard runtime block when the current phase target itself matches the rule boundary.
- `avoid` also removes analyzers whose surfaces would cross a disallowed target boundary during execution.
- Applied rules are logged to `logs/tool_calls.jsonl` with the resolved runtime target for auditability.

Only the grouped `[[rules.focus]]` and `[[rules.avoid]]` format is supported. The older flat `[[rules]]` form is not accepted.

## Generated Defaults

`adversa init` scaffolds a starter `adversa.toml` with safe defaults.
