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

- `ADVERSA_PROVIDER` (`anthropic` or `openai_compatible`)
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
```

## [provider]

- `provider` (string, default: `"anthropic"`)
  - Supported values:
    - `anthropic`
    - `openai_compatible`

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

## Generated Defaults

`adversa init` scaffolds a starter `adversa.toml` with safe defaults.
