# Interactive Shell

Adversa provides an interactive shell mode for operator-driven workflows:

```bash
adversa shell
```

For local development from the repo root, prefer:

```bash
uv run -m adversa
```

The shell uses the same underlying command handlers as the standard Typer CLI commands. Safety checks, acknowledgement requirements, repo path guardrails, and resume validation behavior remain unchanged.

On startup, the shell renders a branded Adversa banner inside a darker terminal-style frame and uses a prompt-bar style input instead of the earlier plain `adversa> ` prompt.
If a committed `assets/adversa_cli_banner.ansi` file exists, the shell prefers that richer terminal banner; otherwise it falls back to `assets/adversa_cli_banner.txt`.

## Slash Commands

- `/help`
  - Show available slash commands and descriptions.
- `/?`
  - Alias for `/help`.
- `/run`
  - Start a workflow run.
- `/status`
  - Show status for a workspace/run.
- `/resume`
  - Resume a paused or waiting workflow.
- `/cancel`
  - Cancel a workflow.
- `/init`
  - Scaffold `adversa.toml` and `scope.template.json`.
- `/config`
  - Show the default config path.
- `/exit`
  - Exit the shell.

## Examples

Start a run directly:

```bash
/run --repo repos/demo --url https://staging.example.com --workspace demo --i-acknowledge
```

Check workflow status:

```bash
/status --workspace demo
```

Resume the latest run in a workspace:

```bash
/resume --workspace demo
```

Cancel a specific run:

```bash
/cancel --workspace demo --run-id abc123def456
```

## Guided Prompts

If a slash command is missing required arguments, shell mode prompts for them interactively instead of failing immediately.

Example:

```text
adversa [/] | /run --workspace demo --i-acknowledge
repo: repos/demo
url: https://staging.example.com
```

## Command Completion

When input starts with `/`, the shell uses `prompt_toolkit` completion for known slash commands.

## Safety Notes

- `run` still requires `--i-acknowledge` unless enabled in config.
- Repository paths must still resolve under the configured `repos/` root.
- Production-like targets remain blocked unless explicitly allowed by config.
- Resume URL mismatch protection is unchanged from non-interactive mode.
