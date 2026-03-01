# Environment Management with mise

[mise-en-place](https://mise.jdx.dev) is a polyglot development environment manager that provides reproducible environments across the team.

## Why mise?

- **Version consistency**: Automatically manages Python versions, uv, and optional security tools
- **Task orchestration**: Simple task runner for common operations (`mise run test`, `mise run worker`)
- **Environment activation**: Automatic environment setup when entering the project directory
- **Tool discoverability**: `mise tasks` shows all available commands
- **Optional dependencies**: Install security tools (nmap, subfinder) only when needed

## Installation

### macOS/Linux

```bash
# Install mise
curl https://mise.run | sh

# Or via Homebrew (macOS)
brew install mise

# Or via apt (Ubuntu/Debian)
sudo install -dm 755 /etc/apt/keyrings
wget -qO - https://mise.jdx.dev/gpg-key.pub | gpg --dearmor | sudo tee /etc/apt/keyrings/mise-archive-keyring.gpg 1> /dev/null
echo "deb [signed-by=/etc/apt/keyrings/mise-archive-keyring.gpg arch=amd64] https://mise.jdx.dev/deb stable main" | sudo tee /etc/apt/sources.list.d/mise.list
sudo apt update
sudo apt install -y mise
```

### Shell Integration

Add to your shell configuration:

```bash
# For bash (~/.bashrc)
eval "$(mise activate bash)"

# For zsh (~/.zshrc)
eval "$(mise activate zsh)"

# For fish (~/.config/fish/config.fish)
mise activate fish | source
```

Restart your shell or run `source ~/.bashrc` (or equivalent).

## Quick Start

```bash
# Clone the repo
cd /path/to/Adversa-core

# Install all tools defined in .mise.toml (Python 3.11, etc.)
mise install

# Install Python dependencies via uv
mise run install

# Run tests
mise run test

# Start Temporal worker
mise run worker

# See all available tasks
mise tasks
```

## Available Tasks

| Task | Command | Description |
|------|---------|-------------|
| `install` | `mise run install` | Install Python dependencies via `uv sync` |
| `test` | `mise run test` | Run pytest test suite |
| `test-watch` | `mise run test-watch` | Run pytest in watch mode |
| `lint` | `mise run lint` | Run ruff linter |
| `lint-fix` | `mise run lint-fix` | Run ruff with auto-fix |
| `worker` | `mise run worker` | Start Temporal workflow worker |
| `cli` | `mise run cli` | Run Adversa CLI |
| `init` | `mise run init` | Initialize Adversa config |

## Configuration

Edit `.mise.toml` in the project root to customize:

### Tool Versions

```toml
[tools]
python = "3.11"  # Change Python version
uv = "latest"    # Pin uv version if needed
```

### Environment Variables

```toml
[env]
ADVERSA_ENV = "development"
ADVERSA_PROVIDER = "anthropic"
# Add more as needed
```

### Custom Tasks

```toml
[tasks.my-custom-task]
description = "My custom task"
run = "python scripts/my_script.py"
```

## Optional Security Tools

For network discovery phase (when implemented), you can optionally manage security tools via mise:

```toml
# Add to .mise.toml [tools] section
[tools]
nmap = "7.94"
subfinder = "latest"
httpx = "latest"
```

Then install with:

```bash
mise install nmap
mise install subfinder
```

**Note**: These tools can also be installed system-wide via package managers. mise management is optional.

## Environment-Specific Configuration

Create `.mise.local.toml` for local overrides (gitignored):

```toml
# .mise.local.toml
[env]
ADVERSA_PROVIDER = "openai_compatible"
ADVERSA_MODEL = "gpt-4"
OPENAI_BASE_URL = "http://localhost:1234/v1"
```

## Troubleshooting

### mise not found after installation

Ensure shell activation is in your shell config:

```bash
echo 'eval "$(mise activate bash)"' >> ~/.bashrc
source ~/.bashrc
```

### Wrong Python version active

```bash
# Check current version
python --version

# Verify mise is managing it
mise current python

# Reinstall if needed
mise install python@3.11
```

### Tasks not running

```bash
# Verify .mise.toml is valid
mise doctor

# List available tasks
mise tasks

# Run with verbose output
mise run --verbose test
```

## Migration from Manual Setup

**Before (manual):**
```bash
# Install Python 3.11 manually
# Install uv manually
uv sync
pytest
python -m adversa.workflow_temporal.worker
```

**After (with mise):**
```bash
mise install        # Installs Python 3.11, uv automatically
mise run install    # Runs uv sync
mise run test       # Runs pytest
mise run worker     # Runs worker
```

## References

- [mise documentation](https://mise.jdx.dev)
- [mise configuration reference](https://mise.jdx.dev/configuration.html)
- [mise tasks](https://mise.jdx.dev/tasks/)
- [mise environments](https://mise.jdx.dev/environments.html)
