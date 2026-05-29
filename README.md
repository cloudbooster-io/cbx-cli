# cbx-cli

CloudBooster CLI — plan, audit, and manage cloud infrastructure from your terminal.

## Installation

```bash
# Via Homebrew (macOS / Linux)
brew tap cloudbooster-io/tap
brew install cbx-cli

# Or download the latest release from GitHub Releases:
# https://github.com/cloudbooster-io/cbx-cli/releases
```

## Quick start

```bash
# (optional) Log in to CloudBooster — not required for `cbx plan`
cbx login

# Configure an LLM provider (bring your own API key)
cbx llm api login claude        # or: codex

# Generate an architecture plan
cbx plan "static site with auth"
# → writes plan.md + plan.mermaid to the current directory (--diagram d2 for D2)

# Audit a live AWS account (read-only, via the AWS SDK)
cbx audit aws
# → audits the default AWS profile in its configured region, grounds the
#   findings in CloudBooster's curated AWS knowledge, and writes a markdown
#   report. Requires `claude` (Claude Code) on PATH for the grounded analysis.

# Audit a named profile across specific regions
cbx audit aws prod --region us-east-1 --region us-west-2
```

## Commands

| Command | Description |
|---------|-------------|
| `cbx login` | Log in to CloudBooster |
| `cbx logout` | Log out of CloudBooster |
| `cbx status` | Show authentication status |
| `cbx llm api login <claude\|codex>` | Store an API key for an LLM provider (bring your own key) |
| `cbx llm cli list` | List local CLI executors (Claude Code, Codex CLI) detected on PATH |
| `cbx llm list` | Show all configured API providers and CLI executors |
| `cbx llm default <name>` | Set the default LLM provider for plan/audit |
| `cbx plan "<intent>"` | Generate an architecture plan |
| `cbx audit aws [profile]` | Audit a live AWS account (read-only, via the AWS SDK; grounded in CloudBooster's AWS knowledge) |
| `cbx version` | Print version |
| `cbx doctor` | Check installation health |
| `cbx completion` | Generate shell completion |
| `cbx upgrade` | Upgrade cbx to the latest release |

Run `cbx --help` (or `cbx <command> --help`) for the full command set,
including `cbx auth`, `cbx config`, `cbx env`, and `cbx telemetry`.

## Development

### Requirements

- Go 1.25+

### Build

```bash
make build
```

### Test

```bash
# Run all tests (unit + E2E)
make test

# Run E2E tests only
make test-e2e

# Run E2E tests against staging
make test-e2e-staging
```

> `make test-e2e-staging` targets CloudBooster's internal staging API and is
> for maintainers; `make test` and `make test-e2e` run for everyone.

### Lint

```bash
make vet
make lint
```

## License

Apache-2.0
