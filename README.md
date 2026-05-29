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
# Log in to CloudBooster
cbx login

# Log in to your LLM provider
cbx llm login claude

# Generate an architecture plan
cbx plan "static site with auth"
# → writes plan.md and plan.d2 to the current directory

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
| `cbx llm login <provider>` | Log in to an LLM provider (claude, openai, ollama) |
| `cbx llm logout <provider>` | Log out of an LLM provider |
| `cbx llm list` | List configured LLM providers |
| `cbx llm default <provider>` | Set the default LLM provider |
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
