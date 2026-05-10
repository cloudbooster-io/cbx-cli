# cbx-cli

CloudBooster CLI — plan, audit, and manage cloud infrastructure from your terminal.

## Installation

```bash
# Via Homebrew (macOS / Linux)
brew tap cloudbooster/tap
brew install cbx-cli

# Or download the latest release from GitHub Releases
```

## Quick start

```bash
# Log in to CloudBooster
cbx login

# Log in to your LLM provider
cbx llm login claude

# Generate an architecture plan
cbx plan "static site with auth"
# → writes plan.adr.md and plan.d2 to the current directory

# Audit existing infrastructure (deployed: state file)
cbx audit --pulumi-state state.json
# → outputs JSON findings and writes a markdown report

# Audit declared infrastructure (source: IaC tree)
cbx audit --source ./infra
# → auto-detects Terraform / CloudFormation / Kubernetes / Helm and runs the
#   configured scanners offline (mock by default; --scanners=tfsec,checkov,trivy
#   for the real binaries)
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
| `cbx audit --pulumi-state <file>` | Audit a Pulumi state file (deployed infrastructure) |
| `cbx audit --terraform-state <file>` | Audit a Terraform state file (deployed infrastructure) |
| `cbx audit --source <dir>` | Audit an IaC source tree (Terraform / CloudFormation / Kubernetes / Helm) |
| `cbx audit --iac-type <auto\|terraform\|cloudformation\|k8s\|helm>` | Pin the IaC flavor for source-mode auto-detection |
| `cbx version` | Print version |
| `cbx doctor` | Check installation health |
| `cbx completion` | Generate shell completion |

## Development

### Requirements

- Go 1.24+

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

### Lint

```bash
make vet
make lint
```

## License

Apache-2.0
