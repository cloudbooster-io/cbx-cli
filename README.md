# cbx-cli

[![Release](https://img.shields.io/github/v/release/cloudbooster-io/cbx-cli)](https://github.com/cloudbooster-io/cbx-cli/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/cloudbooster-io/cbx-cli.svg)](https://pkg.go.dev/github.com/cloudbooster-io/cbx-cli)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

`cbx` is the CloudBooster CLI — plan and audit cloud infrastructure from your terminal.

- **`cbx plan`** turns a natural-language intent into an architecture plan: a `plan.md` with an embedded Mermaid diagram (D2 optional). Bring your own LLM — an Anthropic or OpenAI API key, or a local Claude Code / Codex CLI. No CloudBooster account required.
- **`cbx audit aws`** audits a live AWS account **read-only** via the AWS SDK, grounds every finding in CloudBooster's curated AWS knowledge, and writes a markdown report with severity-mapped exit codes for CI.

`cbx-cli` is the open-source (Apache-2.0) edition of CloudBooster's tooling. It is also designed to be embedded as a Go library — see [Using as a library](#using-as-a-library).

## Installation

**macOS** — Homebrew (cask):

```bash
brew tap cloudbooster-io/tap
brew install --cask cbx-cli
```

**Linux** — `.deb` / `.rpm` from [GitHub Releases](https://github.com/cloudbooster-io/cbx-cli/releases):

```bash
sudo dpkg -i cbx-cli_*_linux_amd64.deb   # Debian / Ubuntu
sudo rpm  -i cbx-cli_*_linux_amd64.rpm   # Fedora / RHEL
```

**Windows** — Scoop:

```powershell
scoop bucket add cloudbooster https://github.com/cloudbooster-io/scoop-bucket
scoop install cbx-cli
```

**From source** (Go 1.25+):

```bash
go install github.com/cloudbooster-io/cbx-cli/cmd/cbx@latest
```

Pre-built archives for any platform are on the [releases page](https://github.com/cloudbooster-io/cbx-cli/releases). Release checksums are signed with keyless [Cosign](https://github.com/sigstore/cosign) and every release ships a Syft SBOM. Once installed, `cbx upgrade` updates in place and `cbx doctor` checks installation health.

## Quick start

```bash
# (optional) Log in to CloudBooster — not required for `cbx plan`
cbx login

# Configure a model for `cbx plan` (pick one):
cbx llm api login claude     # Anthropic API key (bring your own)
cbx llm cli list             # or a local CLI — Claude Code / Codex — no API key needed

# Generate an architecture plan
cbx plan "static site with auth"

# Audit a live AWS account (read-only)
cbx audit aws
```

## Auditing AWS

`cbx audit aws` discovers resources across an account via the Cloud Control API (plus native per-service fallbacks), enriches them with read-only describe calls, fetches CloudBooster's curated AWS knowledge for the discovered resource types, and runs Claude Code locally (`claude -p`) to ground each finding in that knowledge. The result is a markdown report (`<accountID>_audit_report.md`), an interactive findings TUI on a terminal, and structured JSON on stdout with `-o json`.

You need:

- **AWS credentials with read access** — the default SDK credential chain, a named profile, or `--credentials-file`. A least-privilege read-only IAM policy is provided in [`docs/cbx-audit-aws-iam.json`](docs/cbx-audit-aws-iam.json); the AWS-managed `ReadOnlyAccess` policy is a valid superset. The audit never mutates anything and deliberately avoids data-plane reads (no `s3:GetObject`, no `secretsmanager:GetSecretValue`).
- **Claude Code on PATH** — the grounded analysis runs through your local `claude` install, so LLM usage is billed to you, not CloudBooster. Cap a run's spend with `--llm-max-cost` (default $2.00).

```bash
# Default profile, its configured region
cbx audit aws

# Named profile across specific regions (repeatable; 'all' fans out across every enabled region)
cbx audit aws prod --region us-east-1 --region us-west-2

# Paste an AWS console URL — the region is parsed from the hostname
cbx audit aws https://us-east-1.console.aws.amazon.com/console/home
```

Useful flags:

| Flag | Purpose |
|------|---------|
| `--region <r>` | Region to audit (repeatable; `all` = every enabled region) |
| `--dry-run` | Print the audit plan (regions, resource types, estimated calls) and exit without touching AWS or the LLM |
| `--diagnose` | Emit every denied API call plus a recommended IAM policy patch |
| `--llm-max-cost <usd>` | Cost ceiling for the grounded analysis (0 disables) |
| `--strict` | Also gate the exit code on discovery-integrity warnings (CI) |
| `--no-tui` | Skip the interactive findings TUI (implied by `--json`, `--quiet`, non-TTY) |

The exit code reflects the most severe finding, so the audit drops straight into CI:

| Exit code | Meaning |
|-----------|---------|
| `0` | No findings |
| `1` | Worst finding is *info* (also used for runtime errors) |
| `2` | Worst finding is *warning* |
| `3` | Worst finding is *high* or *critical* |

## Planning

`cbx plan "<intent>"` opens an interactive chat TUI by default; `--no-tui` runs one-shot. It writes `plan.md` with an embedded Mermaid diagram to the output dir (`--output-dir`). Plan is **BYO-LLM**: configure a provider once with `cbx llm api login claude|codex` (API key, stored in the OS keyring) or use a local executor that's already on PATH (`cbx llm cli list` shows what was detected); pick the default with `cbx llm default <name>`.

```bash
cbx plan "three-tier web app with a Postgres backend"
cbx plan "static site with auth" --diagram d2      # also emit a standalone plan.d2
cbx plan "event-driven ingest pipeline" --html      # serve an HTML preview locally
cbx plan "static site with auth" --variants 3       # generate alternatives
```

## Commands

| Command | Description |
|---------|-------------|
| `cbx plan "<intent>"` | Generate an architecture plan from a natural-language intent |
| `cbx audit aws [profile\|console-url]` | Audit a live AWS account (read-only, grounded in CloudBooster's AWS knowledge) |
| `cbx llm api login <claude\|codex>` | Store an API key for an LLM provider (bring your own key) |
| `cbx llm cli list` | List local CLI executors (Claude Code, Codex CLI) detected on PATH |
| `cbx llm list` | Show all configured API providers and CLI executors |
| `cbx llm default <name>` | Set the default LLM provider |
| `cbx login` / `cbx logout` / `cbx status` | Manage the CloudBooster session |
| `cbx config get\|set\|list` | Read and write persistent cbx settings |
| `cbx telemetry status\|enable\|disable` | Manage anonymous error reports and usage metrics |
| `cbx doctor` | Check installation health |
| `cbx upgrade` | Upgrade cbx to the latest release |
| `cbx version` | Print version |
| `cbx completion` | Generate shell completion |

Run `cbx --help` (or `cbx <command> --help`) for the full command set, including `cbx auth` and `cbx env`.

### Global flags & environment

- `-o json` — machine-readable output; every payload is wrapped in a stable `{"data": ..., "error": ...}` envelope.
- `-q, --quiet` — suppress non-error output; `--no-color` — disable styling.
- `CBX_NO_UPDATE_CHECK=1` (or `CI=true`) — disable the background update check.

## Using as a library

The `pkg/` tree is the public, semver-stable surface — `pkg/cmd`, `pkg/auth`, `pkg/audit`, `pkg/config`, `pkg/output`. `cmd/cbx/main.go` is deliberately tiny: all command wiring lives in `pkg/cmd`, so downstream tools can embed the whole CLI or just the audit pipeline:

```go
import "github.com/cloudbooster-io/cbx-cli/pkg/cmd"

func main() {
	err := cmd.Execute()
	os.Exit(cmd.ExitCode(err))
}
```

`pkg/audit` exposes the state-file parsers (Terraform / Pulumi) and the finding-provider pipeline for building non-LLM audits; that path is fully offline — zero network calls.

## Development

Requires Go 1.25+.

```bash
make build              # → bin/cbx
make test               # unit tests + local e2e
make test-e2e           # e2e tests only
make vet && make lint   # go vet + golangci-lint
make codegen-check      # verify the generated API client is in sync (CI gate)

# Run a single test
go test ./internal/audit -run TestParsePulumiState
```

> `make test-e2e-staging` targets CloudBooster's internal staging API and is maintainer-only; everything else runs for everyone.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). To report a security issue, please follow [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
