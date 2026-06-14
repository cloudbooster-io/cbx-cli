<div align="center">

# `cbx`

### Audit it after you ship it.

**The CloudBooster CLI — AWS audits grounded in curated cloud expertise<br>instead of generic advice.**

[![CI](https://github.com/cloudbooster-io/cbx-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/cloudbooster-io/cbx-cli/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/cloudbooster-io/cbx-cli)](https://github.com/cloudbooster-io/cbx-cli/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/cloudbooster-io/cbx-cli.svg)](https://pkg.go.dev/github.com/cloudbooster-io/cbx-cli)
[![Go Report Card](https://goreportcard.com/badge/github.com/cloudbooster-io/cbx-cli)](https://goreportcard.com/report/github.com/cloudbooster-io/cbx-cli)
[![License](https://img.shields.io/github/license/cloudbooster-io/cbx-cli)](LICENSE)

</div>

---

## Point it at AWS. Get grounded findings.

```console
$ cbx audit aws prod --region eu-central-1

  HIGH     S3 bucket "data-prod" has no public-access block
  WARNING  CloudTrail "main" has log file validation disabled
  WARNING  IAM user "deploy-bot" has a console password but no MFA
  INFO     2 unattached Elastic IPs accruing charges
                                            (output abridged)
```

`cbx audit aws` reads a live account through the AWS SDK — **strictly
read-only** — and grounds every finding in CloudBooster's curated AWS
knowledge base, analyzed by a local LLM CLI. You get findings that cite
*why* something matters, written to a markdown report.

The grounding CLI is your choice via `--llm-executor`:
[Claude Code](https://github.com/anthropics/claude-code) (`claude -p`, the
default) or the [Codex CLI](https://github.com/openai/codex) (`codex exec`,
with `--llm-executor codex`). The selected binary must be on your `PATH` and
own its own authentication.

Audit the default profile, a named one, or several regions at once:

```bash
cbx audit aws --region us-east-1                       # default: Claude Code
cbx audit aws --region us-east-1 --llm-executor codex  # ground with Codex
cbx audit aws prod --region us-east-1 --region us-west-2
```

## Install

| Platform | |
|---|---|
| **macOS** | `brew tap cloudbooster-io/tap && brew install --cask cbx-cli` |
| **Linux / macOS script** | `curl -sSL https://install.cloudbooster.io/cbx \| sh` — checksum-verified, installs to `/usr/local/bin` or `~/.local/bin`, no implicit sudo |
| **Debian / Ubuntu** | `sudo dpkg -i cbx-cli_*_linux_amd64.deb` — from [Releases](https://github.com/cloudbooster-io/cbx-cli/releases) |
| **Fedora / RHEL** | `sudo rpm -i cbx-cli_*_linux_amd64.rpm` — from [Releases](https://github.com/cloudbooster-io/cbx-cli/releases) |
| **Windows** | `scoop bucket add cloudbooster https://github.com/cloudbooster-io/scoop-bucket && scoop install cbx-cli` |
| **Anything else** | grab an archive from [GitHub Releases](https://github.com/cloudbooster-io/cbx-cli/releases) |

Every release is Cosign-signed and ships a Syft SBOM. Once installed,
`cbx upgrade` keeps you current and `cbx doctor` checks your setup.

## Quick start

```bash
# Audit (read-only; needs AWS credentials + a grounding CLI on PATH)
cbx audit aws

# Verify the grounding CLI is installed and authed (claude-code or codex)
cbx llm cli test claude-code

# Optional: choose Codex as the default grounding executor
cbx llm default codex

# Optional: pin the model an executor runs with
cbx llm model claude-code claude-opus-4-8
cbx llm model codex gpt-5-codex
```

The grounding CLI must be on `PATH` and own its own auth — for an API
provider, run `cbx llm api login <provider>`. `--llm-executor` defaults to
whatever `cbx llm default` names (when it's `claude-code` or `codex`),
otherwise `claude-code`. Pin a one-off model with `--llm-model`, and cap a
run's spend with `--llm-max-cost` (USD) — note the cap is enforced only for
`claude-code`; `codex exec` reports no per-run cost, so it's a no-op there.

`cbx login` is optional — it unlocks CloudBooster account features, but
auditing works anonymously.

## Built for scripting

Every command takes `-o json` (a stable `{data, error}` envelope), `-q/--quiet`,
and `--no-color`. Audit exit codes encode the worst finding, man-page style:

| Exit code | Meaning |
|:---:|---|
| `0` | clean — no findings |
| `1` | worst finding: **info** |
| `2` | worst finding: **warning** |
| `3` | worst finding: **high / critical** |

```bash
# CI gate: tolerate info/warning, fail the pipeline on high or critical
cbx audit aws -o json -q || [ $? -lt 3 ]
```

## Use it as a Go library

`pkg/` is a semver-stable public API — `cbx` is built to be embedded:

```go
import (
    "github.com/cloudbooster-io/cbx-cli/pkg/audit" // programmatic audits, Pulumi/Terraform state parsing
    "github.com/cloudbooster-io/cbx-cli/pkg/cmd"   // embed the full CLI in your own tool
)
```

`pkg/audit` also exposes a fully offline path (state-file parsing, no LLM, no
network) alongside `pkg/auth`, `pkg/config`, and `pkg/output`.

<details>
<summary><b>Full command reference</b></summary>

<br>

| Command | Description |
|---------|-------------|
| `cbx audit aws [profile]` | Audit a live AWS account (read-only, grounded in CloudBooster's AWS knowledge) |
| `cbx llm api login <claude\|codex>` | Store an API key for an LLM provider (bring your own key) |
| `cbx llm cli list` | List local CLI executors (Claude Code, Codex CLI) detected on PATH |
| `cbx llm list` | Show all configured API providers and CLI executors |
| `cbx llm default <name>` | Set the default LLM provider |
| `cbx llm model [name] [model]` | Show or pin the model a provider/executor uses (`--clear` reverts) |
| `cbx login` / `cbx logout` / `cbx status` | CloudBooster account session |
| `cbx doctor` | Check installation health |
| `cbx upgrade` | Upgrade cbx to the latest release |
| `cbx completion` | Generate shell completion |
| `cbx version` | Print version |

Run `cbx --help` (or `cbx <command> --help`) for the full set, including
`cbx auth`, `cbx config`, `cbx env`, and `cbx telemetry`.

</details>

## Development

Go 1.25+ and `make` are all you need:

```bash
make build      # → bin/cbx
make test       # unit + local e2e
make vet lint   # static checks
```

(`make test-e2e-staging` targets CloudBooster's internal staging API and is
maintainer-only.) Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

---

<div align="center">

Apache-2.0 · [Changelog](CHANGELOG.md) · [Security policy](SECURITY.md) · [Code of Conduct](CODE_OF_CONDUCT.md)

</div>
