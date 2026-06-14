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

## What a real run looks like

Below is genuine `cbx audit aws` output (cbx `v0.1.0`, grounded with the Codex
CLI) against a small, deliberately-misconfigured serverless stack — an HTTP API
Gateway fronting an admin-privileged Lambda backed by a DynamoDB table. Account
IDs, resource IDs and ARNs are scrubbed; nothing else is edited.

```console
$ cbx audit aws --region eu-central-1 --no-tui

20 findings    [CRITICAL] × 2    [HIGH] × 3    [WARNING] × 11    [INFO] × 4

CRITICAL · 2

  [CRITICAL]  IAM role cbx-serverless-lambda-admin has AdministratorAccess
    iam | role | cbx-serverless-lambda-admin | eu-central-1

    Remove AdministratorAccess and attach a least-privilege policy scoped to the exact DynamoDB,
    Secrets Manager, CloudWatch Logs, and other APIs the functions require.

    rule LLM-codex-9403a4d9

  [CRITICAL]  Unauthenticated API route invokes admin-privileged Lambda
    apigatewayv2 | route | a1b2c3d4e5|r5t6y7u | eu-central-1

    Require JWT, IAM, or Lambda authorization on the route, and replace the Lambda execution role
    with least-privilege permissions scoped to only the resources the function needs.

    rule LLM-codex-cfd35275

HIGH · 3

  [HIGH]  No CloudTrail covers eu-central-1                          account:123456789012
  [HIGH]  Root account MFA is disabled                               account:123456789012
  [HIGH]  Default EBS encryption is disabled in eu-central-1         account:123456789012

WARNING · 11

  [WARNING]  DynamoDB table cbx-serverless-items has point-in-time recovery disabled
  [WARNING]  DynamoDB table cbx-serverless-items lacks deletion protection
  [WARNING]  API Gateway access logging is disabled
  [WARNING]  Lambda cbx-serverless-api has no dead-letter queue
  ... 7 more

INFO · 4

  [INFO]  Review secret-shaped Lambda environment variable on cbx-serverless-api
  ... 3 more

[OK] report 123456789012_audit_report.md
  open in browser 123456789012_audit_report.html
```

The worst finding is `critical`, so the command **exits `3`** (see the table
above) — drop-in for a CI gate. The two CRITICALs compound: a public route with
no authorizer in front of a Lambda that runs as account admin is an
internet → account-takeover path, which the audit surfaces as one finding.

Every finding carries its grounding. With `-o json` you get the stable
`{data, error}` envelope, and each finding cites the CloudBooster knowledge
primitive that justifies it under `cb_source`:

```json
{
  "rule_id": "LLM-codex-ac715732",
  "title": "AdministratorAccess attached to cbx-serverless-lambda-admin",
  "severity": "critical",
  "resource": "aws://eu-central-1/AWS::IAM::Role/cbx-serverless-lambda-admin",
  "service": "IAM",
  "remediation": "Replace AdministratorAccess with a least-privilege Lambda execution policy scoped to the exact DynamoDB, logs, and other resources the functions require.",
  "cb_source": {
    "tool": "aws_lookup_primitive",
    "key": "aws:iam/role@v1",
    "snippet": "Avoid wildcard actions and resources: never use Action: \"*\" or Resource: \"*\" in production policies."
  }
}
```

> The grounded audit needs a grounding LLM CLI on your `PATH` and authenticated
> (`claude` or `codex` — verify with `cbx llm cli test claude-code`) plus network
> access to the CloudBooster knowledge API. See the
> [full guide](https://docs.cloudbooster.io) for the complete walkthrough.

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
