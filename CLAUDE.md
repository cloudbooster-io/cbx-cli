# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common commands

```sh
make build              # → bin/cbx, with -ldflags injecting Version/Commit/Date into pkg/cmd
make test               # go test ./... (unit + local e2e)
make test-e2e           # go test -v ./e2e/...
make test-e2e-staging   # e2e against https://api.staging.cloudbooster.io (build tag: e2e_staging)
make vet                # go vet ./...
make lint               # golangci-lint run ./...
make codegen            # regenerate core/api/v1/client.gen.go from api/openapi.yaml
make codegen-check      # codegen + fail if client.gen.go drifted (matches CI gate)

# Run a single test
go test ./internal/audit -run TestParsePulumiState
go test -v -tags=e2e_staging ./e2e -run TestStaging_Login
```

CI (GitLab) runs `validate` (vet + build), `codegen-check`, `go test ./...`, mermaid fixture render, an `e2e-matrix` over linux+darwin runners, and an `e2e-staging` job that gates merges. Smoke-brew runs only on tags. Go version pinned to 1.25 in `.gitlab-ci.yml` (module declares 1.25.0).

## Open-core context (load-bearing)

`cbx-cli` is the **OSS Apache-2.0** edition. A sibling proprietary `cb-cli` (currently a placeholder in `../cb-cli/`) **depends on `cbx-cli` as a library — never forks**. That dependency direction is the entire reason for the layered layout below: `pkg/` is the contract `cb-cli` consumes. See `../platform-app/agent-arch-talks/rework-2.5.1/01-strategy.md` and `adrs/adr-001-open-core-split.md` for the why.

Implications you must respect:
- **Any breaking change in `pkg/` is a breaking change for `cb-cli`.** Treat `pkg/auth`, `pkg/config`, `pkg/output`, `pkg/cmd` as semver-public.
- **`cbx audit` is fully offline / zero CB API calls** — works without a CloudBooster account. Don't add hidden network calls to the audit path; mock scanners are the default specifically to keep this property.
- **`cbx plan` is BYO-LLM by default** (anonymous tier; user pays the LLM provider, CB pays nothing). Keep it functional without a CB login.
- **State parsers in `internal/audit/parsers/` are shared substrate** with the hosted "import existing infrastructure" feature in `platform-app`. Changing `DiscoveredResource` shape or parser semantics has cross-repo impact — coordinate.
- A planned `cbx mcp serve` subcommand will embed an MCP server (Day-2 feature, not yet shipped). When it lands, it must proxy the same `api.cloudbooster.io/v1/*` contract that `cbx-mcp` (Python sibling) uses.

## Repository layout — the layering rule

```
cmd/cbx/            thin main; just calls pkg/cmd.Execute / ExitCode
pkg/                public, importable surface — auth/, config/, output/, cmd/
core/               cross-module shared logic — core/api/v1/ (generated), core/plan/
internal/           private to cbx-cli — audit/, plan/, llm/, tui/, output/, config/, …
```

- `cmd/cbx/main.go` is **deliberately tiny** (10 lines). All cobra wiring lives in `pkg/cmd/` so it can be embedded by `cb-cli`.
- `pkg/auth`, `pkg/config`, `pkg/output` are **pure facades**: type aliases and `var X = internal.X` re-exports only. Don't add logic here — implement in `internal/<pkg>` and re-export.
- `core/api/v1/client.gen.go` is generated from `api/openapi.yaml` via `tools/codegen/generate.sh` (uses `go tool oapi-codegen`). Never hand-edit; CI's `codegen-check` job will fail. Hand-written companions (`client.go`, `auth.go`, `retry.go`, `ratelimit.go`) wrap the generated client.
- The API target is the **public** `api.cloudbooster.io/v1/*` surface (anonymous → free → paid tiers, API-key auth). Do **not** call the platform-app **internal** API at `app.cloudbooster.io/api/v1/*` (cookie + CSRF, free to evolve, web-only).
- `internal/audit` and `internal/plan` are the two large feature areas; both have a CLI entry in `pkg/cmd/{audit,plan}.go` and a Bubble Tea TUI in `internal/tui/{audit,chat}`.

## Audit pipeline

`cbx audit --pulumi-state X | --terraform-state Y` flows: `pkg/cmd/audit.go` → `internal/audit/runner.Collect` → `ParseState` (delegates to `internal/audit/parsers/{pulumi,terraform}_state.go`) → `RunProvidersWithProgress` over `FindingProvider`s. Real scanner adapters (tfsec/checkov/prowler/trivy) live in `internal/audit/adapter_*.go`; **default is `MockScanners` (zero network, no external binaries)** unless `--scanners=...` is passed.

Exit codes are not 0/1: `audit.ExitCodeError` propagates from `Execute` through `ExitCode` in `pkg/cmd/execute.go`. Severity mapping is info→1, warning→2, high/critical→3 (`internal/audit/exit.go`). Don't replace this with a generic `os.Exit(1)`.

State-file parsing has a 100 MB guard with a `--yes` bypass (see `Options.Yes` in `internal/audit/types.go`); large fixtures must respect this in tests.

## Plan pipeline

`cbx plan "<intent>"` runs either headless (`pkg/cmd/plan.go:runOneShot`) or in a Bubble Tea chat TUI (`internal/tui/chat`). The plan engine itself is in `core/plan/` (importable by other modules); `internal/plan/` is the REPL/command wiring on top. LLM providers (Claude, Codex/OpenAI) are in `internal/core/llm`, with credentials in the OS keyring via `internal/core/auth/keyring.go`.

A plan run requires an LLM provider configured (`cbx llm login claude|openai|ollama`) — without it `runE` returns early. Output artifacts are `plan.adr.md` + `plan.d2` (or `--diagram-format mermaid`) written to the working directory; HTML preview is opt-in via `--preview`.

## Output / JSON contract

All commands respect a global `--json` flag. JSON output **must** go through `internal/output.WriteJSON` / `PrintJSON`, which wraps payloads in an `Envelope{Data, Error}`. Errors emitted as JSON use `JSONError` / `JSONErrorf` to build the `ErrDetail`. Don't directly `json.Marshal` to stdout — that breaks the wrapper contract and the downstream `cb-cli` consumers depending on it via `pkg/output`.

Styled (color/spinner) output flows through `output.Configure(noColor, quiet)` set in the root cobra `PersistentPreRunE`. Respect `IsQuiet()` and `Enabled()` rather than reading the cobra flags directly from inside `internal/`.

## Update banner

`pkg/cmd/execute.go` runs a 3-second background update check in parallel with the command, then prints a banner to stderr at the end. It's suppressed in `CI=true`, `CB_NO_UPDATE_CHECK=1`, when `--quiet`/`--json`, or for the `version` and `upgrade` subcommands. New subcommands that emit machine output should make sure they don't fight with this banner (it goes to stderr, so pipelines reading stdout are safe).

## Workflow specifics for this repo

- **Forge is GitLab.** Use `glab` for MR / pipeline / issue interaction — never raw `curl`. The branch model uses `vibecode` as the integration branch (see `CONTRIBUTING.md`); MRs target `vibecode`, not `main`.
- **Linear ticket convention:** branch and commit prefixes are `CB-NNN` (e.g. `CB-443: L1.2.2 — …`). The `Lx.y.z` suffix tracks subtasks within a parent; keep that style when adding new commits in a series.
- **Branch hygiene — every WIP gets a worktree.** Non-trivial feature work runs in its own worktree (`git worktree add ../cbx-cli-<branch> -b feat/<topic>`), so `vibecode` stays clean for fast switching. Merge to `vibecode` as soon as CI is green, then **delete both the branch and the worktree the same hour** (`git branch -d feat/<topic> && git worktree remove ../cbx-cli-<branch>`). A long-lived `feat/*` branch without an active worktree is a smell: it's either ready to merge or ready to delete. Housekeeping commits (docs, gitignore, planning notes) can go straight to `vibecode` without a branch.
- E2E tests against staging are gated behind the `e2e_staging` build tag and need `CB_API_URL` (default `https://api.staging.cloudbooster.io`).
- **Release distribution** is GoReleaser → Homebrew tap (`cloudbooster-io/homebrew-tap`) + Scoop bucket + GitLab Releases (will move to GitHub Releases post-migration), with Cosign signing and Syft SBOM. `make test-smoke-brew` / `scripts/smoke-brew.sh` post-release verify the brew install path.

## Docs site is partly aspirational

`../documentation/content/docs/troubleshooting/cbx-{plan,audit}.mdx` and adjacent pages describe flags and subcommands that **do not exist yet** in this repo (e.g. `cbx accounts add aws`, `cbx plan --validate`, `--no-adr`, `--dry-run`, `--format json` on `plan`). Treat the docs as forward-looking spec, not a source of truth for what's implemented. When adding new flags, check that doc set so naming stays consistent with what's been promised publicly.
