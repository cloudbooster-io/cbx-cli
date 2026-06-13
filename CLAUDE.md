# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common commands

```sh
make build              # → bin/cbx, with -ldflags injecting Version/Commit/Date into pkg/cmd
make test               # go test ./... (unit + local e2e)
make test-e2e           # go test -v ./e2e/...
make test-e2e-staging   # e2e against a staging API (build tag: e2e_staging; maintainer-only)
make vet                # go vet ./...
make lint               # golangci-lint run ./...
make codegen            # regenerate core/api/v1/client.gen.go from api/openapi.yaml
make codegen-check      # codegen + fail if client.gen.go drifted (matches CI gate)

# Run a single test
go test ./internal/audit -run TestParsePulumiState
go test -v -tags=e2e_staging ./e2e -run TestStaging_Login
```

CI is GitHub Actions (`.github/workflows/ci.yml`): `validate` (vet + build), `lint` (golangci-lint), `codegen-check`, `test` (unit tests; `./e2e` is excluded — it gets its own job), `mermaid-validate`, `e2e`, and `e2e-staging`. Releases are cut by the tag-triggered `.github/workflows/release.yml`. Module declares go 1.25.0 with `toolchain go1.26.4`; CI resolves the pinned toolchain via `go-version-file: go.mod`.

## Open-core context (load-bearing)

`cbx-cli` is the **OSS Apache-2.0** edition. It is consumed **as a library** by downstream tools — `pkg/` is the contract those consumers depend on, which is the entire reason for the layered layout below.

Implications you must respect:
- **Any breaking change in `pkg/` is a breaking change for downstream library consumers.** Treat `pkg/auth`, `pkg/audit`, `pkg/config`, `pkg/output`, `pkg/cmd` as semver-public.
- **`cbx audit` (state/source modes) is fully offline / zero CB API calls** — works without a CloudBooster account. Don't add hidden network calls to those paths; mock scanners are the default specifically to keep this property. The carve-out is `cbx audit aws`, which (a) reads live AWS via the SDK (single-account, ad-hoc, user-initiated), and (b) **always** grounds findings in CloudBooster's curated AWS knowledge: it fetches that knowledge directly over the CB knowledge API (`/v1/knowledge/aws/*`), inlines it into the prompt alongside discovered resources, and runs a local LLM CLI (no MCP) to cite it — that grounding is the entire value of the subcommand, not optional. So `cbx audit aws` **does** make CB knowledge-API calls and hard-requires a grounding CLI on PATH: `claude -p` by default, or `codex exec` via `--llm-executor codex` (`--llm-executor claude-code|codex`, default claude-code; selected via `audit.ClaudeCodeProvider` / `audit.CodexProvider`, both wired through `newGroundedCLIStreamer`). Parity note: `--llm-max-cost` is enforced only for claude-code — `codex exec` surfaces no per-run cost, so `groundedCodexStreamer.TotalCostUSD` is always 0 and the cap is an inert no-op there (documented degradation, not a silent gap). The audit **rule pack** is API-distributed the same way: a pre-discovery preflight (in `pkg/cmd/audit_aws.go`) fetches it from `/v1/knowledge/aws/rulepack`, caches it under `~/.cache/cbx/rulepack/`, and honors a `CBX_AUDIT_RULES_FILE` local override — there is **no embedded copy**, so a cold cache offline aborts before any AWS spend. Test policy: unit tests use the synthetic pack in `internal/audit/rulesbundle/rulesbundletest` (never production rule content); production-pack contract checks live in the `e2e_staging` tier; production rule content is owned by platform-app. Library callers in `pkg/audit` can still build non-LLM audits (used by downstream consumers and the state-file parsers), but the `cbx audit aws` CLI surface no longer exposes that path.
- **State parsers in `internal/audit/parsers/`** are shared substrate with CloudBooster's hosted "import existing infrastructure" feature. Changing `DiscoveredResource` shape or parser semantics has cross-repo impact — coordinate with maintainers.
- A planned `cbx mcp serve` subcommand will embed an MCP server (Day-2 feature, not yet shipped). When it lands, it must proxy the same `api.cloudbooster.io/v1/*` contract.

## Repository layout — the layering rule

```
cmd/cbx/            thin main; just calls pkg/cmd.Execute / ExitCode
pkg/                public, importable surface — auth/, audit/, config/, output/, cmd/
core/               cross-module shared logic — core/api/v1/ (generated)
internal/           private to cbx-cli — audit/, llm/, tui/, output/, config/, …
```

- `cmd/cbx/main.go` is **deliberately tiny** (10 lines). All cobra wiring lives in `pkg/cmd/` so it can be embedded by downstream consumers.
- `pkg/auth`, `pkg/audit`, `pkg/config`, `pkg/output` are **pure facades**: type aliases and `var X = internal.X` re-exports only. Don't add logic here — implement in `internal/<pkg>` and re-export.
- `core/api/v1/client.gen.go` is generated from `api/openapi.yaml` via `tools/codegen/generate.sh` (uses `go tool oapi-codegen`). Never hand-edit; CI's `codegen-check` job will fail. Hand-written companions (`client.go`, `auth.go`, `retry.go`, `ratelimit.go`) wrap the generated client.
- The API target is the **public** `api.cloudbooster.io/v1/*` surface (anonymous → free → paid tiers, API-key auth). Target only this public surface.
- `internal/audit` is the large feature area, with its CLI entry in `pkg/cmd/audit.go` and a Bubble Tea TUI in `internal/tui/audit`.

## Audit pipeline

The CLI surface is `cbx audit aws` only — `pkg/cmd/audit.go` is a thin dispatcher; the earlier IaC inputs (`--pulumi-state`, `--terraform-state`, `--source`, `--scanners`, ...) were **removed from the flag surface**. The state/source pipeline survives as the **library path** through `pkg/audit`: `internal/audit.Collect` → `ParseState` (delegates to `internal/audit/parsers/{pulumi,terraform}_state.go`) → `RunProvidersWithProgress` over `FindingProvider`s. Real scanner adapters (tfsec/checkov/prowler/trivy) live in `internal/audit/adapter_*.go`; library callers pick providers via `Options.MockScanners` / `Options.Scanners` — **`MockScanners` is the zero-network, no-external-binaries set** that preserves the offline property above.

Exit codes are not 0/1: `audit.ExitCodeError` propagates from `Execute` through `ExitCode` in `pkg/cmd/execute.go`. Severity mapping is info→1, warning→2, high/critical→3 (`internal/audit/exit.go`). Don't replace this with a generic `os.Exit(1)`.

State-file parsing has a 100 MB guard with a `--yes` bypass (see `Options.Yes` in `internal/audit/types.go`); large fixtures must respect this in tests.

## LLM providers (`cbx llm`)

**`cbx plan` was removed in June 2026** (unfinished; pulled from the surface before launch — the engine in `core/plan/`, `internal/plan/`, the chat TUI in `internal/tui/chat`, and the plan-only API-client chain `core/llm` + `internal/core/llm` were deleted with it). The `cbx llm` provider/executor management remains because `cbx audit aws` uses it.

LLM provider metadata, keychain-backed credentials, the HTTP streaming caller the audit analyzer uses, and the CLI-executor plumbing (`llm.IsCLIExecutor`, `llm.ProbeCLIExecutor` — the preflight probe behind `cbx llm cli test` and `cbx audit aws`) all live in `internal/llm` (`llm.Providers`, `llm.GetToken`, `llm.Caller`). Model selection is per provider/executor via `cbx llm model <name> <model>` (stored in `cfg.LLM.Providers[name].Model`): api providers default to a current model (`claude-sonnet-4-6`), CLI executors default to the local CLI's own configured model (cbx passes `--model` only when pinned); `cbx audit aws` additionally honors `--llm-model` (per the selected `--llm-executor`: `cbx llm model claude-code …` / `cbx llm model codex …`). The grounded audit's preflight probes the *selected* executor (`llm.ProbeCLIExecutor(ctx, executor, model)`) before any AWS spend — a broken codex aborts with `E_LLM_PREFLIGHT` exactly like a broken claude.

## Output / JSON contract

All commands respect a global `--json` flag. JSON output **must** go through `internal/output.WriteJSON` / `PrintJSON`, which wraps payloads in an `Envelope{Data, Error}`. Errors emitted as JSON use `JSONError` / `JSONErrorf` to build the `ErrDetail`. Don't directly `json.Marshal` to stdout — that breaks the wrapper contract and the downstream consumers depending on it via `pkg/output`.

Styled (color/spinner) output flows through `output.Configure(noColor, quiet)` set in the root cobra `PersistentPreRunE`. Respect `IsQuiet()` and `Enabled()` rather than reading the cobra flags directly from inside `internal/`.

## Update banner

`pkg/cmd/execute.go` runs a 3-second background update check in parallel with the command, then prints a banner to stderr at the end. It's suppressed in `CI=true`, `CBX_NO_UPDATE_CHECK=1` (or the deprecated `CB_NO_UPDATE_CHECK=1`), when `--quiet`/`--json`, or for the `version` and `upgrade` subcommands. New subcommands that emit machine output should make sure they don't fight with this banner (it goes to stderr, so pipelines reading stdout are safe).

## Workflow specifics for this repo

- **Contributions go through GitHub pull requests against `main`** — see `CONTRIBUTING.md`. Reference any related GitHub issue in commits/PRs.
- **Topic branches off `main`**, kept short-lived; one logical change per commit.
- E2E tests against staging are gated behind the `e2e_staging` build tag and need `CB_API_URL` (maintainer-only).
- **Release distribution** is GoReleaser → Homebrew **cask** (`cloudbooster-io/homebrew-tap`; macOS-only — GoReleaser deprecated `brews`/formulas) + `nfpms` `.deb`/`.rpm` for Linux + Scoop bucket (Windows) + GitHub Releases, with Cosign signing and Syft SBOM. Releases are cut by the tag-triggered `release` job in `.github/workflows/release.yml` (GoReleaser pinned, keyless Cosign via the ambient GitHub OIDC token; cross-repo cask/scoop pushes authenticate via the `cbx-release-bot` GitHub App — `RELEASE_APP_ID` variable + `RELEASE_APP_PRIVATE_KEY` secret, optional `SENTRY_DSN` — see the workflow's comment block). The archive `name_template` (`cbx-cli_<TitleOs>_<Arch>`, amd64→x86_64) is load-bearing — it must match `internal/update/update.go:directAssetURL`; validate with `goreleaser check` + a `--snapshot` build. `make test-smoke-brew` / `scripts/smoke-brew.sh` verify the cask install path post-release (macOS runner only).

## Docs site is partly aspirational

The public documentation site describes some flags and subcommands that **do not exist** in this repo (e.g. `cbx accounts add aws`, and the whole `cbx plan` surface, which was removed from the CLI in June 2026). Treat the docs as forward-looking spec, not a source of truth for what's implemented. When adding new flags, check the published docs so naming stays consistent with what's been promised publicly.
