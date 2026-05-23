# Implementation plan — `cbx audit --source` (IaC source-repo audit)

**Status:** proposed, not yet ticketed
**Author:** drafted by Claude Code, 2026-05-10
**Owner:** TBD
**Linear epic:** TBD (suggested: parent ticket "CB-XXX: cbx audit source mode")

---

## 1. Goal

Let users run `cbx audit` against an IaC source repository — without needing a state file, cloud credentials, or a CB account. Today `cbx audit` requires `--pulumi-state` or `--terraform-state`; this expands the surface to the much larger population of users who have a Terraform repo on disk but never export state.

Framing for users: **state mode finds misconfigurations in deployed infrastructure; source mode finds them in declared IaC.** Both stay fully offline.

## 2. Non-goals

Listed explicitly because they're tempting and they're not what this is.

- **Pulumi source mode.** Pulumi source is general-purpose code (TS/Python/Go); there's no static analysis path that doesn't either run `pulumi preview` (kills offline guarantee) or accept large unresolved-symbol gaps. Pulumi users continue to use `pulumi stack export | cbx audit --pulumi-state -`.
- **Drift detection.** Comparing source-derived findings to state-derived findings is interesting but a separate feature. Don't conflate.
- **Live cloud reading.** That's the hosted "import existing infrastructure" feature in `platform-app`; explicitly out of scope per `agent-arch-talks/rework-2.5.1/01-strategy.md`.
- **Populating `DiscoveredResource` from source.** Phase 1 leaves it empty in source mode. We add it only when something concrete needs it (Phase 4 / Option B), to avoid speculative work on an HCL parser.
- **A new scanner.** We keep tfsec / checkov / trivy as the engines; we change *what we point them at*.

## 3. Phasing

| Phase | Scope | Estimate | Ship gate |
|---|---|---|---|
| 1. Source mode for Terraform | `--source ./infra` runs scanners natively against the dir | ~1 week | feature flag off by default; opt-in via flag |
| 2. CloudFormation + Kubernetes/Helm | Same flag, scanners auto-detect IaC type | ~3–5 days | passes phase-1 e2e + adds CFN/K8s fixtures |
| 3. Docs + GA | Doc page on docs.cloudbooster.io, troubleshooting page, release notes | ~2 days | flag becomes default-on, no flag toggle needed |
| 4. *(deferred)* HCL → `DiscoveredResource` (Option B) | Source mode populates resource model for downstream features | ~1–2 weeks | only triggered by a concrete need |

## 4. Phase 1 — concrete changes

### 4.1 CLI surface

`pkg/cmd/audit.go`:
- Add `--source <path>` flag (string, default empty).
- Update mutual-exclusion: exactly one of `--pulumi-state`, `--terraform-state`, `--source` must be set. Update the error message accordingly.
- Add `--iac-type <auto|terraform|cloudformation|k8s|helm>` (default `auto`) — used in Phase 2; ship the flag in Phase 1 so we don't break compatibility later.
- Thread both into `audit.Options`.

### 4.2 Options struct

`internal/audit/types.go`:

```go
type Options struct {
    // existing fields...
    SourceDir string  // when set, audit runs in source mode
    IaCType   string  // "auto" | "terraform" | "cloudformation" | "k8s" | "helm"
}
```

`StateFile` and `SourceDir` are mutually exclusive (validated in `pkg/cmd/audit.go`, not in Options itself — keep Options dumb).

### 4.3 Runner branch

`internal/audit/runner.go`:
- `Collect()` early-branches on `opts.SourceDir != ""`.
- New helper `collectFromSource(opts) ([]Finding, error)` that:
  - Skips `ParseState`.
  - Skips `loadScanners` resource-aware path; instead picks scanners that support source mode.
  - Calls a new `ScanSource(ctx, opts.SourceDir)` method on each provider.
- The progress/timeout/dedupe logic at the bottom of `Collect()` is shared — refactor that into a `collectFindings(providers, runFn)` helper so source and state paths reuse it.

### 4.4 FindingProvider interface

`internal/audit/types.go`:

```go
type FindingProvider interface {
    Name() string
    Scan(ctx context.Context, resources []Resource) ([]Finding, error)        // state mode
    ScanSource(ctx context.Context, dir string) ([]Finding, error)            // source mode; return ErrSourceModeUnsupported if N/A
    SupportsSource() bool                                                      // for runner to filter
}
```

Adding methods is a breaking change to anything that implements `FindingProvider` outside the repo. **Check `pkg/` re-exports first** — `FindingProvider` is in `internal/audit`, not exposed; safe to extend. (Verified: no `pkg/` facade for it as of the L1.2.2 commit.)

Alternative: a sum-type `ScanInput { Resources []Resource; SourceDir string }` and a single `Scan(ctx, ScanInput)`. Cleaner long-term but a bigger one-shot diff. Pick the simpler interface-extension for Phase 1; revisit if a third input mode appears.

### 4.5 Adapter rewiring

For each of `internal/audit/adapter_{tfsec,checkov,trivy}.go`:
- Add `ScanSource(ctx, dir)`.
- Skip `writeResourcesToTempDir` and `writeTerraformStateFile`.
- Invoke the scanner with the user's directory directly:
  - `tfsec <dir> --format json --no-colour --soft-fail`
  - `checkov -d <dir> -o json --quiet`
  - `trivy config <dir> --format json --quiet`
- Reuse the existing `parse{Tfsec,Checkov,Trivy}Output` parsers verbatim — output schema is identical.

`internal/audit/adapter_prowler.go`:
- `SupportsSource()` returns `false`. Prowler scans live cloud, not source.
- `ScanSource` returns `ErrSourceModeUnsupported`.

### 4.6 Mock scanners

`MockScanners()` in source mode should still work — it's the default no-deps path. Have mock providers return a deterministic small finding set keyed off the directory name (matches the spirit of the state-mode mocks). This keeps `cbx audit --source ./anything` working with no scanner binaries installed.

### 4.7 Validation & UX

- Source dir must exist and be readable; error early with a 3-line error matching the existing `internal/audit/parser.go` style.
- 100 MB guard: skip; source repos easily exceed this and the scanner binaries handle their own size limits. The guard exists for parsed JSON state, not for trees.
- Empty / no-IaC-files-found result: emit a clear "no IaC files detected under <dir>" message, exit 0 (matches state mode's "zero findings" exit 0).

### 4.8 Output / rendering

No changes. `internal/audit/render.go` operates on `[]Finding` and a header string. In source mode, header becomes the source path instead of the state file path. Verify the markdown / SARIF / github-action / json renderers all degrade cleanly when `Resource` field on a finding refers to a source-relative path (e.g. `main.tf:42`) instead of a Pulumi URN — they should, but add a golden fixture per format to prove it (see §5.2).

### 4.9 JSON envelope contract

Keep `output.WriteJSON` / `Envelope{Data, Error}` — no changes. `cb-cli` consumes this; don't break it. The `Data` shape can grow a `mode: "source" | "state"` discriminator field for downstream tools; non-breaking addition.

## 5. Test plan

### 5.1 Unit

- `internal/audit/runner_test.go`: new `TestCollectSourceMode` covering happy path + empty dir + missing dir + scanner error.
- `internal/audit/adapter_tfsec_test.go` etc.: extend with `TestScanSource_*` per adapter; mock `runScanner`.
- `pkg/cmd/audit_test.go` (if missing, add): mutual exclusion of the three input flags.

### 5.2 Golden fixtures

Add `internal/audit/testdata/source_render_{plain,json,markdown,sarif,github_action}.golden` for source-mode finding shape. Run via the same render-test harness used today.

### 5.3 E2E

`e2e/fixtures/terraform-sample-source/` — minimal Terraform repo with one intentionally-misconfigured resource (e.g. unencrypted S3 bucket) to guarantee a finding from real tfsec. Keep it tiny (<10 files).

`e2e/audit_test.go`:
- Add `TestAuditSource_Terraform` — runs `cbx audit --source <fixture>` with mock scanners (CI default), asserts JSON envelope shape and severity-driven exit code.
- Add a build-tagged variant under `e2e/audit_real_scanners_test.go` (`//go:build e2e_real_scanners`) that runs the real tfsec binary — opt-in only, not in default CI matrix.

### 5.4 CI

- No new jobs needed for Phase 1 — existing `test`, `e2e-matrix`, `e2e-staging` cover it.
- `codegen-check` unaffected (no API changes).
- Add Phase 1 fixtures to `mermaid-validate`'s ignore set if any of them contain `.mmd` (none should).

## 6. Risks & open questions

| # | Risk | Mitigation |
|---|---|---|
| R1 | Scanners output paths relative to their CWD; users find this confusing | Resolve to absolute or repo-relative paths in the adapter parsers before populating `Finding.File`/`.Line` |
| R2 | Scanner binary version skew (tfsec deprecated upstream; trivy now subsumes it) | Already constrained via `scannerRegistry` version ranges. Phase 2 may want to drop tfsec entirely and route Terraform through `trivy config` — flag for design discussion before Phase 2 lands |
| R3 | Users will ask for Pulumi source mode | Reject up front in CLI with a helpful error pointing to `pulumi stack export`; add an FAQ entry |
| R4 | Source mode could cannibalize the hosted "import existing infrastructure" pitch | Different value prop (declared misconfigurations vs. running resources you didn't write down). Comms team aligns the framing pre-GA |
| R5 | `DiscoveredResource` substrate divergence with `platform-app` import feature | Phase 1 doesn't touch `DiscoveredResource` at all → no divergence. Defer until Phase 4 and coordinate with platform-app then |
| R6 | `FindingProvider` interface widening breaks an external implementer | Interface lives in `internal/`; verified no `pkg/` re-export. Safe. |
| R7 | Phase 1 ships as `--source` flag; later flag-flip behavior changes | Don't change defaults silently. If state vs. source autodetect is ever added, gate behind a config opt-in |

### Open questions to decide before kickoff

1. **Single binary vs. require user-installed scanners.** Today scanner binaries are `exec`-ed off PATH. Source mode keeps that. Is there appetite to embed `trivy` / `checkov` as Go libraries? (Probably no — both are large; out of scope for this plan.)
2. **`--source -` (stdin tar)?** Tempting for CI usage. Defer to Phase 3 unless a concrete user asks.
3. **Default `--scanners` set in source mode.** Today default is `MockScanners`. Should source mode default to mock too, or default to real tfsec/trivy if available? Recommendation: keep mock default for the offline guarantee; document the `--scanners=tfsec,trivy` opt-in clearly.
4. **Naming.** `--source` vs `--iac-dir` vs `--repo`. `--source` is shortest and matches `--pulumi-state` / `--terraform-state` (input source). Recommended.

## 7. Rollout

1. **MR 1:** runner + interface + Options + `--source` flag plumbing + unit tests + mock-scanner support. No real scanner wiring yet. Ships as preview.
2. **MR 2:** tfsec source-mode adapter + e2e fixture + e2e test. Phase 1 functionally complete.
3. **MR 3:** checkov + trivy source-mode adapters.
4. **MR 4 (Phase 2):** CloudFormation fixture + auto-detect of `--iac-type`.
5. **MR 5 (Phase 2):** K8s/Helm fixture.
6. **MR 6 (Phase 3):** Docs site update — `documentation/content/docs/concepts/audit.mdx` (new) + troubleshooting/cbx-audit.mdx revision. Coordinate naming with the aspirational flags already documented there (see CLAUDE.md "Docs site is partly aspirational" note).
7. **MR 7:** CHANGELOG entry under Unreleased → minor version bump → release.

Each MR targets `vibecode` per `CONTRIBUTING.md`, with `CB-NNN: Lx.y.z — …` commit prefix.

## 8. Docs deltas

- `README.md` Commands table: add `cbx audit --source <dir>` row.
- `documentation/content/docs/troubleshooting/cbx-audit.mdx`: new section "Auditing source vs. state."
- `documentation/content/docs/concepts/audit.mdx` (new): the framing — declared vs. deployed.
- Public OpenAPI / `core/api/v1/`: no change (audit is local-only).

## 9. What this does NOT change

For the reviewer-skimming-fast version:

- No `pkg/` facade signatures change → no break for `cb-cli`.
- No `core/api/v1/` change → no codegen drift, no public API churn.
- No `DiscoveredResource` change → no platform-app coordination needed.
- No new dependencies → single-binary distribution unaffected.
- Audit stays fully offline → "zero CB API calls" property preserved.

## 10. Decision log

- **2026-05-10:** initial plan drafted. Phases 1–3 scoped concretely; Phase 4 deferred until concrete trigger. Pulumi source mode explicitly out of scope.
