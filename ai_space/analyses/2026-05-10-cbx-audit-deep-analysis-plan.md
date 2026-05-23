# Implementation plan — `cbx audit --source` deep analysis (LLM + native CB rules)

**Status:** proposed, not yet ticketed
**Author:** drafted by Claude Code, 2026-05-10
**Owner:** TBD
**Linear epic:** TBD (suggested parent: "CB-XXX: cbx audit deep analysis")
**Builds on:**
- [`2026-05-10-cbx-audit-source-mode-plan.md`](./2026-05-10-cbx-audit-source-mode-plan.md) — Phase 1–3 of source mode (already shipped)
- [`2026-05-10-cbx-audit-source-hcl-phase4-design.md`](./2026-05-10-cbx-audit-source-hcl-phase4-design.md) — HCL parser design (parked until trigger)

---

## 1. Goal

Replace the placeholder behaviour of `cbx audit --source <dir>` with **two real analysis paths that work without external scanner binaries**, so the default invocation produces actual signal instead of mock findings.

Today the default is the static mock — three deterministic findings keyed off the directory basename, ignoring file contents. A first-time user reasonably interprets this as a real audit. This plan ships two complementary fixes: (a) a UX correction so the mock case is unambiguous, (b) two real analyzers — LLM-powered and native CB-rules-over-HCL — that can each become the default when configured.

## 2. Non-goals

- **Bundling scanner binaries into `cbx`.** tfsec / checkov / trivy stay external opt-ins (`--scanners=`).
- **`terraform init` / module fetch.** Phase 4 T4 stays out (breaks offline, see HCL design doc §4.3).
- **Replacing the existing scanner pipeline.** The new analyzers are *additional* defaults, not replacements. `--scanners=tfsec,checkov,trivy` continues to work unchanged.
- **A new finding schema.** Both new analyzers emit `internal/audit.Finding` like everything else; no envelope changes; `pkg/output` stays untouched.
- **Live cloud reading.** That belongs to platform-app's hosted product; explicitly out of scope.

## 3. Phasing

| Phase | Scope | Estimate | Ship gate |
|---|---|---|---|
| A. Mock-mode banner | Print a clear "no real audit performed" notice when source mode falls back to mock | ~1 hour | Banner appears in the right cases, suppressed correctly with `--quiet`/`--json` |
| B. LLM-powered audit | `--llm` flag (or auto-enable when an LLM provider is logged in) sends source files to the configured LLM and emits structured findings | ~2–3 days | Findings round-trip cleanly; works with all three providers (Claude / OpenAI / Ollama); token budget enforced |
| C. Native CB rules over HCL (Phase 4 T1) | Minimal HCL parser → `DiscoveredResource` list → existing `staticScanner.evaluateResource()` produces real CB findings against source | ~3–4 days | Round-trip with state-mode parser produces matching `DiscoveredResource` for the same fixture |
| D. (optional) HCL T2 — vars + locals | Resolve `var.x` and `local.y` via `cty.EvalContext` populated from `variable {}` defaults | +2–3 days | Triggered by user reports of "missing resources due to var refs" |
| E. (optional) Hybrid LLM + parsed resources | LLM analyzer accepts the `DiscoveredResource` list (from C) as additional context to reason over | +1–2 days | Triggered by user reports of "LLM hallucinates resources that aren't in my code" |

A and B can ship in parallel; C is independent of both but completes the "CloudBooster knowledge against source" story.

## 4. Phase A — Mock-mode banner (concrete changes)

Today the runner returns `[]Finding` with no provenance metadata, and the renderer can't tell mock from real. Add a single signal that the renderer can act on.

### 4.1 Where the banner fires

`internal/audit/runner.go::collectFromSource` — at the point where the resolved provider list is `[mockScanner]` (or contains it as the only source-supporting provider in the absence of `--scanners`), set a sentinel on the result. The CLI layer reads the sentinel and prints to stderr, before the report-written line.

Banner text (terse, one fact per line, exit code unchanged):

```
NOTE: built-in mock scanner used — findings do not reflect your actual code.
      For real analysis: install tfsec/checkov/trivy and pass --scanners=…,
      configure an LLM provider and pass --llm, or wait for native source
      analysis (planned, see CB-XXX).
```

Suppress when `--quiet`, `--json`, or `--output=…` is set. Same suppression rules the update banner already uses (`pkg/cmd/execute.go`).

### 4.2 Surface

Carry the signal on `audit.Result` (new field `MockOnly bool`) — non-breaking addition. Or, less invasive, expose `audit.UsedMockOnly(opts) bool` that the CLI calls. Pick whichever is smaller; either is fine.

### 4.3 Tests

Unit: assert the banner string is included on a mock-only run, absent when `--scanners=tfsec` is set, absent on `--quiet`. CLI-level test using cobra in-process command (existing `pkg/cmd/audit_test.go` pattern).

## 5. Phase B — LLM-powered audit (concrete changes)

### 5.1 Flag surface

`pkg/cmd/audit.go`:

- Add `--llm` (bool). When set, source mode dispatches to the LLM analyzer. Mutually exclusive with `--scanners=`.
- Optional auto-enable: when no `--scanners=` is set and `cbx llm default` reports a configured provider, default to `--llm`. Document the rule in `--help`. Defer auto-enable to a follow-up if it's contentious — the explicit flag is sufficient for v1.
- `--llm-provider <name>` overrides the default LLM provider for this single audit (mirrors `cbx plan`).
- `--llm-max-files <N>` and `--llm-max-bytes-per-file <N>` for budget control (defaults: 50 files, 64 KB each).

### 5.2 Reuse `cbx plan`'s LLM plumbing

`internal/core/llm` and `internal/core/auth/keyring.go` already do provider abstraction, credential storage, retry, and message construction. **Don't duplicate** — wrap.

New package `internal/audit/llm/` (or extend `internal/audit` directly — pick by file count):

- `Analyzer` interface: `Analyze(ctx, files []SourceFile) ([]Finding, error)`
- One concrete implementation that takes a `core/llm.Provider`, formats the prompt, parses structured output back to `[]Finding`.

### 5.3 Prompt + output schema

System prompt: "You are CloudBooster's IaC audit analyzer. Analyze the provided IaC files and return any security, compliance, or operational misconfigurations as JSON. Output schema: [list of finding objects with rule_id, title, description, severity (critical|high|warning|info), resource, service, remediation, file, line]." Include the IaC type detected by `iactype.go::detectIaCType` so the LLM tunes its analysis ("This is a Terraform tree.").

Use **structured output** when the provider supports it (Claude tool-use, OpenAI JSON mode). Fallback path: instruct JSON, parse with permissive recovery (extract first `{…}` block).

`rule_id` convention for LLM findings: `LLM-<provider>-<short hash of title>` so they're distinguishable from real-scanner output and dedupe correctly. Document in CHANGELOG.

### 5.4 Source-file gathering

New helper `collectSourceFiles(dir, iacType, maxFiles, maxBytesPerFile) []SourceFile`:

- Walk `dir` respecting the same `.git`/`.terraform`/`node_modules` skips as `iactype.go`.
- Filter by extension to the relevant IaC flavor (terraform: `*.tf` `*.tf.json`; CFN/K8s/Helm: `*.yaml` `*.yml` `*.json` plus `Chart.yaml`).
- Truncate per-file at `maxBytesPerFile` (warn on truncation).
- Hard-cap total at `maxFiles` files (warn on cap).
- Each `SourceFile`: `{Path string, Content []byte, Bytes int, Truncated bool}`.

Token budget enforcement happens at the LLM provider layer (already existing in `core/llm`). The file-level caps above are belt-and-suspenders against pathological repos.

### 5.5 Network egress posture

LLM mode is **explicitly not offline**. Document this clearly:

- `--help` text on `--llm`: "Sends source file contents to the configured LLM provider. Requires `cbx llm login`."
- Banner on first invocation per session (or when `--llm` is set with no provider): "LLM audit will send file contents to <provider>. Re-run with --no-llm to skip."

This matches the posture of `cbx plan`, which also requires LLM login and is explicitly online. The "fully offline by default" property of `cbx audit` is preserved because `--llm` is opt-in.

### 5.6 Errors and partials

LLM call timeout, provider errors, JSON parse errors all surface as `audit.Finding{Severity: "info", RuleID: "LLM-ERROR", ...}` rather than aborting the whole run. Same contract as scanner errors (`runner.go::collectFindings` already joins errors but returns partial findings).

### 5.7 Tests

- Unit: prompt construction, output schema parse including malformed/recoverable cases, file gather with caps and truncation. Use a mock `Provider` (no real API calls).
- E2e: `e2e/audit_llm_test.go` under build tag `e2e_llm` (off by default in CI). Calls a real LLM against the existing `e2e/fixtures/terraform-sample-source/` and asserts at least one finding plus structured shape. Skip when no provider configured.

## 6. Phase C — Native CB rules over HCL (Phase 4 T1)

This **is** Phase 4 T1 from the HCL design doc. See `2026-05-10-cbx-audit-source-hcl-phase4-design.md` §4 for the full design — this section is the reduction to a buildable scope.

### 6.1 Concrete changes

- New file `internal/audit/parsers/terraform_source.go` exposing `ParseTerraformSource(dir string) ([]DiscoveredResource, error)` using `github.com/hashicorp/hcl/v2`.
- T1 fidelity only: literal attribute values; warn-and-skip on `var.x` / `local.y` / `module.…` references. `count` / `for_each` not expanded in T1 (return the unexpanded resource once, with `Inputs["count"]` / `Inputs["for_each"]` carried verbatim).
- Wire from `runner.go::collectFromSource`: when `iacType == terraform`, call the parser, expose the resource list.
- Make the existing `staticScanner` source-mode-aware: its current `ScanSource` returns mock findings; replace with a path that runs `evaluateResource()` over the parsed resources when available, falls back to mock when no parser ran.

### 6.2 Tests

- Unit: `parsers/terraform_source_test.go` covering literal-only resource, `var.x` reference (warns, skipped attr), `count = 2` (single resource emitted with count attr preserved), provider region attachment, mixed-`.tf` + `.tf.json` directories.
- Cross-mode invariant: a fixture parsed via `terraform_source` produces the same `DiscoveredResource` core fields (`Type`, attribute keys) as the same resource definition serialised through state mode.
- E2e: extend `e2e/audit_test.go` to assert that `cbx audit --source <terraform fixture>` (no `--scanners`, no `--llm`) now returns CB findings (e.g. `S3-002` from `evaluateResource()`) instead of `MOCK-SRC-*`.

### 6.3 New dependency

`github.com/hashicorp/hcl/v2`. Vet at design time: `go mod why -m`. HCL pulls in `cty` and a small set; should be fine for single-binary distribution but confirm before merging.

## 7. Phase D — HCL T2 (variables + locals) — optional

Only if T1 user feedback flags too many resources skipped due to `var.x` references. Strategy: build a `cty.EvalContext` from `variable {}` defaults and `locals {}` blocks, evaluate attribute expressions through it. Resources that depend on `*.tfvars` overrides remain T3 territory.

## 8. Phase E — Hybrid LLM + parsed resources — optional

When both Phase B and Phase C have shipped, the LLM analyzer can accept the parsed `DiscoveredResource` list as additional structured context: "Here are the parsed resources [JSON]. Reason about them and the file contents together." Catches drift between what the parser sees and what the LLM hallucinates; tightens output quality.

Don't ship until Phase B users specifically report hallucinated resources or weak file-level reasoning.

## 9. Default selection logic (where this lands)

After Phase A + B + C ship, the default behaviour of `cbx audit --source <dir>` becomes:

1. If `--scanners=…` set → run real scanners (existing behaviour).
2. Else if `--llm` set or LLM provider configured → run LLM analyzer (Phase B).
3. Else if a Phase C parser exists for the detected IaC type → run native CB rules over parsed resources.
4. Else → mock + Phase A banner.

So source mode degrades gracefully through real-scanners → LLM → native CB rules → mock-with-warning. Document the precedence in `--help`.

## 10. Test plan summary

- Unit tests per phase (above).
- E2e default CI: covers Phase A banner + Phase C native rules. Phase B sits behind `e2e_llm` build tag (opt-in, like the existing `e2e_real_scanners`).
- Golden fixtures: extend the existing render-test harness with a "native CB rules over source" golden output to lock the public-facing finding shape.

## 11. Risks and open questions

| # | Risk | Mitigation |
|---|---|---|
| R1 | LLM output is non-deterministic — flaky tests | Use mocked `Provider` in unit tests; only the build-tagged e2e calls a real LLM, and only asserts shape, not exact rule IDs. |
| R2 | Token budget blowups on big repos | Phase B file caps + provider-side budget. Document per-provider context windows in `--help`. |
| R3 | Phase B + Phase C duplicate findings (LLM finds the same misconfig CB rules find) | Dedupe key includes `Title` not just `RuleID|Resource` for LLM findings — if the title hash collides with a CB rule, drop the LLM duplicate. |
| R4 | HCL T1 fidelity too low to be useful | Acceptance test: parse a real-world repo (`platform-smoke-infra/terraform`) and confirm coverage. If <60% of resources end up parsed, schedule T2 immediately. |
| R5 | LLM analyzer leaks sensitive file contents to a third-party API | Inherit `cbx plan`'s posture — opt-in via login, documented in `--help`. Add `--llm-redact-secrets` (regex strip of common secret patterns) as a follow-up if requested. |
| R6 | Banner text confused for an actual error | Print to stderr, prefix `NOTE:`, exit code unchanged. Test that `--quiet` and `--json` suppress it. |

### Open questions

1. **Auto-enable `--llm` when a provider is configured?** Pro: source mode "just works" after `cbx llm login`. Con: silent network egress surprises users. Recommendation: don't auto-enable in v1; require explicit `--llm`. Revisit after we see real usage.
2. **Should Phase C produce findings under the existing `static` scanner name, or a new `cb-source` scanner name?** Recommendation: keep `static` so `--scanners=static` works in source mode too. Adds symmetry with state mode.
3. **What's the right bucket for LLM findings in `--severity` filtering?** Recommendation: trust the LLM's `severity` field; clamp to the four allowed values; map anything else to `info`.
4. **Per-provider prompt tuning?** Recommendation: start with one prompt; only fork per provider if quality differences become observable.

## 12. Rollout

1. **MR-A:** Phase A banner. Self-contained; ships first.
2. **MR-B:** Phase B LLM analyzer + flag + tests. Ships independently of MR-C.
3. **MR-C:** Phase C HCL parser + wire to `staticScanner`. Ships independently of MR-B.
4. **MR-D:** Default-precedence wiring (§9). Lands after both B and C are merged.
5. **MR-E (optional):** Phase D — HCL T2.
6. **MR-F (optional):** Phase E — hybrid.
7. CHANGELOG entry per MR; docs site update bundled with MR-D (the user-visible default change).

Each MR targets `vibecode` per `CONTRIBUTING.md`, with `CB-NNN: …` commit prefix.

## 13. What this does NOT change

- `pkg/auth`, `pkg/config`, `pkg/output`, `pkg/cmd` exported signatures.
- `core/api/v1/` — no codegen drift.
- `DiscoveredResource` shape — Phase C populates it from a new source, doesn't change the struct.
- `cbx audit --pulumi-state` / `--terraform-state` paths — state mode untouched.
- Default offline guarantee — `--llm` is opt-in; mock fallback stays.

## 14. Decision log

- **2026-05-10:** plan drafted in response to user observation that `cbx audit --source` defaults to mock and the mock looks like a real audit. Triggered both Phase 4 (HCL parser, was parked pending consumer) and a new LLM-audit track (was not previously scoped). Phase B and Phase C are independent and complementary; ship either or both.
