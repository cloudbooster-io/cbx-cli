# Design — Phase 4: HCL → `DiscoveredResource` for `cbx audit --source`

**Status:** parked design — not for implementation until a concrete trigger arrives
**Author:** drafted by Claude Code, 2026-05-10
**Companion to:** [`2026-05-10-cbx-audit-source-mode-plan.md`](./2026-05-10-cbx-audit-source-mode-plan.md) (Phase 4)
**Linear epic:** none yet — open one once a trigger from §6 lands

---

## 1. Why this doc exists, why it's parked

Phases 1–3 of the source-mode plan shipped (cbx-cli vibecode `64ca595..f784fc8`, documentation vibecode `5232221`). `cbx audit --source <dir>` works today for terraform / cloudformation / k8s / helm, but it leaves `DiscoveredResource` empty in source mode — scanners read source files directly and emit `Finding`s without ever materializing a normalized resource list.

Phase 4 fills that gap by parsing Terraform HCL into the same `DiscoveredResource` shape that the Pulumi and Terraform **state** parsers already produce. The audit pipeline doesn't need this today (no consumer reads it in source mode), so the original plan deferred Phase 4 to "concrete trigger" status (§3, §10). This doc captures the design so when the trigger arrives the work can start without re-litigating the approach.

**Don't implement this without a named consumer.** See §6.

## 2. Current substrate (what already exists)

`internal/audit/parsers/resource.go`:

```go
type DiscoveredResource struct {
    Type   string                 `json:"type"`
    URN    string                 `json:"urn"`
    ID     string                 `json:"id"`
    Region string                 `json:"region,omitempty"`
    Tags   map[string]string      `json:"tags,omitempty"`
    Inputs map[string]interface{} `json:"inputs,omitempty"`
}
```

JSON tags chosen to match a Pydantic model on the platform-app side. Anything that changes this shape ripples cross-repo (per `CLAUDE.md`: "Changing `DiscoveredResource` shape or parser semantics has cross-repo impact — coordinate.").

Existing parsers, both keyed on `ParseState(opts) ([]DiscoveredResource, error)` selected by JSON top-level keys:

- `parsers/pulumi_state.go` — handles Pulumi v3 deployment shape
- `parsers/terraform_state.go` — handles Terraform `terraform.tfstate` shape

Source-mode dispatch (`internal/audit/runner.go::collectFromSource`) currently bypasses parsing entirely.

## 3. Phase 4 scope

Add `parsers/terraform_source.go` that walks an HCL tree and returns `[]DiscoveredResource`. Wire it from `runner.collectFromSource` so when `iac_type=terraform` (auto or explicit), the source dir is also parsed into the resource model. Pass that list to any future consumer that needs it.

**Strictly Terraform HCL.** CFN / K8s / Helm equivalents are explicit non-goals for Phase 4 — each is its own parser, none shares an HCL toolchain, and they should land as separate phases when their own triggers arrive (see §6).

## 4. Approach

### 4.1 Toolchain

Use `github.com/hashicorp/hcl/v2` + `hashicorp/hcl/v2/hclparse`. This is the upstream HCL library Terraform itself uses; battle-tested; no shellout to `terraform`. The `Inputs` map produced by Pulumi/Terraform state parsers contains arbitrary attribute trees, so HCL's `cty.Value` outputs need to be lowered to `map[string]interface{}` for parity (see §4.4).

Adds one direct dependency (`hashicorp/hcl/v2`). Acceptable: HCL is a stable library, MIT-licensed, actively maintained, no transitive surprises.

### 4.2 Resource extraction strategy

Walk the directory recursively, collect every `*.tf` and `*.tf.json` (matching `iactype.go::detectIaCType` rules), parse each file, then iterate top-level `resource "<type>" "<name>"` blocks. For each block, build:

```go
DiscoveredResource{
    Type:   "<type>",                 // e.g. "aws_s3_bucket"
    URN:    "<type>.<name>",          // matches Terraform addressing convention
    ID:     "",                        // unknown until apply; leave blank
    Region: lookupProviderRegion(...), // best-effort; "" when not derivable
    Tags:   stringMap(attrs, "tags"),
    Inputs: lowered(attrs),            // see §4.4
}
```

`URN` deliberately follows Terraform's `<type>.<name>` addressing rather than fabricating a Pulumi-style URN — consumers that need the Pulumi shape can reformat downstream; we don't lose information by keeping the address native.

`ID` stays empty in source mode (resource has no cloud ID until `apply`); the field's `omitempty` JSON tag means downstream consumers see it absent rather than as `""`. Worth confirming the Pydantic model on platform-app is `Optional[str]` not `str` before shipping.

### 4.3 Expression evaluation — the hard part

HCL attributes can reference variables, locals, modules, `count` / `for_each`, dynamic blocks, and arbitrary functions. Terraform itself evaluates these only after `terraform init` (which fetches modules and providers). We can't run `terraform init` without breaking the offline guarantee.

**Tier the support:**

| Tier | Scope | Effort | When |
|---|---|---|---|
| **T1: literal-only** | Resources with literal attribute values (no `var.x`, no `local.y`, no `${...}` references). Findings are emitted; resources with non-literal attributes get a partial `Inputs` map (resolved attrs only) and a warning logged. | 2-3 days | First cut. Covers the bulk of fixture-style code and a meaningful slice of real repos. |
| **T2: variables + locals** | Use `hcl/v2`'s `cty.EvalContext` populated from `variable {}` defaults and `locals {}` blocks. Skips module references and `var.x` overrides from `*.tfvars`. | +2-3 days | When T1 misses too many real-world resources. |
| **T3: tfvars + count/for_each fan-out** | Honor `*.tfvars`/`*.tfvars.json`, expand `count = N` and `for_each = {...}` into N concrete resources. | +3-5 days | When users complain about underreported resource counts. |
| **T4: modules** | Resolve `module "x" { source = "..." }`. Local sources are doable; remote sources break the offline guarantee. | indefinite | Don't, unless the platform-app consumer specifically needs it. Document as a known limitation. |

**Recommendation:** ship T1 first, hide everything else behind a follow-up. The plan's "1-2 weeks" estimate maps to T1 + T2 + T3.

### 4.4 `Inputs` map lowering

`hcl/v2` emits `cty.Value` for evaluated expressions. Convert to `map[string]interface{}` matching what the Pulumi/Terraform state parsers produce, by `cty.Value.GoString` plus a recursive walk. Numbers become `float64` (matching `encoding/json`), strings stay strings, lists become `[]interface{}`, objects/maps become `map[string]interface{}`. This matters because the existing `Inputs` consumers (currently only the static scanner via `evaluateResource`) expect that shape.

### 4.5 Provider region

Best-effort. If the file declares `provider "aws" { region = "..." }` with a literal region, attach it to every resource of that type. Otherwise leave `Region: ""`. Don't try to resolve `var.region` in T1.

### 4.6 Wiring into `runner.go`

Add a hook in `collectFromSource`:

```go
if iacType == IaCTypeTerraform {
    resources, _ := parsers.ParseTerraformSource(opts.SourceDir) // log+swallow on partial parse
    // expose `resources` to consumers that ask — TBD shape (see §6)
}
```

Don't change the scanner dispatch. The scanners (tfsec/checkov/trivy) keep reading the source dir directly — they have their own parsers and we're not replacing them. The new parsed resource list is *additional* output, not a replacement input.

The "TBD shape" in the snippet above is the open coordination question with the consumer (§6). Plausible options: stash on a new field in `Result`, return alongside `Findings` from `Collect`, write a sidecar file, expose via a new subcommand (`cbx audit --source --emit-resources`).

## 5. Test strategy

Mirror the state parser tests:

- `parsers/terraform_source_test.go` — table-driven across small HCL fixtures under `parsers/testdata/terraform_source/`. One fixture per major case: literal-only resource, resource with `var.x` reference (T1: partial; T2: resolved), `count`-expanded resource (T3), `for_each` map (T3), provider region attachment.
- A round-trip test asserting that a known fixture produces the same `DiscoveredResource` shape that the Terraform **state** parser produces for the same resource definition. This is the cross-mode invariant Phase 4 exists to provide.
- An `internal/audit` integration test that runs `cbx audit --source <fixture>` and verifies the new resource list reaches whatever consumer §6 selects.

No e2e fixture changes needed — the existing `e2e/fixtures/terraform-sample-source/` covers the happy path; CFN/K8s/Helm fixtures stay untouched (Phase 4 is HCL only).

## 6. Open coordination questions (the actual blockers)

These need answers from named owners before any code lands. **The trigger for starting Phase 4 is one of these getting answered**, not architectural readiness:

1. **Who consumes `DiscoveredResource` from source mode?** Plan §10 named platform-app's "import existing infrastructure" feature as the canonical trigger. Confirm this with the platform-app owner. If they want to consume it, what shape — JSON envelope on stdout, sidecar file, API push?
2. **Is the existing `DiscoveredResource` schema sufficient?** platform-app's Pydantic model dictates the JSON tags. If their import flow needs additional fields (e.g. `Source string` discriminator, file/line provenance), the schema change has to land coordinated across both repos.
3. **What's the fidelity bar?** T1 (literal-only) emits an incomplete picture for any non-trivial repo. Is that acceptable to the consumer, or does Phase 4 effectively need T2 + T3 to ship?
4. **`terraform init` permissibility?** If the consumer needs accurate module resolution, the offline guarantee bends. Possible compromise: a `--allow-init` opt-in flag, off by default. Confirm before T4 work.
5. **CFN / K8s / Helm parity?** If the consumer only needs Terraform, leave the others. If they need all four, that's not Phase 4 — that's Phases 4a/b/c/d, and each needs its own design doc.

## 7. Non-goals (lifted from §2 of the source-mode plan, restated for clarity)

- **Pulumi source.** Pulumi source is general-purpose code (TS/Python/Go); no static path that doesn't run `pulumi preview`. Continue to require `pulumi stack export | cbx audit --pulumi-state -`.
- **Drift detection.** Comparing source-derived findings to state-derived findings is a separate feature. Phase 4 enables it; it doesn't ship it.
- **Live cloud reading.** Belongs to platform-app's hosted product; explicitly out of scope.
- **Replacing scanner parsers.** Scanners (tfsec/checkov/trivy) keep their own HCL paths; Phase 4 adds a CB-owned parser for the resource model, not for findings.

## 8. Risks

| # | Risk | Mitigation |
|---|---|---|
| R1 | T1 fidelity is too low to be useful, forcing immediate jump to T3 mid-MR | Get the consumer to accept T1 in writing before starting; or budget T1+T2+T3 from day 1. |
| R2 | Schema divergence with platform-app's Pydantic model | Lock the schema in §6 before any code; add a contract test that diff-checks the Go struct against an exported Pydantic JSON Schema. |
| R3 | `hashicorp/hcl/v2` introduces a transitive dep that breaks the single-binary distribution | Vet at design time: `go mod why -m`. HCL pulls in `cty` and a small set; should be fine. |
| R4 | Module resolution (T4) ends up the only way to get useful output for some consumers, breaking offline | Document the limit. Refuse `--allow-init` until that's a paid-feature gate or otherwise scoped. |
| R5 | Speculative effort if no consumer materializes | The point of this doc — don't start without §6 closed. |

## 9. Estimate (refined from plan §3's "1-2 weeks")

| Tier | Calendar |
|---|---|
| T1 only — literal resources, region attachment, lowering, tests | 3–4 days |
| T1 + T2 — variables + locals via `cty.EvalContext` | +2–3 days |
| T1 + T2 + T3 — tfvars + `count`/`for_each` fan-out | +3–5 days |
| Schema coordination + cross-repo contract test | +1–2 days |
| Total to first useful ship | **8–14 calendar days** |

Plan §3's "1-2 weeks" is right for T1+T2+T3 with coordination. T1-only is a one-week ship if the consumer accepts the fidelity.

## 10. Decision log

- **2026-05-10:** doc drafted in parked state. No consumer named. Don't start work until §6 questions get owners and answers. Recommend the platform-app team be polled on whether the "import existing infrastructure" feature wants source-mode resource lists; that conversation is the trigger.
