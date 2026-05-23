# Implementation plan — `cbx audit --aws` (live AWS account audit)

**Status:** proposed, not yet ticketed
**Author:** drafted by Claude Code, 2026-05-23, in collaboration with @radek.forgac
**Owner:** TBD
**Linear epic:** TBD (suggested parent: "CB-XXX: cbx audit live AWS account")
**Builds on:**
- [`2026-05-10-cbx-audit-source-mode-plan.md`](./2026-05-10-cbx-audit-source-mode-plan.md) — established the multi-input audit pattern (state | source | …)
- [`2026-05-10-cbx-audit-deep-analysis-plan.md`](./2026-05-10-cbx-audit-deep-analysis-plan.md) — established `--llm` + native CB-rules analyzers
- [`2026-05-11-cbx-audit-phase-f-cb-knowledge-grounded.md`](./2026-05-11-cbx-audit-phase-f-cb-knowledge-grounded.md) — established `--cb-knowledge` grounded analyzer + primitive-id map
- [`2026-05-11-phase-f-uptime-cost.md`](./2026-05-11-phase-f-uptime-cost.md) — backend-availability prerequisite for `--cb-knowledge`

**Related parking-lot:**
- [`../parking-lot/2026-05-23-cb-hosted-llm-for-audit.md`](../parking-lot/2026-05-23-cb-hosted-llm-for-audit.md) — `--llm cloudbooster` (parked)

---

## 1. Why this doc exists

`cbx audit` today reads from **declared infrastructure** — Pulumi state, Terraform state, IaC source trees. The natural fourth input is **deployed infrastructure read directly from an AWS account**: a developer logs into a profile, runs `cbx audit --aws`, and gets findings against what's actually running, grouped into components, grounded in CloudBooster's curated knowledge.

This is the input shape `prowlerAdapter` was always built for — `internal/audit/adapter_prowler.go` is gated `ErrSourceModeUnsupported` because there was no live-AWS input mode. This plan unlocks it.

### 1.1 Strategy reversal vs `agent-arch-talks/rework-2.5.1/01-strategy.md`

`CLAUDE.md` currently asserts: *"Live cloud reading. That belongs to platform-app's hosted product; explicitly out of scope per `agent-arch-talks/rework-2.5.1/01-strategy.md`."* This plan reverses that assertion **for the single-account ad-hoc audit use case**. The boundary is now:

| Surface | Owner | Audience |
|---|---|---|
| Single-account ad-hoc audit from a developer's laptop | **cbx** (this plan) | Devs evaluating their own infra |
| Continuous / multi-account / org-wide hosted scanning | **platform-app** | Platform / security teams |

Implementation work in §13 includes a one-line update to both `CLAUDE.md` and `agent-arch-talks/rework-2.5.1/01-strategy.md` so the boundary doc matches reality.

---

## 2. Goal

Make `cbx audit --aws` produce findings that:

1. **Inventory** every resource the configured AWS profile can read, across the user-selected regions, with no external setup (no Config, no Resource Explorer indexes).
2. **Group** discovered resources into components using two complementary lenses in v1 (tag-based + CB-primitive match), with two more added in later phases (network topology + reference graph).
3. **Audit** each component / resource against CloudBooster's curated AWS knowledge via the existing Phase F grounded analyzer (`--cb-knowledge`), and against the existing scanner adapters (especially **prowler**, which is purpose-built for this input).
4. **Flag orphans, misconfigurations, and recommended changes** in the same `Finding` shape as every other `cbx audit` mode, so JSON envelope / exit codes / report rendering all stay unchanged.

### 2.1 Success criteria for v1

- `cbx audit --aws` against a small dev account (≤ 50 resources, 1 region) finishes in ≤ 60s with zero account setup beyond `aws configure`.
- Output includes at least one finding from each: prowler check (security), CB-knowledge-grounded check (best-practice), and orphan-detection check (cost/hygiene).
- Resources are grouped into ≥ 1 named component (tag-based) plus a `cb:<primitive>:<id>` group for any matched CB recipe.
- IAM permission errors are caught early with a clear "you need these IAM actions" error, not a flood of partial failures.

---

## 3. Non-goals (explicit)

Listed because they're tempting and they're not what this is.

- **Continuous / scheduled / org-wide scanning.** That's platform-app. cbx is invoked by a human at a terminal, one account at a time.
- **Multi-account fan-out from a single command.** v1 audits one AWS account per invocation. Multi-account is "run cbx N times" until a real product need says otherwise.
- **AWS Organizations / SCP analysis.** Out of scope; that's a hosted-product concern.
- **Drift detection vs declared IaC.** Comparing `--aws` findings to `--source` findings for the same infra is interesting but a separate feature.
- **Writing / remediating.** Read-only end-to-end. Findings name what's wrong; they don't apply fixes. No `cbx fix --aws`.
- **Non-AWS clouds.** AWS only. GCP / Azure are separate plans.
- **CloudBooster-hosted inference.** See parking-lot. v1 requires either `--llm claude-code` (subprocess) or a `cbx llm login` provider for the grounded path; the offline default still works.
- **A new `Finding` schema or output envelope.** Everything flows through existing types.

---

## 4. The substrate we're reusing vs. building

### 4.1 What already exists

| Component | Reuse / extend? | Notes |
|---|---|---|
| `internal/audit.FindingProvider` interface | **reuse** | New AWS-discovery-backed providers register the same way |
| `internal/audit.DiscoveredResource` | **reuse, possibly extend** | May need a small `AWS *AWSDiscoveredMeta` extension for ARN / region / account |
| `internal/audit/adapter_prowler.go` | **unlock** | Already implemented; flip `SupportsSource` semantics or add a `SupportsAWS` axis |
| `internal/audit/llm_grounded.go` (Phase F) | **reuse** | Same grounded-analyzer path works against `DiscoveredResource` regardless of where the resource was discovered |
| `internal/audit/primitives_aws.go` (Phase F primitive map) | **extend** | Currently keyed on Terraform type names; needs a CFN-type-keyed companion (see §6) |
| `pkg/cmd/audit.go` flag plumbing | **extend** | Add `--aws`, `--aws-profile`, `--regions` |
| `internal/audit/runner.go` (state/source dispatch) | **extend** | Add an AWS branch |
| `pkg/output` JSON envelope | **reuse** | Zero changes |

### 4.2 What we're building net-new

- `internal/audit/discover/aws/` — AWS discovery package (CloudControl API + curated per-service describers)
- `internal/audit/group/` — component-grouping pass (tag-based + CB-primitive match in v1)
- `tools/genprimitives/` extension — emit a CFN-type-keyed map alongside the Terraform-keyed one
- `pkg/cmd/audit.go` — three new flags + mutual-exclusion update
- `internal/audit/types.go` — `Options.AWS`, `Options.AWSProfile`, `Options.Regions` fields

### 4.3 Why not call platform-app's existing AWS providers

`platform-app/be/app/providers/aws/` is substantial — primitives, facets, network helpers, subnet classification, LB helpers, EventBridge schema discovery. Tempting to call it via API.

**We don't, because:**

1. `cbx audit` must work offline by default (CLAUDE.md, load-bearing). Calling `app.cloudbooster.io` for discovery breaks that promise.
2. platform-app providers are Python and tightly coupled to that backend's persistence / event model — not extractable as a library.
3. The hosted product (platform-app) does multi-account, continuous, with stored state. cbx does single-account, one-shot, in-memory. Different deployment shapes warrant different code.

**The shared substrate stays `DiscoveredResource`** — same shape, different producers. When platform-app's "import existing infrastructure" feature changes the resource model, both code paths update together. Coordinate via cross-repo MR per §5 of `CLAUDE.md`.

---

## 5. Phasing

| Phase | Scope | Estimate | Ship gate |
|---|---|---|---|
| **v1** | `--aws` + `--aws-profile` + `--regions`. CloudControl discovery + curated per-service for the top ~10 types. Tag-based grouping + CB-primitive matching (gated on §6). Prowler integration + Phase F grounded analyzer. IAM preflight. | ~2 weeks | E2E against a real dev account; ≥ 1 finding from each of prowler / grounded / orphan; IAM-insufficient error is clean |
| **v1.1** | (only if §6 punts) lookup-table CFN→Terraform-name normalization so CB-primitive matching works even without genprimitives extension | ~2 days | Primitive matching emits ≥ 80% of resources to known primitives on the test account |
| **v2** | Network topology grouping (VPC → subnet → resource membership) + VPC-scoped findings | ~3–5 days | Topology-based finding emitted; report renders a per-VPC section |
| **v3** | Reference-graph grouping — walk SG egress, IAM trust policies, S3 bucket policies, Lambda triggers; cluster transitively | ~2 weeks | Cross-resource graph findings (e.g. "this IAM role has admin access and is assumable from an EC2 with public IP") |

v1 is the only phase ticketed by this doc. v1.1 / v2 / v3 get separate plan docs when their turn arrives.

---

## 6. v1 prerequisite — primitive-id map for CFN-style type names

**The blocker the advisor flagged.** `internal/audit/primitives_aws.go` (generated by `tools/genprimitives/`) maps Terraform type names → CB primitive IDs (`aws_s3_bucket → aws:s3/bucket@v1`). CloudControl API returns CloudFormation type names (`AWS::S3::Bucket`). The two namespaces don't overlap.

Two paths:

### Path A — extend genprimitives (preferred)

Check whether `platform-app/be/app/knowledge/resources/aws/primitives/*/primitive.md` frontmatter carries a CFN-type field (or could). If yes, extend `tools/genprimitives/main.go` to emit a second map:

```go
// generated alongside terraformTypeToCBPrimitive
var cfnTypeToCBPrimitive = map[string]string{
    "AWS::S3::Bucket":   "aws:s3/bucket@v1",
    "AWS::IAM::Role":    "aws:iam/role@v1",
    "AWS::Lambda::Function": "aws:compute/lambda@v1",
    // …
}
```

**Action item before v1 kicks off:** verify the frontmatter shape in platform-app. If the field exists, this is a half-day of work. If it doesn't, it needs to be added — coordinate with platform-app owners.

### Path B — hand-curated lookup (v1.1 fallback)

If Path A slips, ship v1 with **tag-based grouping only** and add a small hand-written `cfnToTerraform` lookup table for the ~30 most common types as v1.1. Worse engineering (drift potential, manual maintenance) but unblocks shipping.

**Recommendation:** spike Path A first. Estimate 1 day for the genprimitives extension assuming the frontmatter cooperates; fall back to Path B only if it doesn't.

---

## 7. v1 — concrete changes

### 7.1 CLI surface

`pkg/cmd/audit.go`:

```go
// new flags
cmd.Flags().BoolVar(&awsAccount, "aws", false,
    "Audit a live AWS account using the default AWS SDK credential chain "+
        "(env vars, ~/.aws/credentials, IAM role, SSO). Mutually exclusive "+
        "with --pulumi-state / --terraform-state / --source.")
cmd.Flags().StringVar(&awsProfile, "aws-profile", "",
    "AWS profile name to use (overrides AWS_PROFILE env var). "+
        "Only meaningful with --aws.")
cmd.Flags().StringVar(&regions, "regions", "",
    "Comma-separated AWS regions to audit. Default: the profile's "+
        "configured region. Use 'all' to audit every enabled region in "+
        "the account. Only meaningful with --aws.")
```

**Mutual exclusion update:** exactly one of `--pulumi-state` / `--terraform-state` / `--source` / `--aws` must be set. Update the error message in `validateInputMutex`.

**Why `--aws` is a bool, not a value-bearing flag like `--source <dir>`:** the input "AWS account" has no path-like value. The account is implicit in the credential chain. `--aws-profile` carries the selector. This is the cleanest mapping of CLI conventions.

### 7.2 Options struct

`internal/audit/types.go`:

```go
type Options struct {
    // existing fields...

    AWS        bool     // when true, audit a live AWS account
    AWSProfile string   // optional profile name (overrides AWS_PROFILE)
    Regions    []string // resolved region list (single, multi, or all-enabled)
}
```

`StateFile`, `SourceDir`, `AWS` are mutually exclusive (validated in `pkg/cmd/audit.go`).

### 7.3 Runner branch

`internal/audit/runner.go::Collect`:

```go
switch {
case opts.StateFile != "":   resources = ParseState(...)
case opts.SourceDir != "":   resources = collectFromSource(...)
case opts.AWS:               resources = collectFromAWS(...)  // new
default:                     return ErrNoInput
}
```

`collectFromAWS` calls into `internal/audit/discover/aws.Discover(ctx, opts)` and returns a `[]DiscoveredResource` shaped identically to the existing producers.

### 7.4 AWS discovery layer

New package `internal/audit/discover/aws/`:

```
discover/aws/
  discover.go            // Discover(ctx, opts) → []DiscoveredResource
  cloudcontrol.go        // CloudControl API list+read (the bulk)
  describers/            // curated per-service describers for deep types
    ec2.go               // DescribeInstances (CC misses some fields)
    s3.go                // ListBuckets + GetBucket*  (CC has limited coverage)
    iam.go               // ListUsers/Roles/Policies + trust-policy fetch
    rds.go               // DescribeDBInstances + DescribeDBClusters
    lambda.go            // ListFunctions + GetFunction (for env, code-size)
    elb.go               // DescribeLoadBalancers (ALB/NLB/CLB)
    vpc.go               // DescribeVpcs + DescribeSubnets + DescribeSecurityGroups
    cloudfront.go        // ListDistributions
    route53.go           // ListHostedZones (+ records via per-zone list)
    cloudwatch.go        // DescribeAlarms + DescribeLogGroups
  iam_preflight.go       // sts.GetCallerIdentity + describe-regions check
  regions.go             // resolves "default" / "all" / explicit list
  types.go               // package-local intermediate types
```

**CloudControl as the default** because:
- One uniform API surface (`ListResources` + `GetResource`) for ~700 CFN-registry types.
- Returns the CFN-shape JSON of each resource — feeds directly into CB-primitive lookup once §6 is solved.
- Zero account setup required.

**Curated per-service describers** for the ~10 types where CB's knowledge depth justifies the extra code:
- EC2 instances (CloudControl returns the base shape; we want instance-profile / IMDSv2 / user-data state)
- S3 buckets (CC covers Properties but you still want PublicAccessBlock / Encryption / Versioning / Lifecycle from the service API)
- IAM (CC has roles/policies but assume-role-policy text + last-used data wants the IAM API)
- RDS, Lambda, ELB, VPC/SG, CloudFront, Route53, CloudWatch (each has CB-knowledge depth justifying the extra calls)

**CloudControl coverage gaps:** ~30% of common AWS types still aren't in the CFN registry (some IAM Identity Center, some Bedrock, some IoT). Doc the gap; user-visible warning ("12 service namespaces skipped — outside CloudControl registry: …") rather than silent.

**Rate-limiting:** AWS APIs throttle hard. Use `aws-sdk-go-v2`'s built-in adaptive retry. Cap concurrent per-service describer calls at N=4 by default; expose `--aws-concurrency` if real users hit limits.

### 7.5 IAM preflight (mandatory)

Before any discovery call, the runner calls `sts.GetCallerIdentity` to:
1. Confirm credentials are present and not expired.
2. Surface the account ID and ARN in the report header.
3. Bail with a clear error if the credentials are missing/invalid — no partial discovery.

After identity check, the runner attempts `ec2.DescribeRegions` to validate the region list. If the user passed `--regions all`, this is also where the enumeration happens.

**No explicit policy check.** AWS doesn't have a real "test these permissions" API (IAM Access Analyzer is a stretch and requires extra setup). Permission failures during discovery surface as per-resource-type warnings ("listed 0 EC2 instances — possible permissions issue, check `cbx audit --aws --diagnose`") rather than blocking.

### 7.6 Minimum IAM policy (documented)

`docs/cbx-audit-aws-iam.json` ships in this MR:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "ec2:Describe*",
        "s3:ListAllMyBuckets",
        "s3:GetBucket*",
        "iam:List*",
        "iam:Get*",
        "rds:Describe*",
        "lambda:List*",
        "lambda:GetFunction*",
        "elasticloadbalancing:Describe*",
        "cloudfront:List*",
        "route53:List*",
        "cloudwatch:Describe*",
        "logs:Describe*",
        "cloudformation:ListResources",
        "cloudformation:GetResource"
      ],
      "Resource": "*"
    }
  ]
}
```

`AWSReadOnlyAccess` (AWS-managed) is a superset and acceptable. Use the curated policy when the user wants least-privilege.

### 7.7 CloudTrail / observability note (user-facing)

Every discovery call generates a CloudTrail event in the audited account. For a small account, expect ~50–200 events per `cbx audit --aws` run. The doc page must say this explicitly — security-conscious users will ask. Add the note to the report header:

```
audited account:  123456789012
audited regions:  us-east-1, eu-west-1
identity:         arn:aws:iam::123456789012:user/alice
note:             this run generated ~120 CloudTrail Read events
```

### 7.8 Component grouping

New package `internal/audit/group/`:

```
group/
  group.go         // Group(resources, opts) → []Component
  tag_based.go     // groupByTags(resources)
  primitive.go     // groupByCBPrimitive(resources)  // needs §6
  types.go         // Component struct: name, kind, resources, source
```

```go
type Component struct {
    Name      string                  // e.g. "frontend", "cb:static-site:foo"
    Kind      string                  // "tag" | "cb-primitive" | "vpc" (v2) | "ref-graph" (v3)
    Resources []DiscoveredResource
    Source    map[string]string       // e.g. {"tag.Application": "frontend"}
}
```

**Tag-based grouping algorithm:**
1. For each resource, read tags `Application`, `Service`, `Component`, `Project` (configurable via `--group-by-tag`).
2. Group by first non-empty tag in that priority order.
3. Resources with no matching tag → `"<unassigned>"` component.

**CB-primitive grouping algorithm (gated on §6):**
1. For each resource, look up its CFN type in `cfnTypeToCBPrimitive`.
2. Resources matching a known primitive → grouped as `cb:<primitive>:<resource-id>`. (Component-of-one in v1; v3 reference-graph clustering will expand this.)
3. Resources with no matching primitive → soft-warning finding ("resource type X not in CB knowledge base; consider authoring") emitted **only with `--cb-knowledge`**, never by default.

**A resource can be in multiple components** (one tag-based, one primitive-based). The renderer dedupes for display.

### 7.9 Orphan detection (one new FindingProvider)

`internal/audit/orphan_provider.go`:

Native CB rule, runs only in `--aws` mode. Walks the discovered resource graph for common orphan patterns:

- **EBS volumes** with no `Attachments`
- **Elastic IPs** with no `AssociationId`
- **Security groups** referenced by no ENI / RDS / Lambda / ELB
- **IAM roles** never assumed (LastUsedDate > 90 days)
- **Empty S3 buckets** older than 30 days
- **Lambda functions** with zero invocations in CloudWatch metrics (only if metrics fetched)
- **Unused snapshots** (EBS / RDS) older than 90 days

Each emits an `info`-severity finding with the orphan ARN + estimated monthly cost where calculable. The cost-estimation is back-of-envelope (per-GB-month rates baked in, not Pricing API).

### 7.10 Prowler integration

`adapter_prowler.go` gets a new `SupportsAWS() bool` axis (returns `true`) alongside the existing `SupportsSource()`. The runner picks scanners that support the active input mode.

By default, prowler **is not** auto-invoked (consistent with the existing mock-default principle — opt-in via `--scanners=prowler`). When invoked, the runner passes through `AWS_PROFILE` from `Options.AWSProfile` and constrains via `--region` per the resolved region list.

### 7.11 Phase F grounded analyzer

`llm_grounded.go` works as-is. Once the AWS-discovered `DiscoveredResource[]` has CB-primitive IDs attached (§7.8), the grounded analyzer's `aws_lookup_primitive` tool call resolves identically to source-mode. No changes required.

### 7.12 Output

Report header gains an "Audited account" section (§7.7). Component grouping renders as `## Components` with one subsection per `Component`. Findings render under their component when possible, with cross-component findings (e.g. orphan SGs) in a separate `## Account-wide findings` section.

JSON envelope: `Result.Components []Component` is a new top-level field. Backward-compatible — existing consumers ignore unknown fields. `pkg/audit` exports the type alias so `cb-cli` can consume.

---

## 8. Testing strategy

### 8.1 Unit tests

- `discover/aws/cloudcontrol_test.go` — mocked AWS SDK responses, asserts `DiscoveredResource` shape
- `discover/aws/describers/*_test.go` — one test per describer, mocked
- `discover/aws/regions_test.go` — `--regions default | all | us-east-1,eu-west-1` resolution
- `group/tag_based_test.go` — priority-order tag resolution, unassigned fallback
- `group/primitive_test.go` — CFN-type-to-primitive lookup (gated on §6)
- `orphan_provider_test.go` — each orphan pattern with synthetic resource fixtures
- `iam_preflight_test.go` — missing creds, expired creds, invalid region

### 8.2 E2E tests (new build tag: `e2e_aws`)

`e2e/aws/` — runs only when `CBX_E2E_AWS_PROFILE` env var is set. CI doesn't run these by default (no shared AWS account); contributors run locally against their own dev account. Tests:

- Discovery in an empty account → zero resources, clean exit
- Discovery in a known fixture account (we ship a Terraform module under `e2e/aws/fixtures/` to set up + tear down)
- IAM-insufficient profile → clean error
- `--regions all` enumeration completes

### 8.3 Cost / blast-radius gates

E2E fixture lives under one tag (`cbx-e2e-aws=1`) so teardown is `aws-nuke --filter tag=cbx-e2e-aws=1`. Cost cap on the fixture account: < $0.10 per E2E run.

---

## 9. Cost / quota

| Concern | Mitigation |
|---|---|
| AWS API call cost | CloudControl + describers are free API calls; no per-call charge |
| Throttling | aws-sdk-go-v2 adaptive retry; `--aws-concurrency` knob |
| Phase F grounded analyzer LLM cost | Existing `--llm-max-cost` cap applies unchanged (default $2.00) |
| CloudTrail event volume | Documented (§7.7); no programmatic mitigation needed |
| Account-discovery noise (security team alerts) | Add doc note: "if your org alerts on Describe-event volume, coordinate before running" |

---

## 10. Risks

### R1 — CloudControl API coverage gap

**Probability:** high. **Impact:** medium.

CloudControl supports ~700 of ~1,400 AWS types. The remainder are CFN-registry-absent and silently invisible. Mitigation:
- v1 surfaces a one-line "skipped service namespaces" warning in the report.
- Curated per-service describers in §7.4 fill the most painful gaps.
- v2+ adds describers as user reports come in.

### R2 — Primitive-id map gap (§6)

**Probability:** medium. **Impact:** high if it lands in §6 Path B.

If genprimitives extension is harder than the half-day estimate, v1 ships **tag-based only** and primitive matching becomes v1.1. Communicated as a known limitation; the product remains useful.

### R3 — `api.cloudbooster.io` still NXDOMAIN

**Probability:** medium (per the 2026-05-11 smoke). **Impact:** high for the grounded path, zero for the offline default.

`cbx audit --aws` (no `--cb-knowledge`) works end-to-end with prowler + orphan detection + native rules. The `--cb-knowledge` path stays in the same broken state as today, until the backend is provisioned. Doc this clearly; don't gate v1 on backend revival.

### R4 — IAM permission failures cascade into noisy output

**Probability:** medium. **Impact:** medium.

Mitigation: per-service describer wraps its errors in a `PermissionDenied` sentinel; the runner aggregates and emits **one** warning per service ("12 IAM-permission errors in s3.*; least-privilege policy at docs/…"), not 12 individual findings.

### R5 — Cross-region resources double-counted

**Probability:** low. **Impact:** low.

Some resources (IAM, CloudFront, Route53) are global; they appear in any region scan. The discovery layer dedupes by ARN before returning.

### R6 — Prowler binary not installed

**Probability:** high (Prowler isn't bundled). **Impact:** low.

`--scanners=prowler` already errors cleanly when the binary is missing; v1 inherits this behavior unchanged.

### R7 — User runs `cbx audit --aws` against a prod account by accident

**Probability:** medium. **Impact:** low (it's read-only, but CloudTrail noise is real).

Mitigation: when the resolved account ID matches a pattern like `prod`, `production`, or is tagged as such in cost-allocation tags (not always available), print a confirmation prompt. Suppress with `--yes`. This is bikeshed-able; ship without it if scope-cuts demand.

---

## 11. Open questions (to settle before kick-off)

1. **§6 path.** Does `platform-app/be/app/knowledge/resources/aws/primitives/*/primitive.md` frontmatter carry a CFN type field? If not, who adds it? **Owner: platform-app frontend/backend lead.**
2. **Boolean vs value flag.** Is `--aws` (bool) + `--aws-profile <name>` the right ergonomic, or do we prefer `--aws-profile default` as the single trigger flag? Current draft picks the former.
3. **Region default behavior.** When no `--regions` and the profile has no default region, do we error or auto-pick `us-east-1`? Current draft says error (explicit > implicit).
4. **Prowler-by-default for `--aws` mode?** v1 keeps prowler opt-in (`--scanners=prowler`). Should `--aws` flip the default since prowler is purpose-built for this input? Arguments both ways.
5. **`--diagnose` flag.** §7.5 mentions this as a UX for IAM debugging. Ship in v1 or v1.1?
6. **Cost surfacing.** Should the report header estimate the total AWS API cost of the run? It's $0 today (Describe* calls are free), but the line is reassuring. Probably yes.

---

## 12. v2 / v3 outlines (sketch, not commitments)

### v2 — Network topology grouping (~3–5 days)

- New `group/network_topology.go`: walks VPCs → subnets → SGs → ENIs → resources
- Emits findings like "SG `sg-0abc` allows 0.0.0.0/0 ingress on 22 and is attached to EC2 in a public subnet"
- Renderer gains a per-VPC section
- Independent slice — doesn't touch v1 code paths

### v3 — Reference-graph grouping (~2 weeks)

- New `group/refgraph/` package — builds a typed reference graph over:
  - IAM trust policies (who can assume what)
  - IAM action grants (who can do what to which resource)
  - S3 bucket policies
  - SG egress rules
  - Lambda triggers (EventBridge, API Gateway, S3 events)
  - VPC peering / TGW attachments
- Component definition becomes "transitively connected subgraph"
- Findings can express cross-resource invariants ("this Lambda has an attached role with `s3:*` on `arn:aws:s3:::sensitive-bucket`")
- Own design doc when this phase starts

---

## 13. Out-of-this-doc work that v1 still needs

These are tracked here so they don't get lost when v1 is ticketed.

- [ ] One-line update to `CLAUDE.md` removing "Live cloud reading [is] explicitly out of scope" and pointing to this plan
- [ ] One-line update to `../platform-app/agent-arch-talks/rework-2.5.1/01-strategy.md` documenting the revised boundary
- [ ] Coordinate with platform-app on `DiscoveredResource` extensions (if any) before merging
- [ ] Coordinate with platform-app on §6 primitive-frontmatter CFN field
- [ ] User-facing docs page: `documentation/content/docs/audit/aws-account.mdx` — IAM policy, regions, cost note, CloudTrail note
- [ ] CHANGELOG entry under `[Unreleased] / Added`

---

## 14. Why this design will hold up

The framing as a fourth `--<input>` flag on the existing `cbx audit` command means:
- Every downstream surface (exit codes, JSON envelope, report rendering, `--llm`, `--cb-knowledge`, `--scanners`) works unchanged.
- The new code is concentrated in three places (discovery, grouping, prowler unlock), which are each independently testable.
- The pkg/internal layering rule is preserved — new code goes in `internal/`, exposed only through `pkg/audit` type aliases as needed.
- `cb-cli` gets the feature for free the moment it picks up the new `pkg/cmd.Execute` signature; no proprietary fork required.

The single thing that can derail v1 is §6. If the primitive-map extension blocks for more than a day, v1 ships with tag-based grouping only and §6 becomes v1.1's headline. That's a known graceful degradation, not a project risk.
