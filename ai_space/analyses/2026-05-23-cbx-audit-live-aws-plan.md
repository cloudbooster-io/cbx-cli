# Implementation plan — `cbx audit aws` (live AWS account audit)

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

`cbx audit` today reads from **declared infrastructure** — Pulumi state, Terraform state, IaC source trees. The natural fourth input is **deployed infrastructure read directly from an AWS account**: a developer logs into a profile, runs `cbx audit aws`, and gets findings against what's actually running, grouped into components, grounded in CloudBooster's curated knowledge.

This is the input shape `prowlerAdapter` was always built for (`internal/audit/adapter_prowler.go` is gated `ErrSourceModeUnsupported` because there was no live-AWS input mode). v1 does not invoke it — see §7.10 for why — but the input mode this plan creates is what eventually unlocks it.

### 1.1 Strategy reversal vs `agent-arch-talks/rework-2.5.1/01-strategy.md`

`CLAUDE.md` currently asserts: *"Live cloud reading. That belongs to platform-app's hosted product; explicitly out of scope per `agent-arch-talks/rework-2.5.1/01-strategy.md`."* This plan reverses that assertion **for the single-account ad-hoc audit use case**. The boundary is now:

| Surface | Owner | Audience |
|---|---|---|
| Single-account ad-hoc audit from a developer's laptop | **cbx** (this plan) | Devs evaluating their own infra |
| Continuous / multi-account / org-wide hosted scanning | **platform-app** | Platform / security teams |

Implementation work in §13 includes a one-line update to both `CLAUDE.md` and `agent-arch-talks/rework-2.5.1/01-strategy.md` so the boundary doc matches reality.

---

## 2. Goal

Make `cbx audit aws` produce findings that:

1. **Inventory** every resource the configured AWS profile can read, across the user-selected regions, with no external setup (no Config, no Resource Explorer indexes).
2. **Group** discovered resources into components using two complementary lenses in v1 (tag-based + CB-primitive match), with two more added in later phases (network topology + reference graph).
3. **Audit** each component / resource against CloudBooster's curated AWS knowledge via the existing Phase F grounded analyzer (`--cb-knowledge`) and native CB rules. v1 deliberately ships with no external CLI dependencies (§7.10).
4. **Flag orphans, misconfigurations, and recommended changes** in the same `Finding` shape as every other `cbx audit` mode, so JSON envelope / exit codes / report rendering all stay unchanged.

### 2.1 Success criteria for v1

- `cbx audit aws` against a small dev account (≤ 50 resources, 1 region) finishes in ≤ 60s with zero account setup beyond `aws configure`.
- Output includes at least one finding from each: native CB-rule check (correctness), CB-knowledge-grounded check (best-practice, when `--cb-knowledge` is on), and orphan-detection check (cost/hygiene).
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
| `internal/audit/adapter_prowler.go` | **leave alone in v1** | Ready to be unlocked (just needs a `SupportsAWS` axis), but v1 keeps no-external-CLI rule. Picked up in a follow-up. |
| `internal/audit/llm_grounded.go` (Phase F) | **reuse** | Same grounded-analyzer path works against `DiscoveredResource` regardless of where the resource was discovered |
| `internal/audit/primitives_aws.go` (Phase F primitive map) | **extend** | Currently keyed on Terraform type names; needs a CFN-type-keyed companion (see §6) |
| `pkg/cmd/audit.go` + new `pkg/cmd/audit_aws.go` | **extend + add** | Existing flag-based modes stay unchanged; `aws` lands as a sibling subcommand |
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
| **v1** | `cbx audit aws [profile]` subcommand. `--config` / `--regions` / `--diagnose` / `--aws-concurrency` flags. CloudControl discovery + curated per-service for the top ~10 types. Tag-based grouping + CB-primitive matching (§6 extension is in-scope, not a prerequisite). Native CB rules + orphan detection + Phase F grounded analyzer. IAM preflight + interactive region prompt. **No external CLI dependencies.** | ~2 weeks | E2E against a real dev account; ≥ 1 finding from each of native-rule / grounded / orphan; IAM-insufficient + `--diagnose` produces a usable policy patch |
| **v1.1** | *(retired)* §6 fallback no longer needed — the CFN-alias extension is part of v1 | — | — |
| **v2** | Network topology grouping (VPC → subnet → resource membership) + VPC-scoped findings | ~3–5 days | Topology-based finding emitted; report renders a per-VPC section |
| **v3** | Reference-graph grouping — walk SG egress, IAM trust policies, S3 bucket policies, Lambda triggers; cluster transitively | ~2 weeks | Cross-resource graph findings (e.g. "this IAM role has admin access and is assumable from an EC2 with public IP") |

v1 is the only phase ticketed by this doc. v1.1 / v2 / v3 get separate plan docs when their turn arrives.

---

## 6. v1 prerequisite — primitive-id map for CFN-style type names

**Investigated 2026-05-23 — no longer a v1 risk.** `internal/audit/primitives_aws.go` (generated by `tools/genprimitives/`) maps Terraform type names → CB primitive IDs (`aws_s3_bucket → aws:s3/bucket@v1`). CloudControl API returns CloudFormation type names (`AWS::S3::Bucket`).

**The investigation result:** `platform-app/be/app/knowledge/resources/aws/primitives/*/primitive.md` frontmatter does **not** carry a CFN type field — it only carries `type_ids`, `tags`, and `composition`. BUT the existing generator already hand-curates Terraform + Pulumi aliases in an `aliasTable` (see `tools/genprimitives/main.go` lines 53–115). The CFN extension fits the same pattern:

```go
type aliasEntry struct {
    Dir     string   // e.g. "s3_bucket"
    TF      []string // existing — e.g. "aws_s3_bucket"
    Pulumi  []string // existing — e.g. "aws:s3/bucket:Bucket"
    CFN     []string // NEW — e.g. "AWS::S3::Bucket"
    Comment string
}
```

The generator then emits a third map (`cfnTypeToCBPrimitive`) alongside the existing two. Populating CFN names is mechanical — they follow a regular pattern (`AWS::Service::Resource`) and there are ~50 entries to fill.

**Scope:** ~half a day, entirely inside `cbx-cli`, zero cross-repo coordination. Folds into v1 as a regular task, not a prerequisite.

**No fallback needed.** v1 ships with CB-primitive matching working.

---

## 7. v1 — concrete changes

### 7.1 CLI surface

**`aws` is a subcommand of `audit`, not a flag.** The other input modes stay flag-based (no breaking change to existing usage); `aws` lands as a sibling subcommand because its semantics differ — it takes a *profile selector* (or credentials file), not a path to a file/dir.

`pkg/cmd/audit_aws.go` (new file):

```go
// cbx audit aws                        — default profile (AWS_PROFILE env or "default")
// cbx audit aws prod                   — positional arg names the profile
// cbx audit aws --config /path/creds   — explicit credentials file (overrides profile)
// cbx audit aws --regions us-east-1,eu-west-1
// cbx audit aws --regions all
//
// All grouped/inherited audit flags (--output, --report-file, --llm,
// --cb-knowledge, --llm-max-cost, --yes, --json, --quiet, etc.) work
// identically on the subcommand.

cmd := &cobra.Command{
    Use:   "aws [profile]",
    Short: "Audit a live AWS account using the default SDK credential chain or an explicit profile / credentials file.",
    Args:  cobra.MaximumNArgs(1),
    RunE:  runAuditAWS,
}
cmd.Flags().StringVar(&configFile, "config", "",
    "Path to an AWS credentials file (overrides profile resolution). "+
        "Equivalent to setting AWS_SHARED_CREDENTIALS_FILE for this run.")
cmd.Flags().StringVar(&regions, "regions", "",
    "Comma-separated AWS regions to audit. Default: the profile's "+
        "configured region (prompts if missing — see §7.5). "+
        "Use 'all' to audit every enabled region in the account.")
cmd.Flags().IntVar(&awsConcurrency, "aws-concurrency", 4,
    "Max concurrent AWS API calls per service. Lower if you hit throttling.")
```

**Resolution precedence for the AWS profile** (highest wins):
1. `--config <path>` — explicit credentials file
2. positional `[profile]` arg
3. `AWS_PROFILE` env var
4. `default` profile in `~/.aws/credentials`

The existing `cbx audit` command keeps its current flag-based input selection (`--pulumi-state`, `--terraform-state`, `--source`). When the user runs `cbx audit` *without* any input flag *and* without the `aws` subcommand, the usage error lists all four options.

**Why subcommand + positional, not `--aws` flag:** the existing input flags all take a *path value*. AWS profile is a *named selector*, not a path. Modelling it as a subcommand with an optional positional reads naturally (`cbx audit aws prod` matches how `aws --profile prod sts get-caller-identity` reads) and avoids visually pretending it's a fourth file-path flag.

### 7.2 Options struct

`internal/audit/types.go`:

```go
type Options struct {
    // existing fields...

    AWS               bool     // true when invoked via `audit aws` subcommand
    AWSProfile        string   // resolved profile (positional arg | AWS_PROFILE | "default")
    AWSConfigFile     string   // optional path to credentials file (--config)
    Regions           []string // resolved region list (single, multi, or all-enabled)
    AWSConcurrency    int      // per-service API-call concurrency cap
    Diagnose          bool     // --diagnose: emit per-call permission errors + IAM fix
}
```

`StateFile`, `SourceDir`, `AWS` are mutually exclusive (validated at the cobra layer, not in `Options`).

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

### 7.5 IAM preflight + region resolution

Before any discovery call, the runner calls `sts.GetCallerIdentity` to:
1. Confirm credentials are present and not expired.
2. Surface the account ID and ARN in the report header.
3. Bail with a clear error if the credentials are missing/invalid — no partial discovery.

**Region resolution sequence:**

1. If `--regions` was passed, validate via `ec2.DescribeRegions` and use as-is. `--regions all` triggers the enumeration here.
2. Else if the profile has a default region (`region = …` in `~/.aws/config`, or `AWS_REGION` env), use it.
3. Else **prompt the user interactively** with the list of enabled regions:
   ```
   ? Profile 'prod' has no default region configured.
     Which region(s) should this audit cover?
       › us-east-1  (most resources here, based on a quick S3-bucket-region peek)
         eu-west-1
         all enabled regions
         enter custom list...
   ```
4. In non-interactive mode (`--json`, `--quiet`, `--yes`, or no TTY), the prompt is replaced by a clean error: `region is required: pass --regions <list> or set AWS_REGION`.

**No explicit policy check.** AWS doesn't have a real "test these permissions" API. Permission failures during discovery surface as per-resource-type warnings ("listed 0 EC2 instances — possible permissions issue, re-run with `--diagnose`") rather than blocking. The `--diagnose` flag (§7.13) gives the actionable detail.

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

Every discovery call generates a CloudTrail event in the audited account. For a small account, expect ~50–200 events per `cbx audit aws` run. The doc page must say this explicitly — security-conscious users will ask. Add the note to the report header:

```
audited account:  123456789012
audited regions:  us-east-1, eu-west-1
identity:         arn:aws:iam::123456789012:user/alice
note:             this run generated ~120 CloudTrail Read events
```

API call cost is intentionally not surfaced — every AWS Describe* / List* / Get* call used by discovery is free, so the line would read "$0.00" forever.

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

### 7.10 Prowler integration — **deferred out of v1**

`adapter_prowler.go` is ready to be unlocked for `--aws` mode (just needs a `SupportsAWS() bool` axis added). **v1 deliberately does not enable it** because the constraint for this train is *no external CLI dependencies* — cbx should not shell out to a `prowler` binary the user has to install separately.

This means v1's finding sources are entirely native:
- **Native CB rules** over the discovered resources (the same `staticScanner.evaluateResource()` path that source mode uses on parsed HCL)
- **Orphan detection** (§7.9, a new native provider)
- **Phase F grounded analyzer** when `--cb-knowledge` is passed (§7.11)

Prowler unlock becomes a follow-up phase if/when the no-external-CLI constraint relaxes. The hook surface in `adapter_prowler.go` stays — no code rot — but the runner won't select it for AWS mode in v1.

### 7.11 Phase F grounded analyzer

`llm_grounded.go` works as-is. Once the AWS-discovered `DiscoveredResource[]` has CB-primitive IDs attached (§7.8), the grounded analyzer's `aws_lookup_primitive` tool call resolves identically to source-mode. No changes required.

### 7.12 Output

Report header gains an "Audited account" section (§7.7). Component grouping renders as `## Components` with one subsection per `Component`. Findings render under their component when possible, with cross-component findings (e.g. orphan SGs) in a separate `## Account-wide findings` section.

JSON envelope: `Result.Components []Component` is a new top-level field. Backward-compatible — existing consumers ignore unknown fields. `pkg/audit` exports the type alias so `cb-cli` can consume.

### 7.13 `--diagnose` mode

A flag on the `aws` subcommand (and only on that subcommand). Default off.

**Without `--diagnose`** — permission failures aggregate into one warning per service:

```
WARN: 12 IAM-permission errors in s3.*; re-run with --diagnose for details
```

**With `--diagnose`** — per-call detail + actionable IAM policy patch:

```
Permission errors during discovery:
  ✗ s3:ListAllMyBuckets    → AccessDenied (arn:aws:iam::123:user/alice)
  ✗ iam:ListRoles          → AccessDenied
  ✗ lambda:ListFunctions   → AccessDenied
  ✗ ec2:DescribeInstances  → AccessDenied (eu-west-1 only)

Recommended IAM policy patch to fix the above:
  { "Effect": "Allow",
    "Action": ["s3:ListAllMyBuckets", "iam:ListRoles",
               "lambda:ListFunctions", "ec2:DescribeInstances"],
    "Resource": "*" }

Apply with: aws iam put-user-policy --user-name alice \
              --policy-name cbx-audit --policy-document file://patch.json
```

Implementation: every AWS-SDK call in the discovery layer wraps its error in a `PermissionError` with the (service, action, region) tuple parsed from the `*smithy.OperationError`. The diagnose-mode renderer collects all `PermissionError`s and emits the policy-patch JSON at the end of the report.

**Ships in v1.** IAM-policy debugging is the #1 first-run friction; the half-day to add this saves real user pain.

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

### R2 — Primitive-id map gap (§6) — **mitigated by 2026-05-23 investigation**

Originally flagged as a v1 blocker. Investigation found the genprimitives generator already hand-curates the alias table; adding a `CFN []string` field follows the same pattern as the existing TF/Pulumi alias columns. Half-day task inside cbx-cli, no cross-repo coordination. Demoted from "risk" to "regular v1 work."

### R3 — `api.cloudbooster.io` still NXDOMAIN

**Probability:** medium (per the 2026-05-11 smoke). **Impact:** high for the grounded path, zero for the offline default.

`cbx audit aws` (no `--cb-knowledge`) works end-to-end with native CB rules + orphan detection. The `--cb-knowledge` path stays in the same broken state as today, until the backend is provisioned. Doc this clearly; don't gate v1 on backend revival.

### R4 — IAM permission failures cascade into noisy output

**Probability:** medium. **Impact:** medium.

Mitigation: per-service describer wraps its errors in a `PermissionDenied` sentinel; the runner aggregates and emits **one** warning per service ("12 IAM-permission errors in s3.*; least-privilege policy at docs/…"), not 12 individual findings.

### R5 — Cross-region resources double-counted

**Probability:** low. **Impact:** low.

Some resources (IAM, CloudFront, Route53) are global; they appear in any region scan. The discovery layer dedupes by ARN before returning.

### R6 — Prowler binary not installed — **N/A in v1**

Removed. v1 does not invoke prowler (§7.10). Re-emerges if/when the no-external-CLI constraint relaxes.

### R7 — User runs `cbx audit aws` against a prod account by accident

**Probability:** medium. **Impact:** low (it's read-only, but CloudTrail noise is real).

Mitigation: when the resolved account ID matches a pattern like `prod`, `production`, or is tagged as such in cost-allocation tags (not always available), print a confirmation prompt. Suppress with `--yes`. This is bikeshed-able; ship without it if scope-cuts demand.

---

## 11. Open questions — resolved 2026-05-23

All six original open questions are settled. Captured here as a decision log.

| # | Question | Decision |
|---|---|---|
| 1 | §6 — does platform-app frontmatter carry a CFN type field? | **No, and we don't need it.** The genprimitives generator already hand-curates Terraform + Pulumi aliases; CFN aliases extend the same pattern. ~half a day inside cbx-cli, no platform-app coordination. |
| 2 | Boolean `--aws` flag vs subcommand? | **Subcommand.** `cbx audit aws [profile]`, with `--config <path>` and `--regions <list>` as flags on the subcommand. Reads naturally because AWS profile is a *named selector*, not a *path value*. Existing input flags (`--pulumi-state` etc.) stay unchanged. See §7.1. |
| 3 | Region default when profile has none? | **Prompt interactively.** Show enabled regions + "all" option. In non-interactive mode (`--json`, `--quiet`, `--yes`, or no TTY), error with a clear "pass --regions" message. See §7.5. |
| 4 | Prowler invoked by default for AWS mode? | **No — prowler deferred out of v1 entirely.** v1 has no external CLI dependencies; findings come from native CB rules + orphan detection + Phase F grounded analyzer. Prowler stays available in the codebase for a follow-up phase. See §7.10. |
| 5 | Ship `--diagnose` in v1? | **Yes, in v1.** IAM-policy debugging is the #1 first-run friction; the actionable per-call error + policy-patch JSON output is worth the half-day. See §7.13. |
| 6 | Surface API cost line in report? | **No.** Discovery uses only free AWS API calls; the line would read "$0.00" forever. Saved as a footnote in §7.7. |

No open questions remain blocking. v1 is ready to ticket.

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
- The new code is concentrated in three places (discovery, grouping, the `aws` subcommand wiring), each independently testable.
- The pkg/internal layering rule is preserved — new code goes in `internal/`, exposed only through `pkg/audit` type aliases as needed.
- `cb-cli` gets the feature for free the moment it picks up the new `pkg/cmd.Execute` signature; no proprietary fork required.

No open questions block v1 (§11). The original §6 risk evaporated once we verified the genprimitives generator already hand-curates aliases — extending it for CFN names is regular work, not a coordination headache.
