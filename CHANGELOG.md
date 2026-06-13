# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `cbx audit aws [profile]` audits a live AWS account read directly via
  the SDK — single-account, ad-hoc, user-initiated. Resolves credentials
  through the standard precedence (`--credentials-file` > positional profile >
  `AWS_PROFILE` > `default`); resolves regions explicitly via
  `--region us-east-1 --region …` (repeatable) / `--region all` or
  interactively when the profile has none; runs an STS preflight;
  discovers resources via
  CloudFormation CloudControl (`cloudformation:ListResources` /
  `GetResource`) across a curated set of CFN types covering the common
  workload primitives; emits findings against the same `Finding` shape
  every other audit mode uses. `--diagnose` surfaces per-call IAM
  permission errors and a recommended policy patch. No external CLI
  dependencies; the default scanner list is the same native CB rules
  source mode uses.
- Per-service describers enrich CloudControl-discovered resources with
  fields CC doesn't expose: `AWS::S3::Bucket` (PublicAccessBlock,
  Versioning, Encryption, BucketPolicy presence, ListObjectsV2 probe,
  ListBuckets-derived CreationDate); `AWS::IAM::Role` (LastUsedDate,
  decoded AssumeRolePolicyDocument, attached managed policy ARNs);
  `AWS::RDS::DBInstance` + `AWS::RDS::DBCluster` (engine-resolved CB
  primitive id via `RDSPrimitiveFor` + normalized security-posture
  booleans); `AWS::Lambda::Function` (runtime / role / vpc-attached
  normalization + a key-shape heuristic for cleartext-secret env vars);
  `AWS::EC2::Instance` (IMDSv2-required, instance-profile ARN, state,
  public-IP presence).
- `internal/audit.orphanProvider` is a new `FindingProvider` (registered
  in `MockScanners()` and `AllScanners()`) with five info-severity
  detectors over CloudControl-discovered resources: unattached EBS
  volumes (with `gp3` $/GB-mo cost estimate), unassociated Elastic IPs
  ($3.65/mo flat), IAM roles unused for 90+ days, empty S3 buckets older
  than 30 days, security groups with no other-resource references.
  Filters to `AWS::`-typed resources at Scan time, so state- and
  source-mode audits silently no-op.
- Component grouping pass under `internal/audit/group/` (re-exported
  via `pkg/audit.Component`) projects discovered resources through a
  tag-based lens (priority `Application` > `Service` > `Component` >
  `Project`, configurable) and a CB-primitive lens. The grouped
  components land on `Result.Components` and render in the audit's
  Markdown report under `## Components` with each finding placed under
  its primary component; resources matching no lens fall into
  `## Account-wide Findings`.
- `cbx audit aws` always runs the Phase F grounded analyzer: it fetches
  CloudBooster's curated AWS knowledge directly over the CB knowledge API,
  inlines it into the prompt (with an AWS-discovery header and per-resource
  `cb_describer_*` describer enrichment), and runs `claude -p` to cite that
  grounding on every finding. It honors the engine-resolved CB primitive id
  (so RDS instances ground against `aws:db/postgres@v1` rather than the
  unmapped CFN type).
- `audit.RunFromResources(opts, resources, *AWSAuditContext)` mirrors
  `audit.Run` for the AWS path: scanner pipeline + component grouping
  + AWS-mode markdown render + populated `Result`. Re-exported via
  `pkg/audit`. `AWSAuditContext` carries the account / identity /
  regions / CloudTrail-event-count estimate the report header reads.
- `pkg/audit` facade: re-exports `Finding`, `Result`, `Component`,
  `Options`, `DiscoveredResource`, severity + IaC constants, lookup
  helpers (`CFNTypeToCBPrimitive`, `TFTypeToCBPrimitive`,
  `PulumiTypeToCBPrimitive`, `RDSPrimitiveFor`), entry points
  (`Run`, `Collect`, `CollectFromResources`, `RunFromResources`), and
  the rendering helpers (`RenderMarkdown`, `RenderAWSMarkdown`,
  `RenderPlain`, `DefaultReportPath`, `ExitWithSeverity`). Per
  CLAUDE.md, `pkg/audit` joins `pkg/auth`, `pkg/config`, `pkg/output`
  as semver-public surface for downstream library consumers.
- `tools/genprimitives` extended to emit a CFN-type-keyed companion
  to the existing Terraform / Pulumi → CB-primitive maps (82 CFN
  aliases). `audit.CFNTypeToCBPrimitive(cfnType)` is the public lookup.
- `ClassifyWorkloads` accepts both Terraform and CFN-shaped resource
  types via an internal `cfnTypeToTFEquivalent` translation map, so
  the grounded analyzer's workload primer (`aws_best_practices_for`)
  fires the same way on live-AWS audits as it does on source audits.
- `docs/cbx-audit-aws-iam.json` — minimum IAM policy a least-privilege
  caller of `cbx audit aws` needs. `AWSReadOnlyAccess` is an acceptable
  superset.
- `cbx audit --source <dir>` audits an IaC source tree without a state file
  or cloud credentials. Stays fully offline by default (mock scanner) and
  opts into real `tfsec` / `checkov` / `trivy` binaries via `--scanners=`.
- `cbx audit --iac-type <auto|terraform|cloudformation|k8s|helm>` pins the
  IaC flavor for source-mode dispatch. `auto` (default) detects the flavor
  by walking the tree (`*.tf` → terraform, `AWSTemplateFormatVersion` /
  `Resources:` + `AWS::*` types → cloudformation, `apiVersion:` + `kind:`
  YAML → kubernetes, `Chart.yaml` present → helm). First-match-wins for
  ambiguous trees; explicit `--iac-type=...` is always honored.
- `tfsec` is filtered out automatically for non-Terraform sources;
  `checkov` and `trivy` self-detect their input and run on every flavor.
- `pkg/audit.DefaultReportPath` exported so non-CLI consumers
  can derive the same `<basename>_audit_report.md` name
  used by the CLI.
- `internal/audit.ErrSourceModeUnsupported` sentinel for adapters with no
  source-mode implementation (currently only `prowler`, which scans live
  AWS by design).

### Changed

- **BREAKING:** the Go module path changed from
  `gitlab.com/cloudbooster.io/platform/cbx-cli` to
  `github.com/cloudbooster-io/cbx-cli` for the public GitHub release.
  Downstream library consumers must update their import paths (or add a
  `replace` directive) in lockstep.
- `cbx audit` now requires exactly one of `--pulumi-state`,
  `--terraform-state`, or `--source`. The error message previously read
  "`--pulumi-state` or `--terraform-state` is required"; it now lists all
  three options. CI/scripts asserting on the old wording must be updated.
- `internal/audit.FindingProvider` widened with `ScanSource(ctx, dir)` and
  `SupportsSource()`. The interface lives in `internal/`, so this is not
  a public API break, but downstream forks that implement it will need to
  add the two methods.
- `.gitlab-ci.yml`: collapsed the `e2e-matrix` job (which required `linux`
  and `darwin` runner tags) into a single untagged `e2e` job that runs on
  the standard group runner. Restore the matrix when a darwin runner is
  registered.

### Deprecated

### Removed

- The IaC state/source flag surface on `cbx audit` (`--pulumi-state`,
  `--terraform-state`, `--source`, `--iac-type`, `--scanners`, `--llm`) is no
  longer exposed at the CLI; `cbx audit` now dispatches only to
  `cbx audit aws`. The underlying parsers, scanners, and analyzers remain
  available to library consumers via the `pkg/audit` facade.

### Fixed

- `cbx audit aws --json` now exits with the severity-mapped code (and the
  partial-failure code) instead of always exiting 0, matching the human
  output path.

### Security
