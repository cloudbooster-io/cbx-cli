# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
  (e.g. `cb-cli`) can derive the same `<basename>_audit_report.md` name
  used by the CLI.
- `internal/audit.ErrSourceModeUnsupported` sentinel for adapters with no
  source-mode implementation (currently only `prowler`, which scans live
  AWS by design).

### Changed

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

### Fixed

### Security
