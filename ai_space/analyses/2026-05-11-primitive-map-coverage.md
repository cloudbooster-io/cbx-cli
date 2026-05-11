# Primitive-map coverage — 2026-05-11

Generated from `make codegen-primitives` walking `platform-app/be/app/knowledge/resources/aws/primitives/*/primitive.md` frontmatter on branch `feat/audit-primitive-map`.

## Numbers

- **54** authored CB primitives.
- **92** Terraform → CB aliases (`tfTypeToCBPrimitive`).
- **48** Pulumi token → CB aliases (`pulumiTypeToCBPrimitive`).
- **6** RDS/Aurora engine values via `rdsPrimitiveFor` (`postgres`, `postgresql`, `mysql`, `mariadb`, `aurora-postgresql`, `aurora-mysql`).

## Coverage against surveyed fixtures

`TestPrimitiveMap_CoversFixtures` scans `e2e/fixtures/terraform-sample-source/`, `e2e/fixtures/terraform-sample-state.json`, `e2e/fixtures/pulumi-sample-state.json`, and (when present) `../platform-smoke-infra/terraform/`:

| Axis | Mapped | Known-unmapped | Total observed |
|---|---|---|---|
| Terraform | 12 | 3 | 15 |
| Pulumi | 4 | 0 | 4 |

TF coverage rate **80%** on the surveyed fixture set; 100% on the Pulumi side.

## Unmapped Terraform types — platform-app content-gap signal

Appear in CB's own smoke infra but have no authored primitive:

- `aws_iam_user` — already flagged in survey 2026-05-11 §1; IAM users are anti-pattern at CB.
- `aws_iam_access_key` — co-resides with `aws_iam_user`; same gap.
- `aws_budgets_budget` — billing/budget out of scope for current primitive set.

Encoded in `knownUnmappedTF` so the test passes and surfaces these as a maintained list. New unmapped types fail the test.
