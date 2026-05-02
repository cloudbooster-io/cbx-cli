# CloudBooster Audit Report

**Findings:** 2

| Severity | Count |
|----------|-------|
| HIGH | 1 |
| WARNING | 1 |

## S3-001 — S3 bucket versioning not enabled

- **Severity:** WARNING
- **Resource:** urn:pulumi:dev::stack::aws:s3/bucket:Bucket::my-bucket
- **Service:** S3
- **Description:** The S3 bucket does not have versioning enabled, which prevents recovery from accidental deletion or overwrites.

**Remediation:** Enable versioning on the S3 bucket.

## S3-002 — S3 bucket encryption not configured

- **Severity:** HIGH
- **Resource:** urn:pulumi:dev::stack::aws:s3/bucket:Bucket::my-bucket
- **Service:** S3
- **Description:** The S3 bucket lacks server-side encryption configuration.

**Remediation:** Enable SSE-S3 or SSE-KMS encryption on the bucket.

