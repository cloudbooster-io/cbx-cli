# CloudBooster Audit Report

**Findings:** 5

| Severity | Count |
|----------|-------|
| HIGH | 2 |
| WARNING | 2 |
| INFO | 1 |

## S3-001 — S3 bucket versioning not enabled

- **Severity:** WARNING
- **Resource:** urn:pulumi:dev::static-site::aws:s3/bucket:Bucket::my-bucket
- **Service:** S3
- **Description:** The S3 bucket does not have versioning enabled, which prevents recovery from accidental deletion or overwrites.

**Remediation:** Enable versioning on the S3 bucket.

## S3-002 — S3 bucket encryption not configured

- **Severity:** HIGH
- **Resource:** urn:pulumi:dev::static-site::aws:s3/bucket:Bucket::my-bucket
- **Service:** S3
- **Description:** The S3 bucket lacks server-side encryption configuration.

**Remediation:** Enable SSE-S3 or SSE-KMS encryption on the bucket.

## EC2-001 — Security group allows unrestricted ingress

- **Severity:** HIGH
- **Resource:** urn:pulumi:dev::static-site::aws:ec2/securityGroup:SecurityGroup::web-sg
- **Service:** EC2
- **Description:** A security group rule allows ingress from 0.0.0.0/0 on a sensitive port.

**Remediation:** Restrict security group ingress to specific CIDR blocks.

## IAM-001 — IAM role has overly permissive trust policy

- **Severity:** WARNING
- **Resource:** urn:pulumi:dev::static-site::aws:iam/role:Role::lambda-role
- **Service:** IAM
- **Description:** The IAM role trust policy allows broad principal access.

**Remediation:** Scope the trust policy principal to specific roles or services.

## LAMBDA-001 — Lambda function environment variables may contain secrets

- **Severity:** INFO
- **Resource:** urn:pulumi:dev::static-site::aws:lambda/function:Function::api-handler
- **Service:** Lambda
- **Description:** Environment variables on Lambda functions are visible in plain text.

**Remediation:** Use AWS Secrets Manager or Parameter Store for sensitive values.

