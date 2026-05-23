# CB knowledge survey — Phase F readiness

**2026-05-11.** `api.cloudbooster.io` NXDOMAIN in this sandbox; no key in `~/.cbx/`. Surveyed `platform-app/be/app/knowledge/resources/aws/` + handlers in `be/app/api/v1/knowledge/aws/*.py`; `KnowledgeService` returns `{kb_version, chunks[]}`.

## 1. Primitives — id scheme is wrong in §4.2

CB uses **domain-based** namespaces, not Pulumi's `aws:<service>/...`:

| Survey id | Actual CB type_id |
|---|---|
| `aws:s3/bucket@v1` | `aws:s3/bucket@v1` ✅ |
| `aws:iam/role@v1` | `aws:iam/role@v1` ✅ |
| `aws:ec2/instance@v1` | `aws:compute/ec2@v1` |
| `aws:ec2/securityGroup@v1` | `aws:network/security-group@v1` |
| `aws:lambda/function@v1` | `aws:compute/lambda@v1` |
| `aws:rds/instance@v1` | `aws:db/postgres@v1`, `db/mysql@v1`, … (split per engine) |
| `aws:ecr/repository@v1` | `aws:container/registry@v1` |
| `aws:cloudwatch/logGroup@v1` | `aws:observability/log-group@v1` |
| `aws:eventbridge/rule@v1` | `aws:messaging/event-bus@v1` (no "rule") |
| `aws:iam/user@v1` | **not authored** |

54 primitives total, each deep (quick-ref, config, security, defaults, facets). 2/10 ids resolve as-written; 7 renamed; 1 absent.

## 2. Practices — mostly fallback

Handler slugs `workload`, queries pattern-tagged chunks, falls back to **all patterns** on miss (`api.py:50`). Authored slugs: `api-with-auth, event-pipeline, http-app, multi-tier-web-app, network-baseline, queue-worker, scheduled-job, secure-s3-bucket, static-site, worker`. Of the 7 survey workloads only `static-site` hits exactly; the other 6 get the undifferentiated catalog. Sample from `static_site.md`:

> *SPA with private S3 origin + CloudFront delivery (OAC) + optional custom domain + TLS. S3 bucket is private; content served only via CloudFront OAC. Do NOT enable S3 website hosting. ACM cert for CloudFront custom domain must be in us-east-1 regardless of S3 region.*

## 3. Composition — POST shape

Returns `{kb_version, chunks: [{chunk_text, doc_path, category, tags, type_ids, …}]}`. Merges per-type composition-rule chunks + all `global/composition*` docs; effectively never 404s. Per-type signal depends on each primitive's frontmatter `composition:` block — S3's is empty.

## 4. Narrative — 5/5 miss

Tag-slug match, fallback = substring scan of pattern `doc_path`/`tags`. Topics `iam-roles, vpc-peering, s3-encryption, secrets-management, immutable-images` — none authored as slugs; none appear as substrings in any pattern doc_path. **All 5 → 404.** Related content exists in primitive facets, reachable only via `primitives/`.

## 5. Verdict

Viable on the primitive axis only: ~50 deep, facet-decomposed primitives clear the bar, so `cb_source.tool=aws_lookup_primitive` will carry 80%+ of citations. `aws_best_practices_for` yields real signal **only when classification emits CB-authored slugs** (`static-site`, `http-app`, `queue-worker`), not `containerized-api`/`ml-inference`.

**Single biggest blocker:** the §4.2 primitive-id map. 2/10 ids resolve as written. Phase 7.1 must source the mapping from authored frontmatter (live `aws_lookup_primitive` walk or repo scan), not Pulumi convention — else every non-S3/non-IAM-role resource 404s on the first MCP call and the audit silently degrades to ungrounded. Secondary: drop `narrative?topic=` from the required tool set, or author ~10 topic-tagged narrative docs first.
