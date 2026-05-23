# Implementation plan — Phase F: CB-knowledge-grounded `cbx audit --llm`

**Status:** proposed; design corrected against 2026-05-11 surveys, not yet ticketed
**Author:** drafted by Claude Code, 2026-05-11 (revised same day after surveys)
**Owner:** TBD
**Linear epic:** TBD (suggested parent: "CB-XXX: cbx audit grounded in CB knowledge")
**Builds on:**
- [`2026-05-10-cbx-audit-source-mode-plan.md`](./2026-05-10-cbx-audit-source-mode-plan.md) — Phases 1–3 (shipped)
- [`2026-05-10-cbx-audit-source-hcl-phase4-design.md`](./2026-05-10-cbx-audit-source-hcl-phase4-design.md) — HCL parser design (T1 shipped as MR-C)
- [`2026-05-10-cbx-audit-deep-analysis-plan.md`](./2026-05-10-cbx-audit-deep-analysis-plan.md) — MR-A/B/C shipped; this doc supersedes its §8 (Phase E hybrid)
**Survey inputs (read first):**
- [`2026-05-11-cb-knowledge-survey.md`](./2026-05-11-cb-knowledge-survey.md) — primitive/practices/composition/narrative coverage in the backend
- [`2026-05-11-claude-mcp-verification.md`](./2026-05-11-claude-mcp-verification.md) — `claude -p --mcp-config` flag surface + stream-json shape

---

## 1. Why this doc exists

`cbx audit --source . --llm claude-code` (shipped 2026-05-10) ships a strong audit experience — 18 findings on `platform-smoke-infra/terraform` vs. 2 from CB's hardcoded rule table — but the findings come **entirely from Anthropic Claude's pretraining**, with zero CloudBooster knowledge informing the substance. The output is indistinguishable from running `claude -p < main.tf` by hand.

That's a product gap, not a bug: the original deep-analysis plan (§8) framed CB-knowledge integration as "Phase E hybrid — defer until users report hallucination." User feedback after seeing the first real output reframed it: the differentiation question is the **primary** value of the audit, not an edge-case fix.

This doc designs the agentic path: give the LLM live access to the CB knowledge base during the audit so each finding is grounded in CB-curated AWS best practices, narratives, and composition rules.

## 2. Goal

Make `cbx audit --source . --llm claude-code` produce findings that:
1. Are anchored to CB-curated knowledge (best-practices documents, narrative refs, composition rules) accessed through cbx-mcp tools during the audit.
2. Cite the CB knowledge source in the finding (rule_id or description), so a reviewer can verify "where did CB say this is bad?"
3. Materially differ from what generic Claude would emit against the same files — both in what it flags AND in what it doesn't (CB's posture on a given resource type wins over Claude's).

Out of scope for Phase F: agentic Phase F for non-Claude-Code providers (`--llm claude` / `--llm codex` / `--llm ollama`). Those are pure HTTP and don't have an MCP-tool-calling loop in cbx today. Confined to `--llm claude-code` for the first ship.

## 3. Non-goals

- **Replacing the hardcoded rule table.** `evaluateResource` stays — it's the offline fallback for `cbx audit --source .` (no `--llm`).
- **Offline guarantee for `--llm claude-code`.** This phase is explicitly online (cbx-mcp → `api.cloudbooster.io/v1/knowledge/aws/*`). The default `cbx audit` path remains fully offline.
- **CB content authoring.** The audit consumes whatever's in `/v1/knowledge/aws/*` today. Filling content gaps is a separate parallel track (see §6 R1).
- **Phase E static-primer variant.** With agentic ship-ready, the static path becomes redundant.

## 4. The substrate we actually have

### 4.1 cbx-mcp tool surface (verified 2026-05-11)

`cbx-mcp/src/cbx_mcp/tools/knowledge.py` exposes four MCP tools, each a thin proxy over the CloudBooster backend:

| Tool | Backend endpoint | Input | Use in audit |
|---|---|---|---|
| `aws_lookup_primitive(type_id)` | `GET /v1/knowledge/aws/primitives/{type_id}` | Pulumi-style primitive id (`aws:s3/bucket@v1`) | Resolve a parsed `aws_s3_bucket` to CB's primitive metadata |
| `aws_best_practices_for(workload)` | `GET /v1/knowledge/aws/practices?workload=…` | Workload tag (`static-site`, `containerized-api`) | Get CB's posture for a workload class — **not keyed on resource type** |
| `aws_composition_for(type_ids)` | `POST /v1/knowledge/aws/composition` | List of primitive ids | "What other resources are usually paired with this one?" — gap-detection |
| `aws_narrative_refs(topic)` | `GET /v1/knowledge/aws/narrative?topic=…` | Topic string (`vpc-peering`, `iam-roles`) | Narrative justification for a finding |

The actual content lives in the **CB backend** (`api.cloudbooster.io`), not in cbx-mcp. cbx-mcp is a 200-line FastAPI/MCP wrapper. So when this plan assumes "mostly populated," the bet is on the backend's content, not the MCP layer.

**Anonymous tier is rate-limited** with a clear sign-up CTA (`tools/knowledge.py:11-15`). An audit that fans out 20 resources × 4 tools = 80 calls will burn through the anonymous limit fast. CB-API-key tier likely lifts that, but Phase F's anonymous-friendliness needs measuring before shipping.

### 4.2 Resource-type ↔ primitive-id mapping — **CORRECTED 2026-05-11**

The HCL parser (MR-C) emits Terraform-style types: `aws_s3_bucket`, `aws_iam_role`, `aws_lambda_function`. The MCP tools speak CB-style primitive ids — **NOT Pulumi-style** as the original draft assumed.

The survey (`2026-05-11-cb-knowledge-survey.md` §1) found CB uses **domain-based namespaces** keyed on workload domain, not AWS service:

| Terraform type | CB primitive id |
|---|---|
| `aws_s3_bucket` | `aws:s3/bucket@v1` ✅ matches Pulumi |
| `aws_iam_role` | `aws:iam/role@v1` ✅ matches Pulumi |
| `aws_instance` | `aws:compute/ec2@v1` |
| `aws_security_group` | `aws:network/security-group@v1` |
| `aws_lambda_function` | `aws:compute/lambda@v1` |
| `aws_db_instance` (postgres) | `aws:db/postgres@v1` *(split per engine)* |
| `aws_db_instance` (mysql) | `aws:db/mysql@v1` |
| `aws_ecr_repository` | `aws:container/registry@v1` |
| `aws_cloudwatch_log_group` | `aws:observability/log-group@v1` |
| `aws_cloudwatch_event_rule` | `aws:messaging/event-bus@v1` *(approximate; no "rule" primitive)* |
| `aws_iam_user` | **not authored** — soft-warn ungrounded |

Of the 10 ids the survey probed, **2 matched Pulumi convention, 7 are renamed, 1 is absent.** The mapping must be **sourced from authored frontmatter**, not from the Pulumi `aws:<service>/...` convention.

Total primitive count in the repo: **~54**, each deep (quick-ref / config / security / defaults / facets). That's enough surface for the `aws_lookup_primitive` axis to carry ~80% of finding citations once the map is correct (survey §5).

Concrete acquisition path for the map: walk `platform-app/be/app/knowledge/resources/aws/primitives/*/` frontmatter at build time, generate a Go map keyed on the `aws:<domain>/<name>@v1` ids the backend exposes plus their Terraform/Pulumi aliases. Cross-repo dep on platform-app — but only at generation time; the generated table ships in the cbx-cli binary.

Engine-split primitives (`aws_db_instance` → postgres/mysql/aurora) need either a heuristic (read `engine` attr from the `Inputs` map MR-C populates) or a multi-id fan-out (query both). Heuristic is cleaner; falls back to fan-out when `engine` is `var.x`-shaped.

### 4.3 Claude Code's MCP consumption — **VERIFIED 2026-05-11 (claude 2.1.138)**

`claude -p --mcp-config` works end-to-end against cbx-mcp; the verification report (`2026-05-11-claude-mcp-verification.md`) confirmed the model saw all 8 `mcp__cbx__*` tools and called `aws_lookup_primitive` correctly. Backend was down at smoke time so the call returned `{"isError":true,"error":"Backend is unreachable"}`, but the MCP transport itself round-tripped cleanly.

**Mandatory flags for the Go wrapper:**
- `--mcp-config <path>` — files OR inline JSON, configures the server set.
- `--strict-mcp-config` — **required**, else `~/.claude.json` and any project-level `.mcp.json` leak into the tool surface and break determinism.
- ~~`--bare`~~ — **dropped 2026-05-11.** Originally listed as required, but it strips Claude Code's keychain, breaking authentication to Anthropic. The MCP server still connected (init event showed `cbx connected`) but the LLM call itself failed `authentication_failed`. `--strict-mcp-config` alone covers the actual determinism concern (MCP-config leakage). Auto-memory / plugins / CLAUDE.md discovery still happen but don't change finding correctness.
- `--allowedTools mcp__cbx__*` — lock the surface to just our MCP server.
- `--permission-mode auto` — headless default; no trust dialogs.
- `--output-format stream-json` — NDJSON, structured tool-call + tool-result events. Strongly preferred over `text` for the wrapper parser.
- `--verbose` — **required** when combining `-p` with `--output-format stream-json`; claude 2.1.138 rejects the flag combination without it.

**Pin to `claude 2.1.x`** — no stability contract on stream-json shape or tool namespacing across major versions. Smoke on every minor bump.

**Cost & timing reality:**
- ~**$0.17 per 3-turn smoke** at current model pricing. An audit with ~20 resources × ~3 tool calls each = 60+ turns. Per-audit cost is non-trivial; needs surfacing in `--cb-knowledge` UX and possibly a `--llm-max-cost` cap.
- ~**10s cold-start** dominated by `uvx` spawning the Python MCP server. Mitigations: (a) pin a pre-built `.venv` and invoke directly, (b) keep cbx-mcp running as a daemon and reuse the connection, (c) accept the 10s and document.

**Quirk to handle:** 2.1.138 defers MCP-tool schemas. Without `--bare` the model emits an extra `ToolSearch` turn before the real call. The verification report says `--bare` *likely* suppresses this; confirm at wiring time and add a `ToolSearch`-aware retry path if not.

**Stream-json event shape** (the Go parser will need to know):
- `system` events with `subtype: init|hook_*`. Assert `mcp_servers:[{name:"cbx",status:"connected"}]` in init or fail-fast.
- `assistant` events carry tool calls: `message.content[i].type=="tool_use"` with `name`, `input`, `id`.
- `user` events carry tool results: `message.content[i].type=="tool_result"` with `tool_use_id`, `content` (string), plus top-level `tool_use_result.structuredContent` — **prefer the structured form, the string is just the JSON serialized**.
- `result` events terminate: `{result, duration_ms, num_turns, total_cost_usd, is_error}`.
- `rate_limit_event` — surface to user, don't swallow.

## 5. Design

### 5.1 New subprocess streamer mode

Extend `claudeCLIStreamer` (or fork it as `claudeCLIGroundedStreamer`) to:
1. Detect a Phase-F-enabled run (new `--cb-knowledge` flag; only valid when `--llm claude-code`).
2. Resolve the cbx-mcp install location — env var `CBX_MCP_PATH` for power users, `uvx --from gitlab.com/cloudbooster.io/platform/cbx-mcp cbx-mcp` as the zero-config default, fall back to "Phase F requires cbx-mcp" error otherwise.
3. Materialise a temp `.mcp.json` and a temp prompt file in a TempDir.
4. Invoke (per §4.3, all flags mandatory):

   ```
   claude -p \
     --mcp-config <tmp>/.mcp.json \
     --strict-mcp-config \
     --bare \
     --allowedTools 'mcp__cbx__*' \
     --permission-mode auto \
     --output-format stream-json \
     < prompt.txt
   ```

5. Parse NDJSON from stdout: assert init reports `cbx` connected; collect `assistant.tool_use` → `user.tool_result.tool_use_result.structuredContent` pairs as the grounding trail; reduce final `result.result` into the existing `parseLLMFindings` path. Persist the grounding trail so each `Finding.cb_source` can cite back to a specific tool call + structured content snippet.

The shift from `--output-format text` (current `claudeCLIStreamer`) to `--output-format stream-json` is the load-bearing change. Without structured events, the grounding citations can't be recovered post-hoc.

### 5.2 Prompt changes

Two tightenings to the prompt builder (`internal/audit/llm_analyzer.go::buildLLMPrompt`):

1. **Tool-use instruction.** Tell the model it has access to four `aws_*` tools and **must** call at least `aws_best_practices_for` (workload-keyed) and `aws_lookup_primitive` (per resource type) before emitting any finding. Reject findings without a `cb_source` citation.
2. **Resource list pre-resolution.** Pass the parsed `[]DiscoveredResource` from MR-C alongside the raw files. Saves the model a parsing round and gives it primitive ids to feed into the tools directly.

New finding-schema fields (additive, non-breaking on the JSON envelope):

```json
{
  "rule_id": "LLM-claudecode-...",
  "title": "...",
  "cb_source": {
    "tool": "aws_best_practices_for",
    "key": "containerized-api",
    "snippet": "<the CB-authored text the model anchored to>"
  },
  ...
}
```

`cb_source` is optional at the parser level so old envelopes still load. Findings without `cb_source` get a `?` icon in the renderer to make grounding visible.

### 5.3 Workload classification — **CORRECTED 2026-05-11**

`aws_best_practices_for` is keyed on workload, not resource type. The survey (§2) enumerated the **actual CB-authored workload slugs**:

`api-with-auth`, `event-pipeline`, `http-app`, `multi-tier-web-app`, `network-baseline`, `queue-worker`, `scheduled-job`, `secure-s3-bucket`, `static-site`, `worker`.

Original draft's guesses (`containerized-api`, `serverless-api`, `batch-job`, `data-pipeline`, `ml-inference`, `microservices`) — **only `static-site` was right.** The other 6 fall through to the "all patterns" undifferentiated catalog (`api.py:50`), which the model will treat as noise.

Heuristic mapping (the audit needs to learn the CB vocabulary, not invent its own):

| Resource signal | Workload slug |
|---|---|
| `aws_s3_bucket` + `aws_cloudfront_distribution` | `static-site` |
| `aws_s3_bucket` standalone with public/sensitive flags | `secure-s3-bucket` |
| `aws_api_gateway_*` + `aws_lambda_function` + `aws_cognito_*` | `api-with-auth` |
| `aws_lb` / `aws_alb` + `aws_ecs_service` (or EC2 ASG) | `http-app` |
| Above + `aws_rds_*` + cache | `multi-tier-web-app` |
| `aws_sqs_queue` + `aws_lambda_function` (event source) | `queue-worker` or `worker` |
| `aws_eventbridge_rule` (or schedule expression) + `aws_lambda_function` | `scheduled-job` |
| `aws_kinesis_*` or `aws_msk_*` consumers | `event-pipeline` |
| `aws_vpc` + subnets + security groups only | `network-baseline` |

Multi-workload trees query all detected slugs and concatenate the results into the system-prompt primer; deduplicate by chunk doc_path. Document the per-call cost.

Drop `aws_best_practices_for` calls for unmapped workloads rather than passing through to the undifferentiated catalog — survey §2 confirmed the fallback is signal-poor.

### 5.4 CLI surface

```
cbx audit --source . --llm claude-code             # current behaviour (no grounding)
cbx audit --source . --llm claude-code --cb-knowledge  # Phase F (grounded)
```

`--cb-knowledge` is an explicit opt-in for the first release so users can A/B test their findings. If the grounded path proves consistently better, flip it to default-on in a follow-up. Same precedent as `--llm` itself in MR-B.

The flag is `--llm`-only and errors if no `--llm` is set: `--cb-knowledge requires --llm <provider>`.

## 6. Risks and open questions

| # | Risk | Mitigation |
|---|---|---|
| R1 | Backend content gap — `/v1/knowledge/aws/practices` returns thin/empty for half the workloads the audit detects | Survey the backend before coding (§7 Step 1); if gaps are wide, scope Phase F to the populated subset and surface an honest "no CB knowledge for <workload>" message rather than fake the rest |
| R2 | Anonymous tier rate limits trip mid-audit | Cache tool responses in the temp scratch dir per audit; emit the existing _SIGNUP_CTA verbatim to stderr when 429 hits; treat 429 as a partial-findings, not a fatal error |
| R3 | Claude Code's MCP surface changes between minor versions | Pin behaviour to `--mcp-config`; smoke against the locally-installed `claude --version` at runtime and warn on version mismatch |
| R4 | `--cb-knowledge` makes audits 5–10x slower (tool round trips) | Measure on platform-smoke-infra; if >30s, bound parallelism by spawning multiple Claude turns concurrently for non-overlapping resource subsets |
| R5 | Primitive-id mapping table goes stale as backend adds resource types | Source the mapping FROM the backend via `aws_lookup_primitive` at startup, fall back to a baked-in table for offline-mock tests only |
| R6 | cbx-mcp is Python; cbx-cli is Go — distributable single-binary story breaks | Acceptable for now (user-installable via `uvx`); revisit when `cbx mcp serve` lands and audit can spawn an in-process Go MCP server instead |
| R7 | ~10s cold-start per audit from `uvx` spawn (verified 2026-05-11) | Pre-spawn cbx-mcp daemon and reuse the MCP connection; OR pin a `.venv` and skip `uvx`. Worst case: document the 10s budget and accept |
| R8 | Per-audit LLM cost (~$0.17 / 3-turn smoke; audits run 60+ turns) | Surface estimated cost on first invocation; add `--llm-max-cost` cap that aborts after a threshold |
| R9 | Backend availability — `api.cloudbooster.io` was down during the verification smoke | Cache primitive/practices responses in the temp dir for the audit duration; treat repeated 5xx as partial findings + warn; do NOT fail the whole audit |
| R10 | `narrative?topic=…` is signal-poor — survey §4 hit 5/5 404s for plausible topics | Drop `aws_narrative_refs` from the required tool set; surface it as optional for the model to call but don't ground findings on it |
| R11 | `aws_iam_user` and other primitives that aren't authored at all | Soft-warn ungrounded findings on those types; emit a structured signal so the platform-app team can prioritize content gaps |

### Open questions to decide before coding

1. **Mapping table source-of-truth.** Live `aws_lookup_primitive` at startup, or baked-in Go map? Live is more correct, baked-in survives offline. Recommend baked-in + opt-in refresh, with the table itself generated from `aws_lookup_primitive` output committed to repo.
2. **Per-finding citation requirement.** Hard-fail findings without `cb_source` (drop them) or soft-warn (render with `?`)? Hard-fail is the strongest "actually grounded in CB knowledge" guarantee but loses LLM signal on resource types CB hasn't authored content for. Recommend soft-warn for v1 + telemetry on the percentage of findings that came back ungrounded; flip to hard-fail once the rate is below ~10%.
3. **Workload classification on multi-workload trees.** A repo with both `aws_s3_bucket+cloudfront` (static-site) AND `aws_ecs_service` (containerized-api) — does the audit query both workload contexts and merge, or pick a primary? Recommend query-all-detected-workloads, merge tool outputs into the system prompt, document the cost.
4. **Anonymous-tier viability.** Is the experience acceptable on anonymous tier rate limits, or should Phase F refuse to run without a CB API key? Recommend run-but-warn; the `_SIGNUP_CTA` is already authored for this.

## 7. Phasing

| Phase | Scope | Estimate | Ship gate |
|---|---|---|---|
| ~~1. Backend survey~~ | ~~curl every `/v1/knowledge/aws/*`~~ | — | **DONE 2026-05-11** — see `2026-05-11-cb-knowledge-survey.md` and `2026-05-11-claude-mcp-verification.md` |
| 2. Primitive-map generator | Walk `platform-app/be/app/knowledge/resources/aws/primitives/*/` frontmatter; emit a Go map keyed on Terraform/Pulumi types → CB primitive ids; commit generated table | ~1 day | Map covers ≥80% of resource types in `e2e/fixtures/terraform-sample-source` + `platform-smoke-infra/terraform`; engine-split RDS handled |
| 3. cbx-mcp spawning + stream-json parser | Scratch-dir `.mcp.json`; full flag set per §4.3; NDJSON parser that extracts `tool_use` / `tool_use_result.structuredContent` pairs into a grounding trail | ~1.5 days | E2E unit test with a fake `claude` shim emitting deterministic NDJSON; init-event assertion fails fast when `cbx` server doesn't connect |
| 4. Workload classifier | Heuristic from `[]DiscoveredResource` → CB-authored workload slugs (§5.3 table); drop unmapped workloads instead of passing through | ~½ day | Table-driven test exercising each of the 10 authored slugs against representative resource mixes |
| 5. Prompt + parser | Tool-use instructions, `cb_source` field in `Finding`, soft-warn ungrounded findings; grounding-trail metadata threaded into `Finding.cb_source` | ~1 day | Unit tests against both grounded and ungrounded NDJSON fixtures |
| 6. `--cb-knowledge` wiring | CLI flag, mutex with non-`claude-code` providers, help text, cost estimate banner | ~½ day | E2E build-tagged test (`e2e_llm`) asserts findings carry `cb_source.tool` + `cb_source.key` |
| 7. Smoke + ship | Platform-smoke-infra A/B (grounded vs. ungrounded), measure overhead, write CHANGELOG; verify backend up and cache responses for the audit duration | ~1 day | ≥60% of grounded findings cite a CB source; total wall-clock ≤3x ungrounded path (R7 cold-start is the binding constraint, not the LLM) |

Total: **~5.5 days** (revised up from 4.5 after surveys exposed the stream-json parser + map-generator scope). Phase 2 is the new gating step — if the primitive-map generator can't reach 80% coverage of common resource types, scope shrinks to "Phase F supports only the mapped subset, others soft-warn."

## 8. What this does NOT change

- `pkg/auth`, `pkg/config`, `pkg/output`, `pkg/cmd` exported signatures unchanged.
- `core/api/v1/` unchanged — Phase F goes through cbx-mcp, not the OpenAPI client directly.
- `DiscoveredResource` shape unchanged — `cb_source` lives on `Finding`, not on the resource model.
- `cbx audit --source .` (no `--llm`) stays fully offline; MR-A banner unchanged in non-LLM paths.
- `cbx audit --llm claude` / `--llm codex` / `--llm ollama` unchanged in Phase F — grounding is `claude-code`-only for v1.

## 10. Survey outcomes — 2026-05-11 PM/late

Three sessions ran:
- **Session 1 (primitive map):** shipped `feat/audit-primitive-map`. 54 authored primitives, 92 TF aliases, 48 Pulumi aliases. Generator at `tools/genprimitives/main.go`, drift-gated by `make codegen-primitives-check`. **Deviation:** the frontmatter doesn't carry `terraform_types[]` / `pulumi_types[]` — only `type_ids:`. Aliases are hand-curated in `aliasTable` inside the generator and cross-validated against the walked truth set, so alias drift fails the build but adding new aliases requires a code change in cbx-cli, not a content change in platform-app. Content-gap signal: `aws_iam_user`, `aws_iam_access_key`, `aws_budgets_budget` observed in fixtures with no authored CB primitive — surface to platform-app team.
- **Session 2 (uptime/cost):** `api.cloudbooster.io` and `api.staging.cloudbooster.io` are **NXDOMAIN** — no DNS A records on either subdomain (apex `cloudbooster.io` resolves; `app.cloudbooster.io` resolves). Phase F cannot live-smoke against a real backend until DNS+service are provisioned. Cost estimate per audit: ~$5 Sonnet flat, ~$3.40 Opus flat, ~$1–2 with prompt-cache discount. Recommended `--llm-max-cost` default cap: **$2.00**.
- **Session 3 (implementation):** correctly aborted on the gating check because Session 1's branch wasn't merged when it ran. After this merge (`cd24320..c65e8a5`), Session 3 can re-run.

### Decision: **local stub mode for cbx-mcp**

User direction 2026-05-11: don't block Phase F on backend availability; assume the backend will exist later and use a **local stub** to validate the wiring end-to-end now.

Stub mode is implemented in **cbx-mcp** (the Python sibling repo), not in cbx-cli. Activated by `CBX_MCP_KB_STUB=1` env var. When active, each `aws_*` knowledge tool returns synthetic data baked from `platform-app/be/app/knowledge/resources/aws/` frontmatter + a small set of hand-curated practice/composition/narrative fixtures, instead of calling `api.cloudbooster.io`. Same `{kb_version, chunks[]}` envelope; downstream Go parser sees identical shape.

Phase F implementation in cbx-cli proceeds without further dependency on the live API. When DNS+service land, unset `CBX_MCP_KB_STUB` and the same code path swaps to real-backend.

## 11. Decision log

- **2026-05-11 AM:** plan drafted in response to user reaction that MR-B's `--llm claude-code` output is "just generic Claude," not CB-grounded. Confirmed MCP-subprocess transport (option A) and "mostly populated" content posture as starting assumptions — both contingent on Phase 7.1 backend survey. Supersedes the deep-analysis plan's §8 (Phase E hybrid).
- **2026-05-11 PM:** revised after `2026-05-11-cb-knowledge-survey.md` and `2026-05-11-claude-mcp-verification.md`. Three load-bearing corrections:
  1. **§4.2 primitive id map was wrong** — CB uses domain-based namespaces (`compute/lambda`, `network/security-group`, `db/postgres`) not Pulumi's `aws:<service>/...`. Phase 2 (was 1) must generate the map from authored frontmatter.
  2. **§5.3 workload list was wrong** — only `static-site` of the original 7 guesses is real; new heuristic table built against the 10 CB-authored slugs.
  3. **§5.1 subprocess flags were incomplete** — `--strict-mcp-config`, `--bare`, `--allowedTools`, `--permission-mode auto`, `--output-format stream-json` all mandatory. Stream-json shift drives a real parser (not just stdout accumulation).
- Estimate revised 4.5d → 5.5d. R7 (10s cold start), R8 (per-audit cost), R9 (backend uptime), R10 (narrative tool is signal-poor), R11 (unauthored primitives) added.
- **2026-05-11 late:** Session 1 merged to vibecode at `c65e8a5`. Session 2 escalated R9 from "uptime" to "NXDOMAIN — subdomain not provisioned." User decision: do **not** block Phase F on backend DNS; build against a local stub instead. New scope item: `CBX_MCP_KB_STUB=1` mode in cbx-mcp returning baked-in frontmatter content. Session 3 unblocked; will smoke against stub.
