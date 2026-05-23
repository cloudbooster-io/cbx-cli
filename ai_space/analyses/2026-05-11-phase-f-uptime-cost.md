# Phase F — backend uptime & cost smoke

**2026-05-11** · anonymous (no `~/.cbx/config.json`) · survey-only. Quantifies §6 R8 (cost), R9 (uptime).

## 1. Uptime probe — 4 URLs × 3 rounds

URLs: P1=`api.cloudbooster.io/v1/knowledge/aws/primitives/aws:s3/bucket@v1`, P2=`…/practices?workload=static-site`, S1/S2 same paths on `api.staging.cloudbooster.io`. All rows below: HTTP `NXDOMAIN`, ~1.3 ms, body=`Could not resolve host`.

| # | Round | URL |
|---|---|---|
| 1 | 1 | P1 | | 2 | 1 | P2 | | 3 | 1 | S1 | | 4 | 1 | S2 |
| 5 | 2 | P1 | | 6 | 2 | P2 | | 7 | 2 | S1 | | 8 | 2 | S2 |
| 9 | 3 | P1 | | 10 | 3 | P2 | | 11 | 3 | S1 | | 12 | 3 | S2 |

**Verdict — down, not flapping.** `dig`: `api.cloudbooster.io` and `api.staging.cloudbooster.io` have no A records. Apex `cloudbooster.io` + `app.cloudbooster.io` resolve (org DNS alive); the `api.*` hosts Phase F depends on aren't provisioned. Matches prior MCP smoke's `Backend is unreachable`. R9 sharpens: Phase F has **no upstream today**; Phase 1 backend survey cannot proceed.

## 2. Cost smoke

`bin/cbx audit … --llm claude-code --output json` → 46.8s wall, 18 findings, exit 3. cbx surfaces no usage/cost (no `--include-usage`). Falling back to the 2026-05-11 stream-json `result` event: model `claude-opus-4-7[1m]`, `num_turns=3`, input 12 + cache_create 19934 + cache_read 67135 = **87,081 in / 502 out**, `total_cost_usd=$0.171`.

Sonnet flat ($3/M in, $15/M out): `87081 × 3/1e6 + 502 × 15/1e6 ≈ $0.27 / 3-turn`. Phase F ≈ 20 resources × 3 tool calls ≈ 60 turns ≈ 20× → **~$5/audit Sonnet flat, ~$3.40 Opus** (today's price). Cache-read discount realistically pulls Sonnet to **$1–2/audit**.

## 3. `--llm-max-cost` recommendation

Ship before Phase F's first user run. Risk isn't the happy path — it's a runaway tool loop (5xx retries, per-resource composition fan-out). Default cap **$2.00**, flag-overridable, abort cleanly with partial findings. Print one-line cost estimate on `--cb-knowledge` first invocation. Pair with tool-response caching in the audit temp dir (R9 mitigation).
