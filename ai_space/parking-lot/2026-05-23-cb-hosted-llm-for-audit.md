# Parking lot — CB-hosted LLM as an `cbx audit --llm` provider

**Status:** parked idea, not designed, not ticketed
**Captured:** 2026-05-23 by Claude Code
**Trigger to resume:** after `cbx audit --aws-account` (plan 4) ships and lands real users, OR earlier if paid-tier monetization needs another lever.

---

## The idea in one sentence

After `cbx login` succeeds, allow `cbx audit --llm cloudbooster` (name TBD) to route inference through a CloudBooster-hosted LLM endpoint — so users don't need to bring their own Claude / OpenAI / Ollama credentials to get a real LLM-powered audit.

## Why this might matter

Today's tiers:

| Tier | LLM access for `cbx audit --llm` |
|---|---|
| Anonymous | Must `cbx llm login claude\|openai\|ollama` — user pays the provider, CB pays nothing |
| Free (CB-logged-in) | Same as anonymous — no LLM benefit from logging in |
| Paid | Same as anonymous — no LLM benefit from logging in |

The gap: logging in to CB unlocks nothing on the audit-LLM axis. That's a missed monetization lever and a friction point ("why do I need a second API key for a CB feature?").

A `--llm cloudbooster` provider would:
- Make `cbx login` materially valuable for audit users.
- Let CB pick the model + tune the prompt centrally (better grounded-audit quality without shipping a new cbx version).
- Be the natural surface for usage-based billing (per-audit, per-token, or per-finding).

## Open design questions (when we pick this up)

1. **Endpoint shape.** New `POST /v1/llm/audit-completions` on `api.cloudbooster.io`? Or a thinner pass-through (`POST /v1/llm/messages`) that mirrors Anthropic's Messages API so the provider adapter is near-trivial in cbx?
2. **Streaming.** `cbx audit --llm claude-code` consumes Claude's stream-json today (Phase F cost reporting depends on it). Does the CB endpoint stream too? Same envelope?
3. **Tool-calling for Phase F grounding.** The grounded audit (`--cb-knowledge`) needs MCP tool calls. If CB hosts the model, do the tool calls happen server-side (CB's model talks to its own KB) or client-side (CB's response includes tool-use blocks that cbx executes locally against cbx-mcp)? Server-side is cleaner but couples cbx tightly to CB's MCP infrastructure.
4. **Quota / rate-limit / cost cap.** Paid tier gets X audits/month? Per-token billing with a hard cap? The existing `--llm-max-cost` flag already exists for client-side cost capping — server-side equivalent needs to surface cost back through the same envelope.
5. **Fallback.** What happens if CB's LLM is down (cf. the 2026-05-11 NXDOMAIN smoke)? Auto-fall-back to user's local provider if logged in, error otherwise?
6. **Naming.** `--llm cloudbooster` is verbose. `--llm cb`? `--llm hosted`? Bikeshed for later.

## Why parking, not building

- **Plan 4 (live AWS audit) is higher priority** — that's the next ship.
- **Phase F backend is NXDOMAIN as of 2026-05-11** ([`../analyses/2026-05-11-phase-f-uptime-cost.md`](../analyses/2026-05-11-phase-f-uptime-cost.md)). Until `api.cloudbooster.io` exists, there's no CB-hosted anything to point an LLM at.
- **Anonymous-tier rate limits on cbx-mcp** haven't been measured under realistic audit load — that survey is a prerequisite to designing any usage-based billing.

## Resume checklist

- [ ] `api.cloudbooster.io` resolves and serves `/v1/*` reliably.
- [ ] Plan 4 has shipped at least to v1.
- [ ] Paid-tier monetization model is decided (per-audit vs per-token vs flat).
- [ ] Phase F has real usage data on tool-call fan-out per audit.

When those four boxes are checked, promote this to `ai_space/analyses/` as a real plan doc.
