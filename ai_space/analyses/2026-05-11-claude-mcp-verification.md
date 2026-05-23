# `claude -p --mcp-config` verification

**2026-05-11 · claude 2.1.138 · validates Phase F §4.3 / §5.1 transport.**

## 1. Flag surface

- `-p, --print` — non-interactive; trust dialog skipped.
- `--mcp-config <configs...>` — files or inline JSON.
- `--strict-mcp-config` — **required**; ignores `~/.claude.json` + project `.mcp.json`.
- `--output-format text|json|stream-json` (`--print` only).
- `--allowedTools <list>` — lock surface, e.g. `mcp__cbx__*`.
- `--bare` — skips hooks/LSP/plugins/auto-memory/CLAUDE.md; best for deterministic subprocess.
- `--permission-mode auto` — headless default.

Pin to claude 2.1.x; re-smoke on bumps (no stability contract on stream-json shape or tool namespacing).

## 2. Minimal smoke

`.mcp.json` exactly as specified, run from a temp cwd. **Wall clock 21.0 s** cold (`uvx` spawn dominates). Init event reports `mcp_servers:[{name:"cbx",status:"connected"}]` and all 8 `mcp__cbx__*` tools. Model listed them and invoked `aws_lookup_primitive({type_id:"aws:s3/bucket@v1"})`. Result returned:

> `{"isError":true,"error":"Backend is unreachable"}`

The CB API was down at test time, but the MCP plumbing — Claude→cbx-mcp→back — round-tripped cleanly. End-to-end transport is verified.

## 3. Stream-json shape

NDJSON; event `type`s: `system` (`subtype: init|hook_*`), `assistant`, `user`, `rate_limit_event`, `result`.

- **Init** — `tools[]`, `mcp_servers[]`, `model`, `session_id`. Assert `cbx` connected here.
- **Tool call** — `assistant.message.content[i].type=="tool_use"` with `name`, `input`, `id`.
- **Tool result** — `user.message.content[i].type=="tool_result"` with `tool_use_id`, `content` (string), plus top-level `tool_use_result.structuredContent` (parsed JSON — prefer this).
- **Final** — `result.{result, duration_ms, num_turns, total_cost_usd, is_error}`.

Quirk: 2.1.138 defers MCP-tool schemas; the model emitted one extra `ToolSearch` turn before the real call. `--bare` likely suppresses it — verify on wiring.

## 4. Verdict

Stable enough. Mandatory flags: **`--strict-mcp-config`** (else `~/.claude.json` leaks in) and **`--bare`** (kills auto-memory, plugins, CLAUDE.md discovery, deferred-tool dance, keychain). No interactive prompts, no stderr noise, exit 0 even on tool error. Budget for: ~$0.17 / 3-turn smoke (scales with audit fan-out), ~10 s cold `uvx` start (pre-spawn or pin a venv), one extra ToolSearch turn unless `--bare` neutralizes it.
