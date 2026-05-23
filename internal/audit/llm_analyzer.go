package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/core/plan"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit/parsers"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"
)

// llmStreamer is the minimal subset of core/plan.LLMCaller that the analyzer
// needs. The interface exists so unit tests can swap in a deterministic
// stub without spinning up a real provider — see llm_analyzer_test.go.
type llmStreamer interface {
	Stream(ctx context.Context, prompt string, onToken func(string)) error
}

// llmAnalyzer is a FindingProvider that ships the source tree to a
// configured LLM provider and parses the structured response back into
// audit findings. It is selected by --llm <provider>; never auto-enabled.
type llmAnalyzer struct {
	provider           string
	streamer           llmStreamer
	maxFiles           int
	maxBytesPerFile    int
	iacType            string
	providerForRuleID  string // short label used in rule_id (e.g. "claude")

	// cbKnowledge selects the Phase F grounded prompt + post-processing. The
	// streamer is expected to implement groundingTrailer when this is set;
	// the constructor enforces that pairing.
	cbKnowledge bool
	maxCostUSD  float64
}

// newLLMAnalyzer wires a Stream-based analyzer against the user's logged-in
// provider. Returns an error when the provider isn't configured — caller
// should surface that to the user as "run cbx llm login <provider> first".
//
// The special provider name ClaudeCodeProvider ("claude-code") sidesteps
// cbx's own credential handling entirely: it shells out to the `claude`
// CLI which authenticates as Claude Code itself. No `cbx llm login`
// required, no token stored by cbx.
func newLLMAnalyzer(opts Options, iacType string) (*llmAnalyzer, error) {
	if opts.LLMProvider == "" {
		return nil, fmt.Errorf("llm analyzer: empty provider")
	}

	if opts.LLMProvider == ClaudeCodeProvider {
		if opts.CBKnowledge {
			streamer, err := newGroundedClaudeStreamer()
			if err != nil {
				return nil, err
			}
			maxCost := opts.LLMMaxCost
			if maxCost <= 0 {
				maxCost = defaultLLMMaxCostUSD
			}
			return &llmAnalyzer{
				provider:          opts.LLMProvider,
				streamer:          streamer,
				maxFiles:          opts.LLMMaxFiles,
				maxBytesPerFile:   opts.LLMMaxBytesPerFile,
				iacType:           iacType,
				providerForRuleID: "claudecode",
				cbKnowledge:       true,
				maxCostUSD:        maxCost,
			}, nil
		}
		streamer, err := newClaudeCLIStreamer()
		if err != nil {
			return nil, err
		}
		return &llmAnalyzer{
			provider:          opts.LLMProvider,
			streamer:          streamer,
			maxFiles:          opts.LLMMaxFiles,
			maxBytesPerFile:   opts.LLMMaxBytesPerFile,
			iacType:           iacType,
			providerForRuleID: "claudecode",
		}, nil
	}

	if opts.CBKnowledge {
		return nil, fmt.Errorf("--cb-knowledge requires --llm %s (other providers don't have an MCP tool-call loop)", ClaudeCodeProvider)
	}

	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("llm analyzer: loading config: %w", err)
	}
	provCfg, ok := cfg.LLM.Providers[opts.LLMProvider]
	if !ok {
		return nil, fmt.Errorf("llm provider %q is not configured; run 'cbx llm login %s' first", opts.LLMProvider, opts.LLMProvider)
	}

	return &llmAnalyzer{
		provider:          opts.LLMProvider,
		streamer:          plan.NewLLMCaller(provCfg),
		maxFiles:          opts.LLMMaxFiles,
		maxBytesPerFile:   opts.LLMMaxBytesPerFile,
		iacType:           iacType,
		providerForRuleID: opts.LLMProvider,
	}, nil
}

func (l *llmAnalyzer) Name() string { return "llm" }

func (l *llmAnalyzer) Scan(_ context.Context, _ []Resource) ([]Finding, error) {
	// State mode is handled by the rule-based engines; the LLM analyzer is
	// source-only. Returning the sentinel keeps the interface consistent
	// with prowlerAdapter's posture.
	return nil, ErrSourceModeUnsupported
}

func (l *llmAnalyzer) SupportsSource() bool { return true }

func (l *llmAnalyzer) ScanSource(ctx context.Context, dir string) ([]Finding, error) {
	files, err := collectSourceFiles(dir, l.iacType, l.maxFiles, l.maxBytesPerFile)
	if err != nil {
		return []Finding{l.errorFinding(fmt.Sprintf("gathering source files: %v", err))}, nil
	}
	if len(files) == 0 {
		return nil, nil
	}

	var (
		resources []DiscoveredResource
		workloads []string
	)
	if l.cbKnowledge && l.iacType == IaCTypeTerraform {
		// Pre-resolve resources so the model can feed CB primitive ids
		// straight into the MCP tools. Best-effort: a parse error here
		// degrades to the non-pre-resolved prompt rather than failing the
		// whole audit.
		if parsed, perr := parsers.ParseTerraformSource(dir); perr == nil {
			resources = parsed
			workloads = ClassifyWorkloads(resources)
		}
	}

	prompt := l.buildPrompt(files, resources, workloads)

	var sb strings.Builder
	streamErr := l.streamer.Stream(ctx, prompt, func(tok string) {
		sb.WriteString(tok)
	})
	if streamErr != nil {
		return []Finding{l.errorFinding(fmt.Sprintf("llm stream: %v", streamErr))}, nil
	}

	findings, parseErr := parseLLMFindings(sb.String(), l.providerForRuleID)
	if parseErr != nil {
		return []Finding{l.errorFinding(fmt.Sprintf("parsing llm output: %v", parseErr))}, nil
	}

	if l.cbKnowledge {
		findings = l.postProcessGrounded(findings)
	}
	return findings, nil
}

// postProcessGrounded threads the grounding trail (if the streamer surfaces
// one) into each Finding.CBSource, soft-warns ungrounded findings, and emits
// a cost-cap warning when the run exceeded --llm-max-cost. Returns the
// possibly-augmented finding slice. Never drops findings — soft-warn only,
// per the §6 open-question recommendation for v1.
func (l *llmAnalyzer) postProcessGrounded(findings []Finding) []Finding {
	trailer, ok := l.streamer.(groundingTrailer)
	if !ok {
		// Defensive: the constructor wires a groundingTrailer-capable
		// streamer for cbKnowledge=true, so this branch only ever runs
		// in unit tests that inject a plain fakeStreamer.
		return findings
	}
	trail := trailer.GroundingTrail()

	// Backfill missing snippets when the model emitted only tool+key but
	// the trail captured a structuredContent payload that matches. Keeps
	// the renderer's "click-through to source" story plausible without
	// requiring the model to verbatim-quote the snippet.
	for i := range findings {
		if findings[i].CBSource != nil && findings[i].CBSource.Snippet == "" {
			if snip := snippetForCitation(findings[i].CBSource, trail); snip != "" {
				findings[i].CBSource.Snippet = snip
			}
		}
	}

	// Count ungrounded findings and stash an info-level summary so the
	// renderer can call it out. Stderr write matches the existing
	// LLM-ERROR posture (visible without --json).
	ungrounded := 0
	for _, f := range findings {
		if f.CBSource == nil || f.CBSource.Tool == "" {
			ungrounded++
		}
	}
	if ungrounded > 0 {
		fmt.Fprintf(os.Stderr,
			"WARN: %d/%d findings have no cb_source citation (grounded mode is best-effort; CB content gaps surface here).\n",
			ungrounded, len(findings),
		)
		findings = append(findings, Finding{
			RuleID:      "LLM-CB-UNGROUNDED",
			Title:       fmt.Sprintf("%d ungrounded LLM findings", ungrounded),
			Description: "Some findings in this report were not anchored to a CB-knowledge MCP tool call. Treat them with the same caution as a non-grounded `--llm claude-code` run.",
			Severity:    SeverityInfo,
			Resource:    l.providerForRuleID,
			Service:     "LLM",
			Remediation: "Run with --cb-knowledge=false to compare; file an issue against the CB knowledge base if a known-resource type repeatedly produces ungrounded findings.",
		})
	}

	if cost := trailer.TotalCostUSD(); l.maxCostUSD > 0 && cost > l.maxCostUSD {
		fmt.Fprintf(os.Stderr,
			"WARN: grounded audit cost $%.2f exceeded --llm-max-cost $%.2f; partial findings preserved.\n",
			cost, l.maxCostUSD,
		)
		findings = append(findings, Finding{
			RuleID:      "LLM-CB-COST-CAP",
			Title:       fmt.Sprintf("Audit cost $%.2f exceeded cap $%.2f", cost, l.maxCostUSD),
			Description: "The grounded audit's reported total_cost_usd exceeded --llm-max-cost. The run completed and findings are preserved, but rerun with a higher cap or scoped --source if you expect more turns.",
			Severity:    SeverityInfo,
			Resource:    l.providerForRuleID,
			Service:     "LLM",
			Remediation: "Increase --llm-max-cost, or narrow --source to fewer files.",
		})
	}

	return findings
}

// snippetForCitation tries to find a chunk text matching the citation's
// (tool, key) tuple inside the grounding trail. Best-effort: returns "" if
// no obvious match. Lookups stay shallow on purpose — a fuzzy match would
// invent grounding the model didn't actually claim.
func snippetForCitation(src *CBSource, trail []GroundingEvent) string {
	if src == nil {
		return ""
	}
	for _, ev := range trail {
		if ev.Tool != src.Tool {
			continue
		}
		if src.Key != "" {
			matched := false
			for _, v := range ev.Input {
				if s, ok := v.(string); ok && s == src.Key {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		if ev.StructuredResult != nil {
			if chunks, ok := ev.StructuredResult["chunks"].([]interface{}); ok && len(chunks) > 0 {
				if first, ok := chunks[0].(map[string]interface{}); ok {
					if txt, ok := first["chunk_text"].(string); ok {
						return truncate(txt, 240)
					}
				}
			}
		}
		if ev.TextResult != "" {
			return truncate(ev.TextResult, 240)
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// errorFinding wraps a stream/parse failure as an info-level finding so a
// partial run still lands somewhere visible. Mirrors the scanner-error
// posture in runner.go::collectFindings (partial findings + joined error).
func (l *llmAnalyzer) errorFinding(detail string) Finding {
	return Finding{
		RuleID:      "LLM-ERROR",
		Title:       "LLM analyzer failed to produce findings",
		Description: detail,
		Severity:    SeverityInfo,
		Resource:    l.providerForRuleID,
		Service:     "LLM",
		Remediation: "Re-run with --llm omitted to fall back to other analyzers, or check provider credentials with 'cbx llm list'.",
	}
}

// buildPrompt routes to the grounded or ungrounded prompt builder. Method
// (not free function) so it can carry the analyzer's cbKnowledge bit
// without an extra arg at every call site.
func (l *llmAnalyzer) buildPrompt(files []SourceFile, resources []DiscoveredResource, workloads []string) string {
	if l.cbKnowledge {
		return buildGroundedPrompt(l.iacType, files, resources, workloads)
	}
	return buildLLMPrompt(l.iacType, files)
}

// buildLLMPrompt assembles the user-side prompt. System prompt is set
// separately by callers that support it; LLMCaller in core/plan currently
// passes a single user message, so we inline the instructions.
func buildLLMPrompt(iacType string, files []SourceFile) string {
	var sb strings.Builder
	sb.WriteString("You are CloudBooster's IaC audit analyzer. Analyse the provided ")
	if iacType != "" {
		sb.WriteString(iacType)
		sb.WriteString(" ")
	}
	sb.WriteString("IaC source files and return any security, compliance, or operational misconfigurations as JSON.\n\n")
	sb.WriteString("Respond with a single JSON object on the format:\n")
	sb.WriteString(`{"findings":[{"rule_id":"…","title":"…","description":"…","severity":"critical|high|warning|info","resource":"…","service":"…","remediation":"…","file":"path/to/file.tf","line":42}]}`)
	sb.WriteString("\n\nOnly emit JSON. Use the file paths exactly as given below. If you find nothing return {\"findings\":[]}.\n\n")

	for _, f := range files {
		sb.WriteString("==== FILE: ")
		sb.WriteString(f.Path)
		if f.Truncated {
			sb.WriteString(" (truncated)")
		}
		sb.WriteString(" ====\n")
		sb.Write(f.Content)
		sb.WriteString("\n\n")
	}
	return sb.String()
}

// buildGroundedPrompt is the Phase F prompt variant. Differs from the
// vanilla prompt in three load-bearing ways: (1) primes the model on the
// available `aws_*` MCP tools and tells it to call them BEFORE emitting a
// finding; (2) feeds the parsed []DiscoveredResource and detected CB
// workload slugs so the model doesn't waste turns re-parsing; (3) requires
// a `cb_source` field on every finding citing the tool call that grounded it.
func buildGroundedPrompt(iacType string, files []SourceFile, resources []DiscoveredResource, workloads []string) string {
	var sb strings.Builder
	sb.WriteString("You are CloudBooster's IaC audit analyzer, grounded in CB-curated AWS knowledge.\n\n")
	sb.WriteString("You have access to four MCP tools under the `mcp__cbx__*` namespace:\n")
	sb.WriteString("  - aws_lookup_primitive(type_id): CB's posture for a specific resource (e.g. type_id=\"aws:s3/bucket@v1\")\n")
	sb.WriteString("  - aws_best_practices_for(workload): CB's posture for a workload class (e.g. workload=\"static-site\")\n")
	sb.WriteString("  - aws_composition_for(type_ids): CB's recommended companions for a given set of primitive ids\n")
	sb.WriteString("  - aws_narrative_refs(topic): CB's narrative justification for a topic (best-effort; may return empty)\n\n")
	sb.WriteString("MANDATORY tool-use protocol BEFORE emitting any finding:\n")
	sb.WriteString("  1. Call `aws_best_practices_for` at least once for each detected workload listed below.\n")
	sb.WriteString("  2. Call `aws_lookup_primitive` at least once for each distinct CB primitive id in the resource table below.\n")
	sb.WriteString("  3. Only emit findings that CB's authored knowledge supports. Do NOT rely on your pretraining alone.\n\n")
	sb.WriteString("Every finding MUST carry a `cb_source` object citing the tool call that grounded it:\n")
	sb.WriteString(`  "cb_source": {"tool": "aws_lookup_primitive", "key": "aws:s3/bucket@v1", "snippet": "<the CB-authored text you anchored to>"}`)
	sb.WriteString("\n\nReturn a single JSON object:\n")
	sb.WriteString(`{"findings":[{"rule_id":"…","title":"…","description":"…","severity":"critical|high|warning|info","resource":"…","service":"…","remediation":"…","file":"path/to/file.tf","line":42,"cb_source":{"tool":"…","key":"…","snippet":"…"}}]}`)
	sb.WriteString("\n\nOnly emit JSON in your FINAL response. Tool-call turns happen automatically; do not narrate them.\n")
	sb.WriteString("If you find nothing return {\"findings\":[]}.\n\n")

	if len(workloads) > 0 {
		sb.WriteString("Detected CB workload slugs (call aws_best_practices_for on EACH): ")
		sb.WriteString(formatWorkloads(workloads))
		sb.WriteString("\n\n")
	} else {
		sb.WriteString("No CB workload slugs detected; rely on per-resource grounding via aws_lookup_primitive.\n\n")
	}

	if len(resources) > 0 {
		sb.WriteString("Pre-resolved resources (Terraform type → CB primitive id; call aws_lookup_primitive on each distinct primitive id):\n")
		// Deduplicate primitive ids for the model — the loop just below
		// shows raw resource lines; the dedup block makes the call list
		// explicit so the model doesn't fan out to dozens of redundant calls.
		seen := map[string]struct{}{}
		for _, r := range resources {
			pid := primitiveIDFor(r)
			if pid == "" {
				continue
			}
			if _, ok := seen[pid]; ok {
				continue
			}
			seen[pid] = struct{}{}
			sb.WriteString("  - ")
			sb.WriteString(pid)
			sb.WriteString("\n")
		}
		sb.WriteString("\nResource-level detail (type / name / region / inputs):\n")
		for _, r := range resources {
			sb.WriteString("  ")
			sb.WriteString(r.Type)
			if r.URN != "" {
				sb.WriteString(" (")
				sb.WriteString(r.URN)
				sb.WriteString(")")
			}
			pid := primitiveIDFor(r)
			if pid != "" {
				sb.WriteString(" → ")
				sb.WriteString(pid)
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	sb.WriteString("Source files follow. Use the paths exactly as given.\n\n")
	for _, f := range files {
		sb.WriteString("==== FILE: ")
		sb.WriteString(f.Path)
		if f.Truncated {
			sb.WriteString(" (truncated)")
		}
		sb.WriteString(" ====\n")
		sb.Write(f.Content)
		sb.WriteString("\n\n")
	}
	_ = iacType // currently unused in grounded variant; primitives carry the type info
	return sb.String()
}

// primitiveIDFor resolves a DiscoveredResource to the CB primitive id
// the grounded analyzer should query. Returns "" when nothing maps
// (the analyzer won't emit a tool-call hint for that resource; the
// final report will mark it ungrounded, which is the signal the
// platform-app team needs).
//
// Resolution order — first hit wins:
//
//  1. r.Inputs[parsers.CBDescriberPrimitiveResolved] — a describer-set
//     override, currently only the RDS describer for engine-split DBs.
//     Read first so live-AWS-discovered RDS instances point at the
//     right engine-specific primitive (postgres / mysql / mariadb /
//     aurora-postgres / aurora-mysql).
//  2. Terraform-side engine split for aws_db_instance / aws_rds_cluster
//     using the lowercase "engine" input that the TF parser populates.
//     The CFN-side equivalent is already handled by step 1 because the
//     RDS describer wrote the resolved id there.
//  3. Static CFN→primitive map for AWS-discovered resources (CFN-shaped
//     Type values like AWS::S3::Bucket).
//  4. Static Terraform→primitive map for source/state-mode resources.
//
// The grouping pass uses the same logical order via its own helper
// (group.resolvedPrimitiveID + the PrimitiveLookup closure), so a
// resource's primitive name in the report and in the grounded prompt
// always agree.
func primitiveIDFor(r DiscoveredResource) string {
	if pid, ok := r.Inputs[parsers.CBDescriberPrimitiveResolved].(string); ok && pid != "" {
		return pid
	}
	if r.Type == "aws_db_instance" || r.Type == "aws_rds_cluster" {
		if engine, _ := r.Inputs["engine"].(string); engine != "" {
			if pid := rdsPrimitiveFor(engine); pid != "" {
				return pid
			}
		}
	}
	if pid := cfnTypeToCBPrimitive[r.Type]; pid != "" {
		return pid
	}
	return tfTypeToCBPrimitive[r.Type]
}

// jsonBlockRe extracts the first {...} JSON object from a possibly chatty
// response, so providers that wrap output in code fences or commentary still
// parse cleanly. Non-greedy is wrong here — we want the longest balanced
// object — so we use a greedy match starting at the first '{'.
var jsonBlockRe = regexp.MustCompile(`(?s)\{.*\}`)

// llmRawResponse mirrors the structured-output schema in buildLLMPrompt.
type llmRawResponse struct {
	Findings []llmRawFinding `json:"findings"`
}

type llmRawFinding struct {
	RuleID      string       `json:"rule_id"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Severity    string       `json:"severity"`
	Resource    string       `json:"resource"`
	Service     string       `json:"service"`
	Remediation string       `json:"remediation"`
	File        string       `json:"file"`
	Line        int          `json:"line"`
	CBSource    *llmRawCBSrc `json:"cb_source,omitempty"`
}

type llmRawCBSrc struct {
	Tool    string `json:"tool"`
	Key     string `json:"key"`
	Snippet string `json:"snippet"`
}

// parseLLMFindings tolerates code-fenced output / leading prose by extracting
// the first balanced JSON object before unmarshalling. Severity is clamped
// to the four allowed values; anything outside maps to info per §11.3.
func parseLLMFindings(raw, providerLabel string) ([]Finding, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	// Strip a fenced code block: ```json … ``` or ``` … ```.
	if strings.HasPrefix(raw, "```") {
		raw = strings.TrimPrefix(raw, "```json")
		raw = strings.TrimPrefix(raw, "```")
		if idx := strings.LastIndex(raw, "```"); idx >= 0 {
			raw = raw[:idx]
		}
		raw = strings.TrimSpace(raw)
	}

	jsonBlob := raw
	if !strings.HasPrefix(jsonBlob, "{") {
		match := jsonBlockRe.FindString(raw)
		if match == "" {
			return nil, fmt.Errorf("no JSON object found in response")
		}
		jsonBlob = match
	}

	var parsed llmRawResponse
	if err := json.Unmarshal([]byte(jsonBlob), &parsed); err != nil {
		return nil, fmt.Errorf("unmarshalling response: %w", err)
	}

	findings := make([]Finding, 0, len(parsed.Findings))
	for _, r := range parsed.Findings {
		ruleID := r.RuleID
		if ruleID == "" || !strings.HasPrefix(ruleID, "LLM-") {
			ruleID = fmt.Sprintf("LLM-%s-%s", providerLabel, shortHash(r.Title))
		}
		f := Finding{
			RuleID:      ruleID,
			Title:       r.Title,
			Description: r.Description,
			Severity:    clampSeverity(r.Severity),
			Resource:    r.Resource,
			Service:     r.Service,
			Remediation: r.Remediation,
			File:        r.File,
			Line:        r.Line,
		}
		if r.CBSource != nil && r.CBSource.Tool != "" {
			f.CBSource = &CBSource{
				Tool:    r.CBSource.Tool,
				Key:     r.CBSource.Key,
				Snippet: r.CBSource.Snippet,
			}
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func clampSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case SeverityCritical:
		return SeverityCritical
	case SeverityHigh:
		return SeverityHigh
	case SeverityWarning, "medium", "warn":
		return SeverityWarning
	case SeverityInfo, "low", "":
		return SeverityInfo
	default:
		return SeverityInfo
	}
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}
