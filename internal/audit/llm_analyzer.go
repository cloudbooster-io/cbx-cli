package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/core/plan"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/audit/knowledge"
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

	// posture is the pre-fetched account-level configuration block
	// passed in via Options.AWSAccountPosture. The prompt builder
	// inlines it as an ==== ACCOUNT POSTURE ==== section so the LLM
	// can flag account-wide gaps (default EBS encryption off, no MFA
	// on root, etc.). Nil for non-AWS audits.
	posture *AccountPosture
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
			// LLMMaxCost semantics: 0 means "no cap" (no warning ever
			// emitted). The CLI default is 2.00 (set in audit_aws.go).
			// Library callers wiring Options directly take the field as
			// the literal cap; if they want the historical "use the
			// default" behavior they can pass defaultLLMMaxCostUSD
			// explicitly.
			return &llmAnalyzer{
				provider:          opts.LLMProvider,
				streamer:          streamer,
				maxFiles:          opts.LLMMaxFiles,
				maxBytesPerFile:   opts.LLMMaxBytesPerFile,
				iacType:           iacType,
				providerForRuleID: "claudecode",
				cbKnowledge:       true,
				maxCostUSD:        opts.LLMMaxCost,
				posture:           opts.AWSAccountPosture,
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

// ScanResources is the live-AWS entry point. It mirrors ScanSource but
// takes a pre-discovered []DiscoveredResource instead of a source
// directory — there are no IaC files to walk in AWS mode. The prompt
// builder treats files=nil as the AWS-mode signal and switches its
// trailing instructions to "file=\"\", line=0" so the model doesn't
// invent paths. Post-processing (grounding trail backfill, ungrounded
// soft-warn, cost cap finding) is reused verbatim.
//
// Workload classification is best-effort: ClassifyWorkloads is currently
// Terraform-typed and will yield zero slugs on AWS-discovered CFN-shaped
// resources. The prompt builder already handles "no workloads detected"
// by falling back to per-primitive grounding only, so the AWS path
// degrades gracefully until a CFN-aware classifier lands (PR 8.5).
func (l *llmAnalyzer) ScanResources(ctx context.Context, resources []DiscoveredResource) ([]Finding, error) {
	if len(resources) == 0 {
		return nil, nil
	}

	var bundle *GroundingBundle
	if l.cbKnowledge {
		var fetchErr error
		bundle, fetchErr = l.fetchBundle(ctx, resources)
		if fetchErr != nil {
			return []Finding{l.errorFinding(fmt.Sprintf("fetching cb knowledge: %v", fetchErr))}, nil
		}
		l.installBundle(bundle)
	}

	prompt := l.buildPrompt(nil, resources, bundle, l.posture)

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

// fetchBundle runs the Go-side grounding enumerator: looks up every CB
// primitive id, every detected workload, and the bulk composition once.
// Returns nil bundle on no inputs (the prompt renders that explicitly).
// The CB backend's reachability is already verified by the streamer
// constructor's preflight; per-request errors here propagate up.
func (l *llmAnalyzer) fetchBundle(ctx context.Context, resources []DiscoveredResource) (*GroundingBundle, error) {
	workloads := ClassifyWorkloads(resources)
	if uniqueSortedPrimitiveIDs(resources) == nil && len(workloads) == 0 {
		return nil, nil
	}
	kc := knowledge.New(resolvedCBKnowledgeBaseURL())
	bundle, _, err := BuildGrounding(ctx, kc, resources, workloads, 6)
	return bundle, err
}

// installBundle hands the pre-fetched bundle to the streamer (if it
// supports the grounded interface) so GroundingTrail() returns events
// reflecting actual fetches, not the LLM's tool calls.
func (l *llmAnalyzer) installBundle(bundle *GroundingBundle) {
	if bundle == nil {
		return
	}
	if installer, ok := l.streamer.(bundleInstaller); ok {
		installer.InstallBundle(bundle)
	}
}

// bundleInstaller is the optional capability the grounded streamer
// exposes so the analyzer can pre-populate its grounding trail before
// streaming the LLM response.
type bundleInstaller interface {
	InstallBundle(*GroundingBundle)
}

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
		bundle    *GroundingBundle
	)
	if l.cbKnowledge && l.iacType == IaCTypeTerraform {
		// Pre-resolve resources so the bundle fetcher can look up the
		// right CB primitives. Best-effort: a parse error here degrades
		// to an empty bundle rather than failing the whole audit.
		if parsed, perr := parsers.ParseTerraformSource(dir); perr == nil {
			resources = parsed
			b, ferr := l.fetchBundle(ctx, resources)
			if ferr != nil {
				return []Finding{l.errorFinding(fmt.Sprintf("fetching cb knowledge: %v", ferr))}, nil
			}
			bundle = b
			l.installBundle(bundle)
		}
	}

	prompt := l.buildPrompt(files, resources, bundle, l.posture)

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
// without an extra arg at every call site. In grounded mode bundle is
// the pre-fetched CB knowledge and posture is the account-level
// configuration block (both may be nil — the prompt builder handles
// that explicitly).
func (l *llmAnalyzer) buildPrompt(files []SourceFile, resources []DiscoveredResource, bundle *GroundingBundle, posture *AccountPosture) string {
	if l.cbKnowledge {
		return buildGroundedPrompt(l.iacType, files, resources, bundle, posture)
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

// buildGroundedPrompt assembles the deterministic grounded prompt. The
// LLM does NOT call MCP tools — every CB-knowledge lookup has already
// run on the Go side (see BuildGrounding), and the result is inlined
// here as plain text. The model's job is purely to reason over the
// frozen knowledge bundle and emit findings.
//
// Determinism is load-bearing: this function must produce byte-identical
// output for identical inputs across runs. That means:
//   - bundle slices are pre-sorted by BuildGrounding,
//   - resources are sorted by URN/Type before iteration here,
//   - describer-enrichment keys are sorted by formatDescriberEnrichment,
//   - no map iteration leaks into the output.
//
// Knowledge gaps (CB has no entry for a primitive / workload) are
// rendered as "(no CB entry)" placeholders, never silently omitted —
// otherwise a backend deploy that adds or removes a primitive would
// shift the prompt invisibly.
func buildGroundedPrompt(iacType string, files []SourceFile, resources []DiscoveredResource, bundle *GroundingBundle, posture *AccountPosture) string {
	var sb strings.Builder
	sb.WriteString("You are CloudBooster's AWS security and architecture auditor.\n\n")
	sb.WriteString("You will be given: (a) a CB knowledge bundle with CloudBooster's curated AWS posture, (b) an account-posture block with account-level configuration, and (c) every discovered resource with its full deployed state (raw CFN Properties + describer enrichment).\n\n")
	sb.WriteString("DO NOT call any tools — none are available in this run.\n\n")
	sb.WriteString("Reasoning rules:\n")
	sb.WriteString("  1. Flag well-known AWS misconfigurations from the resource state DIRECTLY, even when the CB knowledge bundle doesn't explicitly enumerate the pattern. Baseline examples (non-exhaustive):\n")
	sb.WriteString("       • Security groups with 0.0.0.0/0 ingress on admin/database ports (22, 3389, 3306, 5432, 6379, 1433, 27017, 9200).\n")
	sb.WriteString("       • EBS snapshots with `CreateVolumePermission` shared publicly (group=all) — anyone can copy the volume.\n")
	sb.WriteString("       • IAM users with active access keys AND no MFA AND admin-equivalent policy attached.\n")
	sb.WriteString("       • S3 bucket policies allowing `Principal: \"*\"` without a strong condition (or any `aws:PrincipalAccount` restriction).\n")
	sb.WriteString("       • Load balancers with HTTP-only listeners on port 80 and no HTTPS sibling; missing WAF association on internet-facing ALBs.\n")
	sb.WriteString("       • Databases / cache clusters with `PubliclyAccessible: true`.\n")
	sb.WriteString("       • Secrets without rotation (`RotationEnabled: false` or unset).\n")
	sb.WriteString("       • DynamoDB tables without point-in-time recovery, or without CMK encryption when storing sensitive data.\n")
	sb.WriteString("       • Unattached / orphaned resources accruing cost: EBS volumes (`State: available`), EIPs (no `AssociationId`), KMS keys with `cb_describer_is_unused: true` (no other resource references the key — pure cost waste).\n")
	sb.WriteString("       • Account-level gaps from the ACCOUNT POSTURE block: missing CloudTrail in a region, default EBS encryption disabled, no S3 account-level public-access-block.\n")
	sb.WriteString("       • EC2 instances effectively exposed via attached wide-open security groups (cross-reference SG ingress with instance SG list).\n")
	sb.WriteString("     This list is NOT exhaustive — use AWS-baseline judgement.\n")
	sb.WriteString("  2. Use the CB knowledge bundle as authoritative context for CB's RECOMMENDED posture. When a finding aligns with CB-authored guidance, quote the relevant phrase in `cb_source.snippet` and set `cb_source.tool` to the bundle section (`aws_lookup_primitive` / `aws_best_practices_for` / `aws_composition_for`) with `key` set to the primitive id / workload slug / \"composition\".\n")
	sb.WriteString("  3. When a finding has no exact CB-authored anchor (baseline AWS hygiene), set `cb_source` to {tool: \"aws_baseline\", key: \"<short-rule-name>\", snippet: \"<the AWS-baseline rule you applied>\"} so the report still carries a justification.\n")
	sb.WriteString("  4. Use the resource's URN as `resource` for resource-scoped findings, and `account:<accountId>` for account-posture findings.\n")
	sb.WriteString("  5. Don't invent file/line fields — set `file: \"\"` and `line: 0` for live-AWS findings.\n\n")
	sb.WriteString("Return a single JSON object:\n")
	sb.WriteString(`{"findings":[{"rule_id":"…","title":"…","description":"…","severity":"critical|high|warning|info","resource":"…","service":"…","remediation":"…","file":"","line":0,"cb_source":{"tool":"…","key":"…","snippet":"…"}}]}`)
	sb.WriteString("\n\nOnly emit JSON. No commentary, no code fences. If you find nothing return {\"findings\":[]}.\n\n")

	writeAccountPosture(&sb, posture)
	writeGroundingBundle(&sb, bundle)
	writeResourceTable(&sb, resources)

	if len(files) > 0 {
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
	} else {
		// AWS / live-discovery mode: no source files. Tell the model
		// explicitly that it is grounding against deployed state read
		// from AWS APIs (CloudControl + per-service describers) rather
		// than declared IaC, so it doesn't ask for file references that
		// don't exist and so its `file`/`line` fields stay empty.
		sb.WriteString("Audit context: this audit operates against LIVE AWS resources discovered via CloudControl + per-service describers. No source files are available. Emit findings with file=\"\" and line=0; reference resources by the URN shown above.\n\n")
	}
	_ = iacType // currently unused in grounded variant; primitives carry the type info
	return sb.String()
}

// writeGroundingBundle serialises the pre-fetched CB knowledge into the
// prompt. Each section is delimited by a stable header so the model can
// reference blocks by tool+key in its cb_source citations. Knowledge
// gaps surface as "(no CB entry)" lines rather than being skipped, so
// the section structure is invariant to backend KB content drift.
func writeGroundingBundle(sb *strings.Builder, bundle *GroundingBundle) {
	if bundle == nil {
		sb.WriteString("CB knowledge bundle: (empty — no resources mapped to CB primitives)\n\n")
		return
	}

	sb.WriteString("==== CB KNOWLEDGE BUNDLE ====\n")
	if bundle.Composition != nil && bundle.Composition.Data != nil && bundle.Composition.Data.KBVersion > 0 {
		fmt.Fprintf(sb, "(kb_version=%d)\n", bundle.Composition.Data.KBVersion)
	}
	sb.WriteString("\n")

	for _, p := range bundle.Primitives {
		fmt.Fprintf(sb, "---- CB-PRIMITIVE: %s ----\n", p.TypeID)
		if p.Missing || p.Data == nil || len(p.Data.Chunks) == 0 {
			sb.WriteString("(no CB entry)\n\n")
			continue
		}
		writeChunks(sb, p.Data.Chunks)
	}

	for _, w := range bundle.Practices {
		fmt.Fprintf(sb, "---- CB-WORKLOAD: %s ----\n", w.Workload)
		if w.Missing || w.Data == nil || len(w.Data.Chunks) == 0 {
			sb.WriteString("(no CB entry)\n\n")
			continue
		}
		writeChunks(sb, w.Data.Chunks)
	}

	if bundle.Composition != nil {
		fmt.Fprintf(sb, "---- CB-COMPOSITION (type_ids=[%s]) ----\n", strings.Join(bundle.Composition.TypeIDs, ", "))
		if bundle.Composition.Missing || bundle.Composition.Data == nil || len(bundle.Composition.Data.Chunks) == 0 {
			sb.WriteString("(no CB entry)\n\n")
		} else {
			writeChunks(sb, bundle.Composition.Data.Chunks)
		}
	}

	sb.WriteString("==== END CB KNOWLEDGE BUNDLE ====\n\n")
}

// writeChunks renders the chunk array as readable Markdown-ish blocks.
// Chunks arrive sorted by chunk_index from the backend, but we re-sort
// defensively — KB renumbering or a partial response shouldn't reorder
// the prompt.
func writeChunks(sb *strings.Builder, chunks []knowledge.Chunk) {
	ordered := append([]knowledge.Chunk(nil), chunks...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].DocPath != ordered[j].DocPath {
			return ordered[i].DocPath < ordered[j].DocPath
		}
		return ordered[i].ChunkIndex < ordered[j].ChunkIndex
	})
	for _, c := range ordered {
		if c.Heading != "" {
			fmt.Fprintf(sb, "## %s\n", c.Heading)
		}
		if c.DocPath != "" {
			fmt.Fprintf(sb, "_(source: %s)_\n", c.DocPath)
		}
		sb.WriteString(strings.TrimSpace(c.ChunkText))
		sb.WriteString("\n\n")
	}
}

// writeResourceTable lists discovered resources in stable order so two
// audits over the same account produce the same prompt. Resources are
// sorted by (URN, Region, Type). For each resource it emits a header
// line plus the full Inputs map serialised as deterministic JSON
// (sorted keys) — that includes raw CFN Properties from CloudControl,
// per-service describer enrichment (cb_describer_* keys), and tag
// extraction. The LLM gets to see ingress rules, bucket policies,
// rotation configs, PITR settings, etc. directly rather than via a
// curated subset.
func writeResourceTable(sb *strings.Builder, resources []DiscoveredResource) {
	if len(resources) == 0 {
		return
	}
	sorted := append([]DiscoveredResource(nil), resources...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].URN != sorted[j].URN {
			return sorted[i].URN < sorted[j].URN
		}
		if sorted[i].Region != sorted[j].Region {
			return sorted[i].Region < sorted[j].Region
		}
		return sorted[i].Type < sorted[j].Type
	})
	sb.WriteString("==== DISCOVERED RESOURCES ====\n")
	for _, r := range sorted {
		sb.WriteString("---- ")
		sb.WriteString(r.Type)
		if r.URN != "" {
			sb.WriteString(" :: ")
			sb.WriteString(r.URN)
		}
		if r.Region != "" {
			sb.WriteString(" [")
			sb.WriteString(r.Region)
			sb.WriteString("]")
		}
		pid := primitiveIDFor(r)
		if pid != "" {
			sb.WriteString(" → ")
			sb.WriteString(pid)
		}
		sb.WriteString(" ----\n")
		if payload := serialiseInputs(r.Inputs); payload != "" {
			sb.WriteString(payload)
			sb.WriteString("\n")
		}
	}
	sb.WriteString("==== END DISCOVERED RESOURCES ====\n\n")
}

// serialiseInputs renders a resource's Inputs map as deterministic
// indented JSON. Keys are sorted at every level so two runs over the
// same account yield byte-identical prompts. Returns "" for nil/empty
// inputs (the header line alone is enough for resources CloudControl
// returned no properties for).
func serialiseInputs(in map[string]any) string {
	if len(in) == 0 {
		return ""
	}
	// json.Marshal already produces sorted keys for map[string]T at the
	// top level (since Go 1.12); MarshalIndent traverses nested maps the
	// same way. That's the determinism we need.
	raw, err := json.MarshalIndent(deterministicValue(in), "", "  ")
	if err != nil {
		return fmt.Sprintf("(failed to serialise inputs: %v)", err)
	}
	return string(raw)
}

// deterministicValue normalises a value tree so json.Marshal yields a
// stable byte sequence: maps stay map[string]any (Marshal sorts keys),
// slices keep their existing order (CloudControl already returns them
// in a stable order), and scalars pass through. Returns the input
// unchanged when it's not a map/slice — cheap recursion.
func deterministicValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = deterministicValue(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = deterministicValue(val)
		}
		return out
	default:
		return v
	}
}

// formatDescriberEnrichment serializes only the cb_describer_* keys
// from a resource's Inputs as a compact one-liner for the prompt. We
// deliberately omit raw CFN Properties — those are large per resource
// and the describer-emitted keys already capture the load-bearing
// signals (IMDSv2, encryption posture, last-used dates, etc.). Empty
// when no describer ran or none of its keys landed on this resource.
func formatDescriberEnrichment(inputs map[string]any) string {
	if len(inputs) == 0 {
		return ""
	}
	keys := make([]string, 0, len(inputs))
	for k := range inputs {
		if strings.HasPrefix(k, "cb_describer_") {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return ""
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, fmt.Sprintf("%s=%v", k, inputs[k]))
	}
	return strings.Join(pairs, ", ")
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
