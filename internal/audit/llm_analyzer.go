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
	"strconv"
	"strings"

	"github.com/cloudbooster-io/cbx-cli/core/plan"
	"github.com/cloudbooster-io/cbx-cli/internal/audit/knowledge"
	"github.com/cloudbooster-io/cbx-cli/internal/audit/parsers"
	"github.com/cloudbooster-io/cbx-cli/internal/config"
	"github.com/cloudbooster-io/cbx-cli/internal/llm"
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
	provider          string
	streamer          llmStreamer
	maxFiles          int
	maxBytesPerFile   int
	iacType           string
	providerForRuleID string // short label used in rule_id (e.g. "claude")

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

	// lastConnections holds the architecture-diagram edges extracted
	// from the most recent grounded response. Read by
	// CollectFromResources after ScanResources returns so the
	// downstream renderer can draw labelled arrows alongside the
	// deterministic Inputs-based ones. Empty when grounded mode is
	// off or the model didn't emit any.
	lastConnections []LLMConnection
}

// LastConnections returns the architecture edges the analyzer
// extracted from the most recent ScanResources call. Safe to call
// after the stream completes; nil otherwise.
func (l *llmAnalyzer) LastConnections() []LLMConnection {
	if l == nil {
		return nil
	}
	return l.lastConnections
}

// newLLMAnalyzer wires a Stream-based analyzer against the user's logged-in
// provider. Returns an error when the provider isn't configured — caller
// should surface that to the user as "run cbx llm api login <provider> first".
//
// The special provider name ClaudeCodeProvider ("claude-code") sidesteps
// cbx's own credential handling entirely: it shells out to the `claude`
// CLI which authenticates as Claude Code itself. No `cbx llm api login`
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
			// default" behavior they can pass 2.00 explicitly.
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
		return nil, fmt.Errorf("llm provider %q is not configured; run 'cbx llm api login %s' first", opts.LLMProvider, opts.LLMProvider)
	}

	// Resolve the provider credential here at the audit composition root and
	// inject it; core/plan.NewLLMCaller no longer reads the keychain itself.
	// A keyring failure (including no stored token) is a constructor error —
	// matching the unconfigured-provider posture above — rather than a blank
	// token that would surface later as an opaque provider auth failure.
	llmToken, err := llm.GetToken(opts.LLMProvider)
	if err != nil {
		return nil, fmt.Errorf("llm analyzer: reading %q token from keyring: %w; run 'cbx llm api login %s' to store one", opts.LLMProvider, err, opts.LLMProvider)
	}

	// core/plan carries its own LLMProvider type (the subset of
	// config.LLMProvider it actually reads) so the shared package stays
	// decoupled from internal/config — convert explicitly here at the
	// composition root.
	planProv := plan.LLMProvider{
		Name:    provCfg.Name,
		BaseURL: provCfg.BaseURL,
		Model:   provCfg.Model,
	}

	return &llmAnalyzer{
		provider:          opts.LLMProvider,
		streamer:          plan.NewLLMCaller(planProv, llmToken),
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
		// fetchErr is reserved for grounding-premise failures (auth-class
		// 401/403, total backend wipeout) — those abort the analysis.
		// Transient per-lookup misses ride back in bundle.Misses and
		// degrade to an LLM-CB-KNOWLEDGE-PARTIAL warning below instead.
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

	rawResp := sb.String()
	findings, parseErr := parseLLMFindings(rawResp, l.providerForRuleID)
	if parseErr != nil {
		return []Finding{l.errorFinding(fmt.Sprintf("parsing llm output: %v", parseErr))}, nil
	}
	// Connections are best-effort — parse failures here never block
	// findings from making it to the user.
	l.lastConnections = parseLLMConnections(rawResp)

	if l.cbKnowledge {
		findings = l.postProcessGrounded(findings)
		// Surface resource-table truncation (capPromptResources inside
		// buildGroundedPrompt drops the tail past the prompt budget).
		_, omitted := capPromptResources(resources)
		findings = l.appendTruncationFinding(findings, len(resources), omitted)
		findings = l.appendKnowledgePartialFinding(findings, bundle)
	}
	return findings, nil
}

// fetchBundle runs the Go-side grounding enumerator: looks up every CB
// primitive id, every detected workload, and the bulk composition once.
// Returns nil bundle on no inputs (the prompt renders that explicitly).
// The CB backend's reachability is already verified by the streamer
// constructor's preflight; only grounding-premise failures (auth-class
// 401/403, total backend wipeout) propagate up as errors — transient
// per-lookup failures land in bundle.Misses (see BuildGrounding's error
// policy) and are surfaced by appendKnowledgePartialFinding.
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

	rawResp := sb.String()
	findings, parseErr := parseLLMFindings(rawResp, l.providerForRuleID)
	if parseErr != nil {
		return []Finding{l.errorFinding(fmt.Sprintf("parsing llm output: %v", parseErr))}, nil
	}
	// Connections are best-effort — parse failures here never block
	// findings from making it to the user.
	l.lastConnections = parseLLMConnections(rawResp)

	if l.cbKnowledge {
		findings = l.postProcessGrounded(findings)
		if len(resources) > 0 {
			_, omitted := capPromptResources(resources)
			findings = l.appendTruncationFinding(findings, len(resources), omitted)
		}
		findings = l.appendKnowledgePartialFinding(findings, bundle)
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
			"WARN: grounded audit cost $%.2f exceeded --llm-max-cost $%s; partial findings preserved.\n",
			cost, formatCostCap(l.maxCostUSD),
		)
		findings = append(findings, Finding{
			RuleID:      "LLM-CB-COST-CAP",
			Title:       fmt.Sprintf("Audit cost $%.2f exceeded cap $%s", cost, formatCostCap(l.maxCostUSD)),
			Description: "The grounded audit's reported total_cost_usd exceeded --llm-max-cost. The run completed and findings are preserved, but rerun with a higher cap or scoped --source if you expect more turns.",
			Severity:    SeverityInfo,
			Resource:    l.providerForRuleID,
			Service:     "LLM",
			Remediation: "Increase --llm-max-cost, or narrow --source to fewer files.",
		})
	}

	return findings
}

// formatCostCap renders a --llm-max-cost value without rounding small
// caps to "$0.00" (a $0.001 cap is legitimate for validation runs).
// Two decimals for ordinary dollar amounts, full precision below a cent.
func formatCostCap(v float64) string {
	if v >= 0.01 {
		return fmt.Sprintf("%.2f", v)
	}
	return strconv.FormatFloat(v, 'f', -1, 64)
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

// errorFinding wraps a stream/parse failure as a warning-level finding so
// a partial run still lands somewhere visible. Mirrors the scanner-error
// posture in runner.go::collectFindings (partial findings + joined error).
// Warning (exit 2) rather than info: this is a TOTAL analysis failure —
// the LLM produced zero usable findings — and exit-code-gated CI must be
// able to tell it apart from a clean run with minor findings.
func (l *llmAnalyzer) errorFinding(detail string) Finding {
	return Finding{
		RuleID:      "LLM-ERROR",
		Title:       "LLM analyzer failed to produce findings",
		Description: detail,
		Severity:    SeverityWarning,
		Resource:    l.providerForRuleID,
		Service:     "LLM",
		Remediation: "Re-run with --llm omitted to fall back to other analyzers, or check provider credentials with 'cbx llm list'.",
	}
}

// appendTruncationFinding surfaces a capped resource table (see
// capPromptResources) to the user: an info-level LLM-CB-TRUNCATED
// finding listing how many resources the prompt omitted, plus a stderr
// warning matching the LLM-CB-UNGROUNDED posture. No-op when nothing
// was omitted.
func (l *llmAnalyzer) appendTruncationFinding(findings []Finding, total, omitted int) []Finding {
	if omitted <= 0 {
		return findings
	}
	fmt.Fprintf(os.Stderr,
		"WARN: %d/%d discovered resources omitted from the LLM prompt (budget: %d resources / %d bytes of inputs); findings cover the included resources only.\n",
		omitted, total, defaultLLMMaxPromptResources, defaultLLMMaxResourceTableBytes,
	)
	return append(findings, Finding{
		RuleID:      "LLM-CB-TRUNCATED",
		Title:       fmt.Sprintf("%d discovered resources omitted from the LLM prompt", omitted),
		Description: fmt.Sprintf("The grounded prompt's resource table is capped at %d resources / %d bytes of serialised inputs; %d of %d discovered resources were omitted (deterministically, from the tail of the sorted resource list). LLM findings cover only the included resources.", defaultLLMMaxPromptResources, defaultLLMMaxResourceTableBytes, omitted, total),
		Severity:    SeverityInfo,
		Resource:    l.providerForRuleID,
		Service:     "LLM",
		Remediation: "Narrow the audit (fewer regions or resource types) so the inventory fits the prompt budget, or run the non-LLM analyzers which have no such cap.",
	})
}

// appendKnowledgePartialFinding surfaces transiently-failed CB knowledge
// lookups (BuildGrounding's bundle.Misses) as ONE warning-severity
// LLM-CB-KNOWLEDGE-PARTIAL finding listing every primitive / workload /
// composition whose curated knowledge was unavailable, plus a stderr
// warning matching the LLM-CB-UNGROUNDED posture. Warning (exit 2), not
// info: findings touching the listed keys were produced WITHOUT CB's
// curated grounding — the whole value of `cbx audit aws` — and
// exit-code-gated CI must be able to see that degradation. 404s
// (knowledge.ErrNotAuthored) never land here: CB having no authored
// entry is the expected, fully-grounded state. Coexists with
// LLM-CB-TRUNCATED — both append to the same slice off independent
// conditions. No-op when the bundle is nil or complete.
func (l *llmAnalyzer) appendKnowledgePartialFinding(findings []Finding, bundle *GroundingBundle) []Finding {
	if bundle == nil || len(bundle.Misses) == 0 {
		return findings
	}
	keys := make([]string, 0, len(bundle.Misses))
	var details strings.Builder
	for _, m := range bundle.Misses {
		keys = append(keys, m.Kind+" "+m.Key)
		fmt.Fprintf(&details, "\n  - %s %s: %s", m.Kind, m.Key, m.Err)
	}
	fmt.Fprintf(os.Stderr,
		"WARN: CB knowledge unavailable for %d lookup(s): %s — findings for the affected resources are NOT grounded in CB's curated knowledge.\n",
		len(bundle.Misses), strings.Join(keys, "; "),
	)
	return append(findings, Finding{
		RuleID:      "LLM-CB-KNOWLEDGE-PARTIAL",
		Title:       fmt.Sprintf("CB knowledge unavailable for %d lookup(s); audit ran with reduced grounding", len(bundle.Misses)),
		Description: fmt.Sprintf("The following CB knowledge lookups failed transiently (after retry) and were skipped. The analysis proceeded with the knowledge that WAS fetched, but findings touching these primitives/workloads are not grounded in CloudBooster's curated knowledge:%s", details.String()),
		Severity:    SeverityWarning,
		Resource:    l.providerForRuleID,
		Service:     "LLM",
		Remediation: "Re-run the audit once the CloudBooster knowledge API is reachable to restore full grounding; until then treat findings on the listed resources like a non-grounded `--llm claude-code` run.",
	})
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
//   - resource Inputs are serialized with sorted keys (writeResourceTable),
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
	sb.WriteString("       • IAM roles with cross-account trust and no ExternalId → HIGH: when an `AWS::IAM::Role`'s decoded trust policy (`cb_describer_assume_role_policy_raw`) Allows an `sts:AssumeRole`-class action to a `Principal.AWS` in a DIFFERENT AWS account — an account id, an `:root` ARN, or a role/user ARN whose 12-digit account ≠ THIS audited account — or to `Principal.AWS: \"*\"`, with NO `sts:ExternalId` condition, the role is open to the confused-deputy attack (a third party who learns the role ARN can assume it without proving a shared secret). Emit a HIGH finding (recommend adding an `sts:ExternalId` condition, or scoping the trust to specific principals). NOT this finding, do NOT flag: same-account trust, AWS service principals (`Principal.Service`, e.g. `lambda.amazonaws.com`), and any statement that already carries an `sts:ExternalId` condition. Skip when `cb_describer_assume_role_policy_raw` is absent (the role wasn't enriched — never infer from a missing key).\n")
	sb.WriteString("       • IAM Group granting broad standing privilege via PowerUserAccess → MEDIUM: an `AWS::IAM::Group` with `cb_describer_power_user_managed_policy_attached: true` carries the AWS-managed `PowerUserAccess` policy, so EVERY member inherits persistent full access to nearly all AWS services (everything except IAM / Organizations / Account user-and-permission management) as a standing baseline — far broader than least-privilege, with a large blast radius if any member's credentials are compromised. Emit a MEDIUM finding (wire value `warning`; recommend replacing the blanket PowerUserAccess attachment with task-scoped policies granting only the services the group's members actually need). SCOPE — this is the broad-but-NOT-full-admin case: `cb_describer_power_user_managed_policy_attached` is a POSITIVE field set true ONLY for PowerUserAccess, never for AdministratorAccess, so a full-admin group does NOT trip this bullet (its account-takeover risk is the separate full-admin / wildcard-IAM CRITICAL case) — do NOT also emit this MEDIUM for an admin group, and do NOT inflate this PowerUserAccess finding above MEDIUM. Skip when `cb_describer_power_user_managed_policy_attached` is absent (the group's attached policies weren't enumerated — never infer the gap from a missing key).\n")
	sb.WriteString("       • S3 bucket policies allowing `Principal: \"*\"` without a strong condition (or any `aws:PrincipalAccount` restriction).\n")
	sb.WriteString("       • S3 bucket data-protection & hygiene posture — emit each item at `info` severity, INTENT-SCOPED. These are HARDENING recommendations, not \"the bucket is exposed/unencrypted\". CRITICAL FP GUARD: only flag a given item when the bucket's NAME or TAGS signal data, backup, archive, log, analytics/data-lake, or compliance/regulated intent — a generic or `*-private` bucket with no such intent signal and Public Access Block on must produce ZERO hygiene findings. Never flag an item the bucket already satisfies. These intent-scoped overrides apply EVEN WHEN the CB knowledge bundle frames a weaker setting as acceptable for general workloads. Specifically:\n")
	sb.WriteString("         – Versioning disabled (`cb_describer_versioning_enabled: false`): flag for data/stateful/backup buckets. Suppress for ephemeral, cache, build-artifact, or static-site CloudFront-origin buckets whose contents are re-publishable from source.\n")
	sb.WriteString("         – Default encryption is SSE-S3, not a KMS CMK (`cb_describer_sse_is_kms: false` AND encryption IS present): flag ONLY for sensitive/compliance/data-classification or analytics/data-lake buckets, as \"upgrade to SSE-KMS (CMK) for audit-logged, customer-managed key usage\". SSE-S3 (AES256) IS encryption-at-rest — never describe the bucket as unencrypted. The \"SSE-S3 is acceptable\" carve-out — CB knowledge endorses SSE-S3 for standard workloads — applies ONLY to OUT-of-scope generic / public / static-site-origin buckets with no data-intent signal; do NOT invoke it to suppress this item on an in-scope data/compliance bucket.\n")
	sb.WriteString("         – MFA-Delete absent (`cb_describer_mfa_delete_enabled: false`) AND versioning enabled (`cb_describer_versioning_enabled: true`): flag ONLY for versioned backup/compliance buckets. MFA-Delete is root-only to toggle and noisy on general buckets — never blanket.\n")
	sb.WriteString("         – No lifecycle policy (`cb_describer_lifecycle_present: false`): flag for buckets that accumulate data/ingest/log objects (cost + retention hygiene). Suppress short-lived or static-website-origin buckets.\n")
	sb.WriteString("         – No server-access logging (`cb_describer_access_logging_enabled: false`): flag for audit/data/compliance buckets. SUPPRESS when the bucket is itself an access-log destination (another bucket's `cb_describer_access_logging_target_bucket` points at it) — a log target logging to itself is recursion, not a gap.\n")
	sb.WriteString("         – Object Lock absent (`cb_describer_object_lock_enabled: false`): flag ONLY for backup, WORM, archive, or compliance/immutability-intent buckets — never blanket.\n")
	sb.WriteString("         – No SSL-only / TLS-enforcing bucket policy (`cb_describer_bucket_policy_present: false`, OR `cb_describer_bucket_policy_document` present but containing no `Deny` statement on `s3:*` with a `aws:SecureTransport: false` condition): the bucket accepts plaintext HTTP requests, so objects and pre-signed URLs can be read/written in cleartext over the network. Flag ONLY for data/sensitive/compliance/log/backup-intent buckets (NAME or TAGS signal). SUPPRESS generic / static-website-origin / already-public buckets (an intentionally public static site has no confidentiality to protect via transport). Recommend a bucket policy `Deny`-ing all S3 actions when `aws:SecureTransport` is `false`. SKIP when `cb_describer_bucket_policy_present` is absent (the policy was not read — never infer from a missing key).\n")
	// --- AWS Backup vault hygiene (one contiguous block) ---
	sb.WriteString("       • AWS Backup vault hygiene — emit each item as an INTENT-SCOPED HARDENING recommendation on an `AWS::Backup::BackupVault`, never as \"the vault is broken/unencrypted\". A Backup vault is inherently backup/recovery-intent, so no name/tag gate is needed — but PRESENT-FIELD discipline is mandatory: fire ONLY on the explicit `cb_describer_*` field value below, and SKIP when the field is ABSENT (the probe was denied or not read — NEVER infer the gap from a missing key). Specifically:\n")
	sb.WriteString("         – No Vault Lock (`cb_describer_vault_locked: false`) → `warning`: the vault has no Vault Lock, so its recovery points are deletable by anyone holding vault-Delete permission — there is no immutability / ransomware floor protecting the backups. Recommend enabling Vault Lock so recovery points become immutable for their retention period. SKIP when `cb_describer_vault_locked` is absent.\n")
	sb.WriteString("         – AWS-managed key, not a customer CMK (`cb_describer_vault_uses_aws_managed_key: true`) → `info`: the vault encrypts recovery points with the default `aws/backup` AWS-managed key rather than a customer-managed KMS CMK, so key policy, rotation, and grants are NOT operator-controlled — recommend a customer CMK for audit-logged, customer-controlled key usage. This is the Backup analog of the S3 SSE-S3→SSE-KMS upgrade item: the vault IS encrypted at rest — NEVER describe it as unencrypted. SKIP when the field is absent.\n")
	sb.WriteString("         – No vault access policy (`cb_describer_vault_access_policy_present: false`) → `info`: the vault has no resource-based access policy denying manual recovery-point deletion, so protection against accidental or malicious deletion relies solely on IAM. Recommend a vault policy with an explicit `Deny` on `backup:DeleteRecoveryPoint`. SKIP when the field is absent.\n")
	sb.WriteString("       • Load balancers with HTTP-only listeners on port 80 and no HTTPS sibling; missing WAF association on internet-facing ALBs.\n")
	// --- CloudFront security posture (one contiguous block) ---
	sb.WriteString("       • CloudFront distributions (`AWS::CloudFront::Distribution`) — evaluate the raw `DistributionConfig`; emit ONE finding per distinct gap below, never merged into one remediation:\n")
	sb.WriteString("         – Default viewer certificate / weak minimum TLS → `warning`: when `ViewerCertificate.CloudFrontDefaultCertificate` is `true` (the distribution serves only the default `*.cloudfront.net` certificate, which pins `MinimumProtocolVersion` to `TLSv1`), OR `ViewerCertificate.MinimumProtocolVersion` is any pre-2021 tier (`SSLv3`, `TLSv1`, `TLSv1_2016`, `TLSv1.1_2016`, `TLSv1.2_2018`, `TLSv1.2_2019`) rather than `TLSv1.2_2021`+, viewers can still negotiate a deprecated TLS version — emit a `warning` recommending a custom ACM certificate with `MinimumProtocolVersion=TLSv1.2_2021`. Suppress when `CloudFrontDefaultCertificate` is false/absent AND `MinimumProtocolVersion` is `TLSv1.2_2021` or a `TLSv1.3` tier.\n")
	sb.WriteString("         – No WAF web ACL → `info`: when `WebACLId` is empty or absent, no AWS WAF Web ACL is associated with the internet-facing distribution — emit an `info` hardening finding (a WAF on a static-content CDN is defense-in-depth, not an active exposure, so do NOT rate it higher than `info`).\n")
	sb.WriteString("         – Access logging disabled → `warning`: when `DistributionConfig.Logging` is absent, or `Logging.Bucket` is empty/absent, or `Logging.Enabled` is `false`, standard access logging is off and there is no request-level audit trail for the CDN — emit a `warning`. This reads the raw CFN property (not a `cb_describer_*` probe), so an absent `Logging`/`Bucket` genuinely means unconfigured — DO flag it.\n")
	sb.WriteString("         – Origin uses the S3 GLOBAL endpoint → `warning`: when any `Origins[*].DomainName` is the S3 global-endpoint form `<bucket>.s3.amazonaws.com` (NO region segment) rather than the regional form `<bucket>.s3.<region>.amazonaws.com`, requests to a bucket outside us-east-1 incur 307 redirects that add latency and can leak request data — emit a `warning` recommending the regional S3 origin endpoint (OAC-fronted). Treat the regional `<bucket>.s3.<region>.amazonaws.com` form and non-S3 custom origins (`Origins[*].CustomOriginConfig`) as compliant.\n")
	sb.WriteString("       • Databases / cache clusters with `PubliclyAccessible: true`.\n")
	sb.WriteString("       • RDS DB instances with insufficient automated-backup retention: when an `AWS::RDS::DBInstance` has `cb_describer_backup_retention_days <= 1` (0 = automated backups disabled — no point-in-time recovery at all; 1 = a single day, below any realistic recovery objective), emit a HIGH finding (data-durability / disaster-recovery gap; recommend a retention window that meets the workload's RPO, typically ≥7 days). CARVE-OUTS — flag ONLY a standalone primary: SUPPRESS when `cb_describer_is_read_replica` is `true` (read replicas legitimately run retention 0 — backups are taken on the source instance) and SUPPRESS when `cb_describer_is_cluster_member` is `true` (Aurora and non-Aurora Multi-AZ DB cluster members inherit cluster-level retention governed on the cluster, so the instance-level value is not authoritative). Treat an ABSENT `cb_describer_is_read_replica`, `cb_describer_is_cluster_member`, OR `cb_describer_backup_retention_days` as UNKNOWN and do NOT flag (the role probe failed or the field wasn't read — never infer the gap from a missing key).\n")
	sb.WriteString("       • Storage unencrypted at rest → HIGH: an `AWS::RDS::DBInstance` / `AWS::RDS::DBCluster` with `cb_describer_storage_encrypted: false`, or an `AWS::EC2::Volume` with `Encrypted: false` AND `cb_describer_is_attached: true` (a volume actively backing a running instance), keeps its data unencrypted on disk — emit a HIGH finding (RDS: enable KMS storage encryption at create / restore from an encrypted snapshot; EBS: re-create the volume from an encrypted snapshot). This means the storage is UNENCRYPTED — it is DISTINCT from, and must NEVER be conflated with, the S3 SSE-S3-vs-CMK upgrade rec above (an SSE-S3 bucket IS encrypted at rest). Skip when the encryption field is absent (not read — never infer the gap from a missing key) or `true`; an UNATTACHED unencrypted volume is the cost/hygiene orphan item above, NOT this HIGH finding.\n")
	sb.WriteString("       • Secrets without rotation (`RotationEnabled: false` or unset).\n")
	sb.WriteString("       • DynamoDB tables without point-in-time recovery (no continuous backups / PITR disabled).\n")
	sb.WriteString("       • DynamoDB AWS-owned-key (non-CMK) encryption — INTENT-SCOPED hardening rec, NOT an \"unencrypted\" finding: when an `AWS::DynamoDB::Table` has `cb_describer_dynamodb_sse_aws_owned: true` (the table uses the default AWS-owned key rather than a customer-managed KMS CMK, so key usage is NOT logged in CloudTrail), recommend upgrading to a customer-managed CMK for audit-logged, customer-controlled key usage — but ONLY when the table's NAME or TAGS signal sensitive / PII / regulated / compliance / financial data intent. DynamoDB is ALWAYS encrypted at rest — never describe an AWS-owned-key table as unencrypted; this mirrors the S3 SSE-S3→CMK upgrade item and must NEVER be conflated with the RDS/EBS \"unencrypted at rest\" HIGH. A generic application table with no data-intent signal must produce ZERO finding here. Skip when the field is absent or false (the table already uses a KMS CMK — never infer the gap from a missing key).\n")
	sb.WriteString("       • Athena workgroups (`AWS::Athena::WorkGroup`): emit a WARNING hardening finding when `WorkGroupConfiguration.EnforceWorkGroupConfiguration` is false or absent (client-side query settings can override the workgroup's result location and encryption), and a SEPARATE WARNING when `WorkGroupConfiguration.ResultConfiguration.EncryptionConfiguration` is absent (query results are written to S3 unencrypted). These are orthogonal — never merge them into one finding. EXCLUDE the AWS-managed default workgroup (`cb_describer_is_default_workgroup == true`) from BOTH findings: it ships unenforced and unencrypted by default in every account, so that state is AWS's baseline, not a user misconfiguration — flag ONLY user-created workgroups.\n")
	sb.WriteString("       • Unattached / orphaned resources accruing cost: EBS volumes (`State: available`), EIPs (`cb_describer_is_attached: false`), KMS keys with `cb_describer_is_unused: true` (no other resource references the key — pure cost waste). Exclude AWS-managed keys (`cb_describer_key_manager == \"AWS\"`) from unused-key findings.\n")
	// --- CIS/FSBP bucket-A batch: S3 Block-Public-Access disabled (HIGH) + public KMS key-policy (CRITICAL) + KMS CMK rotation off (info). Beyond-fixtures, detection-only; every field is already rendered into the prompt. ---
	sb.WriteString("       • S3 Block Public Access disabled → HIGH (data exposure): when an `AWS::S3::Bucket` has `cb_describer_public_access_block` present as an object in which ANY of the four flags `block_public_acls`, `block_public_policy`, `ignore_public_acls`, `restrict_public_buckets` is `false`, the bucket's guardrail against public ACLs and public bucket policies is weakened — a single public ACL or `Principal: \"*\"` policy can then expose its objects to the internet (CIS 2.1.4 / FSBP S3.1, S3.8). Emit a HIGH finding (recommend enabling all four Block Public Access settings on the bucket). This is a real data-exposure control — it is NOT one of the `info` SSE / versioning / lifecycle hygiene items above, so do NOT fold it into their positive-data-intent gate and do NOT downgrade it to `info`. INTENT-SCOPE — the ONE legitimate reason to disable BPA is a deliberately public bucket: SUPPRESS when the bucket is a public static-site / CloudFront-origin / public-website bucket (its NAME or TAGS, an attached public-read `s3:GetObject` policy, or a website-hosting configuration signal that public serving is intended) — disabling BPA is correct there; otherwise FIRE for data / private / internal / backup / log buckets and any bucket with no public-serving intent. CRITICAL FP GUARD — present-field discipline: fire ONLY when `cb_describer_public_access_block` is present as an object carrying an explicit `false` flag; SKIP when it is `null` or ABSENT — a `null`/absent value means the bucket has no bucket-level Block-Public-Access config of its own, so it may be covered by account-level Block Public Access (or the probe was denied), which is UNKNOWN, never the gap — never infer a finding from `null`/absent.\n")
	sb.WriteString("       • Public KMS key policy → CRITICAL (key compromise / cross-account decrypt): when an `AWS::KMS::Key`'s raw `KeyPolicy` (the key's resource policy, returned inline in the resource state) has a statement with `Effect: Allow` and a wildcard principal — `Principal: \"*\"`, `{\"AWS\": \"*\"}`, or `{\"AWS\": [\"*\"]}` — WITHOUT a condition that scopes that wildcard back to your account or organization (`aws:PrincipalAccount`, `aws:PrincipalOrgID`, `aws:PrincipalOrgPaths`, `aws:PrincipalArn`, or `kms:CallerAccount`), the key is usable by any principal in any AWS account (e.g. `kms:Decrypt`, `kms:Encrypt`), so every ciphertext and every resource the key protects is exposed cross-account / publicly (FSBP KMS.5 / CIS 2.21). Emit a CRITICAL finding (recommend scoping the key policy `Principal` to specific accounts / roles, or adding an `aws:PrincipalOrgID` condition). This mirrors the S3 public-bucket-policy rule and the Glue Data Catalog wildcard-principal rule above. COMPLIANT / DO-NOT-FLAG: the ubiquitous DEFAULT key policy grants `Principal: {\"AWS\": \"arn:aws:iam::<thisAccount>:root\"}`, which is an account-root ARN, NOT a wildcard — do NOT flag it; likewise a wildcard statement that DOES carry one of the scoping conditions above, and a `KeyPolicy` that is absent or unreadable in the resource state (UNKNOWN — never infer the gap from a missing key), are all compliant.\n")
	sb.WriteString("       • KMS customer-managed CMK with rotation disabled → `info` (key hygiene): when an `AWS::KMS::Key` has `cb_describer_key_rotation_enabled: false` AND `cb_describer_key_manager: \"CUSTOMER\"`, the customer-managed CMK is not on automatic annual key rotation, so the same key material protects data indefinitely (CIS 3.6 / FSBP KMS.4-class). Emit an `info` hardening finding (recommend enabling automatic key rotation). SUPPRESS AWS-managed / AWS-owned keys (`cb_describer_key_manager: \"AWS\"`): AWS rotates those on its own schedule, outside operator control, so their rotation state is never a finding (the same AWS-managed exclusion the unused-key item above applies). Automatic rotation applies only to symmetric encryption CMKs, so confine this to `cb_describer_key_spec: SYMMETRIC_DEFAULT` / `cb_describer_key_usage: ENCRYPT_DECRYPT` keys. PRESENT-FIELD discipline: fire ONLY on an explicit `cb_describer_key_rotation_enabled: false`; SKIP when the field is ABSENT (`kms:GetKeyRotationStatus` was denied or not applicable to the key type — never infer the gap from a missing key).\n")
	sb.WriteString("       • Lambda functions missing operational-resilience config: `cb_describer_dlq_configured: false` means no dead-letter target — failed async invocations are silently dropped (emit WARNING, no DLQ configured). `cb_describer_reserved_concurrency_set: false` means no reserved concurrency — a runaway or abusive caller can consume the account-wide concurrency budget and starve every other function (emit WARNING, framed as availability / DoS-amplifier hygiene, NOT critical).\n")
	sb.WriteString("       • Lambda functions with secret-shaped plaintext env vars → `info`, FP-AWARE HEURISTIC: `cb_describer_env_has_plaintext_secrets: true` means at least one `Environment.Variables` KEY matches a secret-NAME pattern (`*SECRET*`, `*PASSWORD*`, `*TOKEN*`, `API_KEY`, `*CREDENTIAL*`, `PRIVATE_KEY`) while NOT looking like a reference (the describer already excludes `_arn` / `_id` / `_uri` / `_url`-suffixed keys). This is a key-SHAPE heuristic over variable NAMES, not an inspection of their values, so emit only an `info` finding framed as REVIEW: review whether these env vars hold plaintext secrets rather than Secrets-Manager / SSM references — if so, switch to a runtime lookup or an encrypted reference. NEVER assert a variable IS a leaked secret, and keep the severity `info` (the heuristic's false-positive rate is exactly why it is not rated higher). SKIP when `cb_describer_env_has_plaintext_secrets` is absent or `false` (no secret-shaped key, or the function wasn't enriched — never infer the gap from a missing key).\n")
	sb.WriteString("       • API Gateway with access logging disabled: `cb_describer_access_logging_enabled: false` on an `AWS::ApiGatewayV2::Api` (or `AWS::ApiGateway::RestApi`) means one or more stages have no access-log destination, so there is no request-level audit trail (emit WARNING). `cb_describer_stages_without_access_log` names the affected stages when present. Skip this when the field is absent (stages weren't enumerated — do NOT infer disabled from a missing key).\n")
	sb.WriteString("       • ECS clusters with CloudWatch Container Insights disabled: when an `AWS::ECS::Cluster` has `cb_describer_container_insights_enabled: false` (the cluster's `ClusterSettings` explicitly sets `containerInsights` to `disabled`), emit a WARNING — the cluster has no aggregated CPU / memory / task-level metrics, slowing incident triage and capacity planning (recommend enabling Container Insights). Skip when the field is absent (no explicit cluster-level setting — an account-level default may still enable it; do NOT infer disabled from a missing key).\n")
	sb.WriteString("       • ECR repositories with MUTABLE image tags: when an `AWS::ECR::Repository` has `ImageTagMutability` == `MUTABLE`, emit a HIGH finding — a published tag (e.g. a release / deployed version) can be overwritten with different image content, undermining supply-chain integrity, image provenance, and reproducible deploys (recommend `ImageTagMutability=IMMUTABLE`). This is a distinct finding from scan-on-push and lifecycle-policy gaps on the same repository — keep them separate. Skip when `IMMUTABLE` or when the field is absent (the repo wasn't enriched — do NOT infer the gap from a missing key).\n")
	// --- next-round recall rule-gaps batch 1 (field-in-hand, healthy variants 06/08/03) ---
	sb.WriteString("       • CloudTrail trails not streaming to CloudWatch Logs → WARNING: when an `AWS::CloudTrail::Trail` has no `CloudWatchLogsLogGroupArn` (the property is empty or absent), the trail delivers events to S3 only — there is no near-real-time CloudWatch Logs stream, so metric-filter alarms and SIEM hand-off cannot alert on activity as it happens (the S3 trail still supports after-the-fact forensics, which is why this is WARNING, not a blind-audit HIGH). Emit a WARNING scoped to the trail's URN, recommending the trail be wired to a CloudWatch Logs log group. This reads the raw CFN property — CloudControl returns `CloudWatchLogsLogGroupArn` only when the integration is configured (mirroring the CloudFront `Logging` case above), so an absent value genuinely means unconfigured: DO flag it. DISTINCT from the account-level CloudTrail region-coverage finding below — a covered region can still lack CW-Logs alerting.\n")
	sb.WriteString("       • CloudTrail trail without log-file validation → WARNING (audit integrity): an `AWS::CloudTrail::Trail` whose raw CFN property `EnableLogFileValidation` is explicitly `false` produces no signed SHA-256 digest files, so after-the-fact tampering with (or deletion of) delivered log files cannot be cryptographically detected — the audit trail is no longer tamper-evident. Emit a WARNING (recommend `EnableLogFileValidation: true` and periodic `aws cloudtrail validate-logs`). `EnableLogFileValidation` arrives as a raw CloudControl CFN property (there is no `cb_describer_*` probe for trails); fire ONLY on an explicit `false`, and SKIP when the property is absent (CloudControl did not return it — never infer the gap from a missing key).\n")
	sb.WriteString("       • ECS task definitions with a writable container root filesystem → WARNING, INTENT-SCOPED: when an `AWS::ECS::TaskDefinition` has a container in `ContainerDefinitions[*]` whose `ReadonlyRootFilesystem` is explicitly `false`, that container's root volume is writable at runtime — an attacker who achieves code execution inside it can drop a webshell, persist, or modify binaries in place. Emit a WARNING recommending `readonlyRootFilesystem: true` with explicit writable mounts only for the paths that need them. CRITICAL FP GUARD — a writable root is default-common and legitimate for many workloads, so: (a) fire ONLY on an EXPLICIT `false` — when `ReadonlyRootFilesystem` is ABSENT/unset, treat it as UNKNOWN and do NOT flag (a bare container with the field unset is NOT a finding; never infer the gap from a missing key); and (b) flag ONLY the primary application / long-running workload container(s) — those marked `Essential: true` or clearly the main service image — and SKIP sidecar, init, and build/CI containers (logging or telemetry agents, envoy/otel/xray sidecars, one-shot init/migration jobs) where a writable root is routine. Scope the finding to the task definition's URN.\n")
	sb.WriteString("       • ECS task-definition container posture (`AWS::ECS::TaskDefinition`) — read the synthesised `ContainerDefinitions[*]` array (the native ECS task-definition lister surfaces these raw CFN container fields directly; there is no `cb_describer_*` probe for them). PRESENT-FIELD discipline is mandatory: evaluate ONLY containers actually present in `ContainerDefinitions[*]`, and when `ContainerDefinitions` is absent entirely (the task definition wasn't read) emit NOTHING for these items — never infer a gap from a missing key. Specifically:\n")
	sb.WriteString("         – Privileged container → HIGH: a container in `ContainerDefinitions[*]` whose `Privileged` is explicitly `true` runs with host-root Linux capabilities — code execution inside it can escape the container and compromise the underlying host / EC2 node and every other task scheduled on it. Emit a HIGH finding (recommend `privileged: false`, granting only the specific Linux capabilities the workload actually needs). Fire on ANY such container INCLUDING sidecars (a privileged sidecar is just as host-dangerous as a privileged application container). The lister emits `Privileged` only when the SDK returned a non-nil value, so SKIP when `Privileged` is ABSENT/unset (the AWS default is non-privileged — never infer it from a missing key) and SKIP when it is explicitly `false`.\n")
	sb.WriteString("         – Secret-shaped plaintext `Environment` vars → `warning`, FP-AWARE HEURISTIC: when a container carries an entry in its plaintext `Environment[*]` list (each entry is `{Name, Value}`) whose `Name` looks like a secret — contains or ends with `SECRET`, `PASSWORD`, `PASSWD`, `TOKEN`, `API_KEY`, `CREDENTIAL`, or `PRIVATE_KEY` — with an inline literal `Value`, that secret is baked into the task definition in cleartext (readable by anyone holding `ecs:DescribeTaskDefinition`) instead of being injected through the container's `Secrets[*]` block (which references SSM Parameter Store / Secrets Manager via `ValueFrom`). Emit a `warning` framed as REVIEW — these env keys look like secrets stored in plaintext; prefer the `Secrets` / SSM injection path — and NEVER assert the value IS a leaked secret: this is a key-NAME heuristic, not a value inspection. SUPPRESS when the `Value` is clearly a reference rather than a literal secret (an `arn:`-prefixed value, or a key suffixed `_ARN` / `_URL` / `_URI` / `_ID`, the canonical indirection shape) and when the same logical secret is already supplied via the container's `Secrets[*]` block.\n")
	sb.WriteString("         – No container log driver → `warning`, REVIEW nudge: when a container present in `ContainerDefinitions[*]` has no `LogConfiguration.LogDriver`, that container's stdout/stderr may be shipped to no centralized log sink (CloudWatch Logs, `awslogs`, `awsfirelens`, …) — leaving no runtime audit trail for it. The native ECS task-definition lister emits `LogConfiguration` only when a log driver is set, so on natively-listed task definitions an absent value means none is configured; frame this as a `warning` REVIEW nudge to CONFIRM the log driver — not a hard assertion — because a discovery path that simply does not return the nested `LogConfiguration` on read would look identical. Recommend an `awslogs` (or `awsfirelens`) log driver, focused on the primary / long-running application container(s); a one-shot init / build container that legitimately omits logging is low value and may be skipped.\n")
	sb.WriteString("       • DynamoDB tables without deletion protection → WARNING, scoped to durable/stateful tables: when an `AWS::DynamoDB::Table` has `DeletionProtectionEnabled: false`, a single `DeleteTable` call — a mis-clicked console action, a Terraform/CloudFormation destroy, or a compromised credential — irreversibly drops the table and every item in it. Emit a WARNING recommending `DeletionProtectionEnabled: true` for tables holding durable application state. `DescribeTable` always returns this field, so an explicit `false` is a reliable signal; do NOT flag when the field is absent (not read — never infer the gap from a missing key). FP-scope: this is a production-data-durability control — a table whose NAME or TAGS signal scratch, cache, ephemeral, or temp intent need not carry it, so prefer to flag tables that look like durable application data. ORTHOGONAL to the PITR and AWS-owned-key (CMK) items above — emit it as its own finding, never merged.\n")
	sb.WriteString("       • Account-level gaps from the ACCOUNT POSTURE block: any region in `CloudTrail coverage` reporting `false` (no trail covers it — emit an account-level finding `account:<accountId>` for each), default EBS encryption disabled for a region, no IAM password policy.\n")
	sb.WriteString("       • GuardDuty (ACCOUNT POSTURE `GuardDuty detector` block): for EACH region whose line reads `disabled`, emit a HIGH account-level finding `account:<accountId>` titled `GuardDuty disabled in <region>` — a detector exists but is suspended, so threat detection is off (a real regression). Separately, when the derived `GuardDuty detector present in at least one audited region` line is `false` (NO detector exists in ANY audited region — every region reads `absent`), emit ONE WARNING `account:<accountId>` finding that the account has no GuardDuty threat detection. A `disabled` detector means a detector IS present, so it does NOT trip this account-wide warning — the per-region HIGH above already covers it. Do NOT flag a single region reading `absent` when another region reads `enabled` or `disabled`.\n")
	sb.WriteString("       • AWS Config global coverage (ACCOUNT POSTURE `AWS Config recorder` block): when `AWS Config recorder present in at least one audited region` is `true` but `global resource types recorded in at least one audited region` is `false`, emit ONE HIGH account-level finding `account:<accountId>` titled `AWS Config not recording global (IAM) resource types` — a recorder IS configured but blind to IAM/global changes, so those changes go unmonitored (a real coverage regression on a service the account already runs, mirroring the GuardDuty `disabled`-detector HIGH above). Separately, when `present in at least one audited region` is `false` (no recorder exists in ANY audited region), emit ONE WARNING `account:<accountId>` finding that AWS Config is not enabled. Do NOT flag a per-region `records_global_types=false` when another region records them — global types only need recording once.\n")
	sb.WriteString("       • Glue Data Catalog exposure from the ACCOUNT POSTURE block: any region whose `Glue Data Catalog resource policy` reports `grants_wildcard_principal=true` grants `Principal: \"*\"` (or `{\"AWS\":\"*\"}`) over the entire Data Catalog with no scoping condition — emit a CRITICAL account-level finding `account:<accountId>` per affected region (every database, table, and partition is exposed cross-account / publicly).\n")
	sb.WriteString("       • Root account credentials from the ACCOUNT POSTURE block (exact iam:GetAccountSummary counters, account-wide singletons): when `Root account access keys present` reads `true`, the AWS account root user holds standing long-lived access key(s) — a direct account-takeover vector that bypasses every per-identity IAM guardrail — so emit a CRITICAL account-level finding `account:<accountId>` (recommend deleting all root access keys; the root user must never hold programmatic credentials; AWS FSBP IAM.4). SEPARATELY, when `Root account MFA enabled` reads `false`, the root user has no MFA device, so a single leaked root password is full account compromise — emit a HIGH account-level finding `account:<accountId>` (recommend enabling a hardware or virtual MFA device on the root user; AWS FSBP IAM.9). These are exact integer reads, so DO flag on the explicit value; but when EITHER line is ABSENT from the ACCOUNT POSTURE block (the iam:GetAccountSummary probe failed — see the posture probe errors), treat it as UNKNOWN and do NOT flag (never infer the gap from a missing counter).\n")
	sb.WriteString("       • IAM console users without MFA (ACCOUNT POSTURE `IAM console users WITHOUT MFA` block, from iam:GetCredentialReport): for EACH user name listed, emit a WARNING account-level finding `account:<accountId>` titled `IAM console user <user> has no MFA` — the user can sign in to the AWS console with a password alone, so a single phished or leaked password is a full session takeover for that identity (CIS AWS Foundations 1.10 / AWS FSBP IAM.5: MFA must be enabled for every IAM user that has a console password). The block lists ONLY non-compliant users (password_enabled=true AND mfa_active=false) and already EXCLUDES the root user (covered by the `Root account MFA enabled` rule) and programmatic-only / service users (no console password). The derived `(... evaluated N; without MFA 0)` line with NO user list is positive confirmation that every console user has MFA — do NOT flag. When the `IAM console users WITHOUT MFA` block is ABSENT entirely (the iam:GetCredentialReport probe failed — see the posture probe errors), treat console-MFA coverage as UNKNOWN and do NOT flag (never infer the gap from missing data).\n")
	sb.WriteString("       • EC2 instances effectively exposed: check `cb_describer_subnet_is_public` (pre-computed — subnet has MapPublicIpOnLaunch=true OR its route table has a 0.0.0.0/0 → IGW route) combined with `cb_describer_public_ip_present`. When both true AND any attached SG has wide-open admin ingress, emit a CRITICAL compound finding referencing the instance, subnet, and SG.\n")
	sb.WriteString("       • EC2 instances allowing IMDSv1 → HIGH: when an `AWS::EC2::Instance`'s `MetadataOptions.HttpTokens` is set to anything other than `required` (e.g. `optional`), the Instance Metadata Service still answers unauthenticated IMDSv1 requests, so an SSRF flaw or a compromised in-instance process can read the instance role's temporary credentials with no token. Emit a HIGH finding (recommend `HttpTokens=required` — IMDSv2-only — and `HttpPutResponseHopLimit=1`). Skip when `MetadataOptions` is absent (not read — do NOT infer the gap from a missing key) or when `HttpTokens == required`.\n")
	sb.WriteString("       • VPC flow logs absent: any `AWS::EC2::VPC` whose `cb_describer_flow_logs_enabled` is `false` has no ACTIVE VPC-level flow log — emit a WARNING finding scoped to that VPC's URN (`resource: <vpc-urn>`) recommending a flow log for network-traffic visibility / incident forensics. Treat an absent or unset `cb_describer_flow_logs_enabled` as UNKNOWN and do NOT flag it (the region wasn't probed).\n")
	// --- next-round recall bullet batch: RDS deletion-protection / single-AZ (07), EC2 no-instance-profile (04), ALB access-logs (07, !53 enrich) ---
	sb.WriteString("       • RDS DB instances without deletion protection → WARNING: an `AWS::RDS::DBInstance` with `cb_describer_deletion_protection: false` can be deleted by a single API / console call with no guard — accidental or malicious deletion destroys the database and its automated backups. Emit a WARNING (recommend enabling deletion protection). INTENT-SCOPE (the AWS default is `false`, so this is default-common — do NOT blanket-fire): flag ONLY when the database's NAME or TAGS signal production / stateful / primary / critical intent — SUPPRESS for names/tags signalling dev, test, staging, sandbox, ephemeral, or CI intent (those are deliberately left deletable for automated teardown). CARVE-OUTS — flag ONLY a standalone primary `AWS::RDS::DBInstance` (this rule is instance-scoped; an `AWS::RDS::DBCluster` carries neither carve-out signal and is out of scope): SUPPRESS when `cb_describer_is_cluster_member` is `true` (deletion protection on an Aurora / Multi-AZ DB-cluster member is governed at the cluster, not the instance — not authoritative) and SUPPRESS when `cb_describer_is_read_replica` is `true`. Treat an ABSENT `cb_describer_deletion_protection`, `cb_describer_is_cluster_member`, OR `cb_describer_is_read_replica` as UNKNOWN and do NOT flag (the field wasn't read or the role probe failed — never infer the gap from a missing key).\n")
	sb.WriteString("       • RDS single-AZ (no high-availability) → WARNING: an `AWS::RDS::DBInstance` with `cb_describer_multi_az: false` runs in one Availability Zone — an AZ outage takes it fully offline with no automatic failover. Emit a WARNING (recommend Multi-AZ). INTENT-SCOPE (single-AZ is the AWS default and a legitimate cost choice — HIGH FP-risk if blanket-fired): flag ONLY when the database's NAME or TAGS signal production / stateful / primary / critical intent — SUPPRESS for dev / test / staging / sandbox / ephemeral / CI-intent databases (single-AZ is the correct, cheaper choice there). CARVE-OUTS — flag ONLY a standalone primary `AWS::RDS::DBInstance` (instance-scoped, same reason as deletion protection above): SUPPRESS when `cb_describer_is_cluster_member` is `true` (Aurora and Multi-AZ DB clusters provide HA at the cluster level across AZs — the instance-level `MultiAZ` flag is not the HA signal for a cluster member) and SUPPRESS when `cb_describer_is_read_replica` is `true` (a replica's own AZ posture is not the primary's availability story). Treat an ABSENT `cb_describer_multi_az`, `cb_describer_is_cluster_member`, OR `cb_describer_is_read_replica` as UNKNOWN and do NOT flag.\n")
	sb.WriteString("       • RDS DB instance with automatic minor-version upgrades disabled → WARNING (patch hygiene): an `AWS::RDS::DBInstance` whose raw CFN property `AutoMinorVersionUpgrade` is explicitly `false` will NOT auto-apply AWS's minor engine patches in its maintenance window, so security and bug fixes accumulate unpatched until a manual upgrade. Emit a WARNING (recommend `AutoMinorVersionUpgrade: true`, or a documented manual-patch SLA). Fire on an explicit `false`; SKIP when `AutoMinorVersionUpgrade` is absent (the instance was discovered on a path that did not carry it — never infer the gap from a missing key). This is instance-scoped: an `AWS::RDS::DBCluster` carries cluster-level patching and is out of scope.\n")
	sb.WriteString("       • EC2 instances with no IAM instance profile → WARNING: an `AWS::EC2::Instance` whose `cb_describer_instance_profile_arn` is the empty string `\"\"` has no IAM identity attached, so AWS Systems Manager (Session Manager / Patch Manager / Fleet Manager) cannot manage it — operators fall back to SSH / key-pair access, a larger attack surface with no centralised, audited access path. Emit a WARNING (recommend attaching an instance profile granting `AmazonSSMManagedInstanceCore`). This detects the NO-instance-profile state, NOT a profile that exists but lacks SSM permissions (the describer surfaces only the profile ARN, not the role's policies). Flag only running / stopped instances — SKIP when `cb_describer_state` is `terminated` or `shutting-down`. Unlike the RDS deletion-protection / single-AZ bullets above, this finding is DELIBERATELY NOT intent-scoped: those gate on prod-intent because the SEVERITY of single-AZ / no-deletion-protection is genuinely environment-dependent (single-AZ is the correct, cheaper choice in dev/test), whereas \"not SSM-managed\" is a uniform low-severity hygiene gap — an equal, real exposure on ANY instance regardless of environment (mirroring AWS FSBP control SSM.1). Fire on every profile-less running / stopped instance; do NOT add a prod-intent gate here (no dev / test / sandbox suppression). Treat an ABSENT `cb_describer_instance_profile_arn` key as UNKNOWN and do NOT flag (in practice the EC2 describer always sets it to `\"\"` or an ARN — never infer the gap from a missing key).\n")
	sb.WriteString("       • ALB with access logging disabled → WARNING: an `AWS::ElasticLoadBalancingV2::LoadBalancer` with `cb_describer_alb_access_logs_enabled: false` writes no S3 access logs — there is no request-level audit trail of traffic through the load balancer. Emit a WARNING (recommend enabling access logs to an S3 bucket). `cb_describer_alb_access_logs_enabled` is a POSITIVE field (`true` iff enabled, `false` iff explicitly disabled), so fire ONLY on an explicit `false`. Skip when the field is absent (the LB's attributes weren't read — do NOT infer disabled from a missing key).\n")
	// --- EKS no pod-level IAM mechanism (10) — both-absent gate over the two EKS describer probes ---
	sb.WriteString("       • EKS cluster with no pod-level IAM mechanism → HIGH: an `AWS::EKS::Cluster` where BOTH `cb_describer_eks_irsa_oidc_provider_present: false` AND `cb_describer_eks_pod_identity_present: false` has neither an IAM OIDC identity provider (IRSA) NOR an EKS Pod Identity association — pods have NO way to assume scoped IAM roles via Kubernetes service accounts and fall back to the shared, broad node instance-role credentials reachable by ANY pod on the node (a real privilege-scoping / lateral-movement gap). Emit a HIGH finding (recommend adopting IRSA — create the IAM OIDC provider — or EKS Pod Identity). SUPPRESS when EITHER field is `true` (the cluster already has a scoped-role mechanism). Skip when EITHER field is ABSENT (the issuer / IAM providers / Pod-Identity associations couldn't be read — do NOT infer the gap from a missing key).\n")
	sb.WriteString("       • EKS cluster without envelope encryption for Kubernetes Secrets → WARNING: an `AWS::EKS::Cluster` with no KMS envelope-encryption provider for the `secrets` resource stores Secrets only base64-encoded in etcd (base64 is NOT encryption), so anyone who reaches etcd, a node, or the API with secret-read access sees them in cleartext. Detect via EITHER discovery shape: `EncryptionConfigPresent: false` (the native EKS lister's synthesised boolean) OR a CloudControl-discovered cluster whose raw CFN `EncryptionConfig` array is absent or empty. Emit a WARNING (recommend an `encryptionConfig` block with a KMS CMK provider covering `resources: [\"secrets\"]`). SUPPRESS when `EncryptionConfigPresent` is `true` OR `EncryptionConfig` is a non-empty array (envelope encryption is configured). SKIP when NEITHER field is present (the cluster's encryption config was not read — never infer the gap from a missing key).\n")
	sb.WriteString("     This list is NOT exhaustive — use AWS-baseline judgement.\n\n")
	sb.WriteString("  2. **DO NOT MERGE ORTHOGONAL ISSUES.** If a single resource has multiple distinct security issues, emit ONE FINDING PER ISSUE — never roll them into one finding with a long remediation. Specifically:\n")
	sb.WriteString("       • Security groups: emit ONE CRITICAL finding per (SG, exposed admin port) pair listed in `cb_describer_ingress_exposed_admin_ports`. A SG with ports [22, 3389] open to 0.0.0.0/0 produces TWO findings, not one. Title each as `SSH (port 22) open to the internet on <SG-id>`, `RDP (port 3389) open to the internet on <SG-id>`, etc. Compound \"instance exposed via SG\" findings are ADDITIONAL — they don't replace the per-port SG findings.\n")
	sb.WriteString("       • EBS snapshots: a snapshot that is both unencrypted AND publicly shared (`cb_describer_publicly_shared: true`) produces TWO findings — an unencryption finding (WARNING) and a SEPARATE publicly-shared-snapshot finding (CRITICAL). The public-share finding is the most dangerous attribute and MUST stand alone; never bury it in a remediation paragraph.\n")
	sb.WriteString("       • API Gateway with no authorizer + backing Lambda with admin-equivalent role: emit a CRITICAL compound finding referencing both resources. The Lambda's role privilege is pre-computed — check `cb_describer_role_is_admin_equivalent` (true means AdministratorAccess / PowerUserAccess / IAMFullAccess attached) and `cb_describer_role_has_wildcard_inline_policy` (true means an inline `Action:* Resource:*` Allow). Either flag being true on a Lambda fronted by an unauthenticated route is CRITICAL.\n")
	sb.WriteString("       • RDS / databases with `PubliclyAccessible: true`: severity is pre-computed via `cb_describer_effectively_public`. When that field is `true` (the DBSubnetGroup contains at least one internet-routable subnet) emit CRITICAL (\"database is reachable from the internet\"). When `false` (all subnets are private) emit HIGH (\"publicly-accessible flag is set — one route-table change exposes the database\") with the explicit caveat that current routing keeps it private. Never escalate to CRITICAL on the flag alone.\n\n")
	sb.WriteString("  3. Use the CB knowledge bundle as authoritative context for CB's RECOMMENDED posture. When a finding aligns with CB-authored guidance, quote the relevant phrase in `cb_source.snippet` and set `cb_source.tool` to the bundle section (`aws_lookup_primitive` / `aws_best_practices_for` / `aws_composition_for`) with `key` set to the primitive id / workload slug / \"composition\".\n")
	sb.WriteString("  4. When a finding has no exact CB-authored anchor (baseline AWS hygiene), set `cb_source` to {tool: \"aws_baseline\", key: \"<short-rule-name>\", snippet: \"<the AWS-baseline rule you applied>\"} so the report still carries a justification.\n")
	sb.WriteString("  5. Use the resource's URN as `resource` for resource-scoped findings, and `account:<accountId>` for account-posture findings.\n")
	sb.WriteString("  6. Don't invent file/line fields — set `file: \"\"` and `line: 0` for live-AWS findings.\n\n")

	sb.WriteString("ARCHITECTURE CONNECTIONS — Alongside findings, also emit a `connections` array describing the SEMANTIC data-flow relationships between discovered resources. These power the architecture diagram. Only emit edges you can support from concrete fields in the resource data:\n")
	sb.WriteString("  • CloudFront → S3 origin: when an `AWS::CloudFront::Distribution` has `Origins[*].S3OriginConfig` AND the origin's `DomainName` resolves to a discovered S3 bucket (match the bucket name prefix of `DomainName` against discovered bucket IDs).\n")
	sb.WriteString("  • CloudFront → ALB origin: when `Origins[*].CustomOriginConfig` plus `DomainName` resolves to a discovered ALB/ELB DNS name.\n")
	sb.WriteString("  • API Gateway → Lambda: when `AWS::APIGateway::Method.Integration.Uri` ARN references a discovered Lambda function ARN, or `AWS::ApiGatewayV2::Integration.IntegrationUri` does.\n")
	sb.WriteString("  • Lambda → DynamoDB / S3 / Secrets / KMS: when the Lambda's execution role's INLINE or ATTACHED policy lists Allow actions (`dynamodb:*`, `s3:*`, `secretsmanager:GetSecretValue`, `kms:Decrypt`, etc.) targeting a specific Resource ARN that matches a discovered resource. Skip wildcard `Resource: \"*\"` cases — the edge isn't specific enough to draw.\n")
	sb.WriteString("  • AppSync → Lambda / DynamoDB: from data source definitions in the GraphQL API.\n")
	sb.WriteString("  • SNS / SQS / EventBridge → Lambda subscriptions: from event source mappings or subscriptions.\n")
	sb.WriteString("  • RDS / DynamoDB → KMS CMK: when the database's `KmsKeyId` / `SSESpecification.KMSMasterKeyId` matches a discovered KMS key.\n\n")
	sb.WriteString("RULES for connections:\n")
	sb.WriteString("  (a) `from` and `to` must be the EXACT discovered URNs (the `urn` field on each resource). Do not invent or paraphrase URNs.\n")
	sb.WriteString("  (b) Skip the edge if either endpoint isn't in the discovered set.\n")
	sb.WriteString("  (c) `label` is a 1-3 word verb describing the flow (\"origin\", \"invokes\", \"reads\", \"writes\", \"publishes to\", \"encrypts\"). Keep it short — it overlays the arrow on the diagram.\n")
	sb.WriteString("  (d) Don't emit duplicate edges (same from+to+label). Don't emit edges between resources in the same Component the audit already groups together (those are implicit).\n")
	sb.WriteString("  (e) When uncertain, OMIT the edge. A clean smaller graph beats a noisy speculative one.\n\n")

	sb.WriteString("Return a single JSON object:\n")
	sb.WriteString(`{"findings":[{"rule_id":"…","title":"…","description":"…","severity":"critical|high|warning|info","resource":"…","service":"…","remediation":"…","file":"","line":0,"cb_source":{"tool":"…","key":"…","snippet":"…"}}],"connections":[{"from":"<urn>","to":"<urn>","label":"…"}]}`)
	sb.WriteString("\n\nOnly emit JSON. No commentary, no code fences. If you find nothing return {\"findings\":[],\"connections\":[]}.\n\n")

	sb.WriteString("SEVERITY SCALE — rate every finding on CloudBooster's operator-facing 5-bucket scale (CRITICAL > HIGH > MEDIUM > LOW > INFO), then emit the mapped wire value. The emitted `severity` MUST be one of the four strings `critical|high|warning|info`; `MEDIUM` maps to `warning` and `LOW`/`INFO` both map to `info`. Anchor to the WORST plausible outcome of the SPECIFIC condition, not the service's reputation:\n")
	sb.WriteString("  • CRITICAL → `critical`: account-takeover or direct data exposure — full-admin / wildcard IAM grant, a public data store reachable from the internet, plaintext secret material, an unauthenticated public entrypoint to an admin-privileged backend.\n")
	sb.WriteString("  • HIGH → `high`: a serious security / compliance gap that is not yet an active breach — at-rest encryption disabled, a configured audit/threat-detection service left blind (CloudTrail without KMS, ECS Exec unlogged, AWS Config not recording IAM/global types, a suspended GuardDuty detector), ECR MUTABLE image tags, an EC2 instance still accepting IMDSv1, an IAM role trusting another account with no ExternalId, a database flagged publicly-accessible but currently kept private by routing.\n")
	sb.WriteString("  • MEDIUM → `warning`: operational-resilience / hygiene gaps with a bounded blast radius — missing DLQ or reserved concurrency, no VPC flow logs, Container Insights off, no lifecycle / rotation / PITR, single-AZ, no access logging.\n")
	sb.WriteString("  • LOW / INFO → `info`: informational or best-practice nudges with no direct exposure (e.g. intent-scoped S3 hygiene recommendations).\n")
	sb.WriteString("Do NOT inflate a hygiene gap to `high`, and do NOT deflate an account-takeover gap to `warning`. When a per-rule instruction elsewhere in this prompt names an explicit severity for a specific condition, that instruction WINS over this general rubric.\n\n")

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

// Caps for the grounded prompt's resource table — the live-AWS analog
// of the source-mode caps in llm_files.go (defaultLLMMaxFiles /
// defaultLLMMaxBytesPerFile). Without them writeResourceTable inlines
// every discovered resource's full Inputs unbounded, and a large
// account silently blows the model's context with no signal to the
// user. When either cap trips, the sorted tail is dropped and the
// truncation is surfaced as an LLM-CB-TRUNCATED finding plus a stderr
// warning (see truncationFinding).
const (
	defaultLLMMaxPromptResources    = 500
	defaultLLMMaxResourceTableBytes = 1 << 20 // 1 MiB of serialised Inputs
)

// promptResourceEntry pairs a resource with its pre-serialised Inputs
// payload so the byte budget is enforced on exactly the bytes that end
// up in the prompt.
type promptResourceEntry struct {
	resource DiscoveredResource
	payload  string
}

// capPromptResources sorts resources into the prompt's stable order
// (URN, Region, Type), serialises each Inputs map, and applies the
// resource-count and byte caps above. It returns the kept prefix (in
// prompt order, payloads attached) and the number of resources omitted.
// Truncation is deterministic: the sort is stable and the caps cut a
// strict prefix, so two runs over the same account drop the same tail.
// At least one resource is always kept so a single oversized resource
// can't blank the whole table.
func capPromptResources(resources []DiscoveredResource) ([]promptResourceEntry, int) {
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

	kept := make([]promptResourceEntry, 0, len(sorted))
	totalBytes := 0
	for i, r := range sorted {
		if len(kept) >= defaultLLMMaxPromptResources {
			return kept, len(sorted) - i
		}
		payload := serialiseInputs(r.Inputs)
		if len(kept) > 0 && totalBytes+len(payload) > defaultLLMMaxResourceTableBytes {
			return kept, len(sorted) - i
		}
		totalBytes += len(payload)
		kept = append(kept, promptResourceEntry{resource: r, payload: payload})
	}
	return kept, 0
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
//
// The table is budgeted via capPromptResources: past the count/byte
// caps the sorted tail is dropped and an explicit TRUNCATED marker is
// written so the model knows the inventory is partial. The analyzer
// surfaces the same omission to the user as an LLM-CB-TRUNCATED
// finding.
func writeResourceTable(sb *strings.Builder, resources []DiscoveredResource) {
	if len(resources) == 0 {
		return
	}
	kept, omitted := capPromptResources(resources)
	sb.WriteString("==== DISCOVERED RESOURCES ====\n")
	for _, e := range kept {
		r := e.resource
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
		if e.payload != "" {
			sb.WriteString(e.payload)
			sb.WriteString("\n")
		}
	}
	if omitted > 0 {
		fmt.Fprintf(sb, "---- TRUNCATED: %d additional resources omitted to fit the prompt budget (%d resources / %d bytes) — this inventory is PARTIAL ----\n",
			omitted, defaultLLMMaxPromptResources, defaultLLMMaxResourceTableBytes)
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
	Findings    []llmRawFinding    `json:"findings"`
	Connections []llmRawConnection `json:"connections,omitempty"`
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

type llmRawConnection struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Label string `json:"label,omitempty"`
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

// parseLLMConnections extracts the `connections` array from the same
// JSON envelope the grounded prompt now asks for. Returns nil when
// the field is absent or empty; tolerates the same fenced / prose
// wrappers parseLLMFindings handles.
//
// Connections with the same endpoint URN on both sides are dropped
// (self-loops add noise), as are entries missing either URN.
func parseLLMConnections(raw string) []LLMConnection {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
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
		if m := jsonBlockRe.FindString(raw); m != "" {
			jsonBlob = m
		} else {
			return nil
		}
	}
	var parsed llmRawResponse
	if err := json.Unmarshal([]byte(jsonBlob), &parsed); err != nil {
		return nil
	}
	out := make([]LLMConnection, 0, len(parsed.Connections))
	for _, c := range parsed.Connections {
		if c.From == "" || c.To == "" || c.From == c.To {
			continue
		}
		out = append(out, LLMConnection(c))
	}
	return out
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
