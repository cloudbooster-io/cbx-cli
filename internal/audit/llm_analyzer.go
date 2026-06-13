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

	"github.com/cloudbooster-io/cbx-cli/internal/audit/knowledge"
	"github.com/cloudbooster-io/cbx-cli/internal/audit/parsers"
	"github.com/cloudbooster-io/cbx-cli/internal/audit/rulesbundle"
	"github.com/cloudbooster-io/cbx-cli/internal/config"
	"github.com/cloudbooster-io/cbx-cli/internal/llm"
)

// llmStreamer is the minimal subset of internal/llm.Caller that the analyzer
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

	// rules is the resolved rule pack that grounds the prompt's policy
	// sections (see rulepack_resolve.go); rulesProv records which rung
	// of the resolve ladder served it, surfaced post-scan as the
	// LLM-CB-RULES-* meta-findings. The pack is API-distributed with no
	// embedded floor, so rules must be non-nil for grounded prompts —
	// buildPrompt panics otherwise. Zero-value rulesProv suppresses the
	// provenance findings (direct constructions have no ladder state to
	// report).
	rules     *rulesbundle.RulePack
	rulesProv rulesbundle.Provenance

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
// The CLI-executor provider names ClaudeCodeProvider ("claude-code") and
// CodexProvider ("codex") sidestep cbx's own credential handling entirely:
// they shell out to the local `claude` / `codex` CLI which authenticates as
// itself. No `cbx llm api login` required, no token stored by cbx. Both
// support the grounded `cbx audit aws` path; codex differs only in that it
// surfaces no per-run cost (--llm-max-cost is unenforced — see
// groundedCodexStreamer.TotalCostUSD).
func newLLMAnalyzer(opts Options, iacType string) (*llmAnalyzer, error) {
	if opts.LLMProvider == "" {
		return nil, fmt.Errorf("llm analyzer: empty provider")
	}

	if isCLIExecutorProvider(opts.LLMProvider) {
		label := ruleIDLabelFor(opts.LLMProvider)
		if opts.CBKnowledge {
			streamer, err := newGroundedCLIStreamer(opts.LLMProvider, opts.LLMModel)
			if err != nil {
				return nil, err
			}
			// Rule pack: the CLI preflight (pkg/cmd/audit_aws.go) already
			// resolved + memoized it pre-discovery; this returns the memo.
			// Library callers without that preflight resolve here WITHOUT
			// the network rung (override file → cache only — the pack is
			// API-distributed, no embedded floor) — see rulepack_resolve.go.
			// Failure is abort-class (broken override / unsatisfiable pin /
			// ladder exhausted), matching the streamer-preflight posture.
			rules, rulesProv, err := currentRulePack(context.Background())
			if err != nil {
				return nil, err
			}
			// LLMMaxCost semantics: 0 means "no cap" (no warning ever
			// emitted). The CLI default is 2.00 (set in audit_aws.go).
			// Library callers wiring Options directly take the field as
			// the literal cap; if they want the historical "use the
			// default" behavior they can pass 2.00 explicitly. Codex
			// reports no cost, so the cap is inert there regardless.
			return &llmAnalyzer{
				provider:          opts.LLMProvider,
				streamer:          streamer,
				maxFiles:          opts.LLMMaxFiles,
				maxBytesPerFile:   opts.LLMMaxBytesPerFile,
				iacType:           iacType,
				providerForRuleID: label,
				cbKnowledge:       true,
				maxCostUSD:        opts.LLMMaxCost,
				posture:           opts.AWSAccountPosture,
				rules:             rules,
				rulesProv:         rulesProv,
			}, nil
		}
		streamer, err := newCLIExecutorStreamer(opts.LLMProvider, opts.LLMModel)
		if err != nil {
			return nil, err
		}
		return &llmAnalyzer{
			provider:          opts.LLMProvider,
			streamer:          streamer,
			maxFiles:          opts.LLMMaxFiles,
			maxBytesPerFile:   opts.LLMMaxBytesPerFile,
			iacType:           iacType,
			providerForRuleID: label,
		}, nil
	}

	if opts.CBKnowledge {
		return nil, fmt.Errorf("--cb-knowledge requires --llm %s or %s (other providers don't have a grounded executor path)", ClaudeCodeProvider, CodexProvider)
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
	// inject it; llm.NewCaller doesn't read the keychain itself. A keyring
	// failure (including no stored token) is a constructor error — matching
	// the unconfigured-provider posture above — rather than a blank token
	// that would surface later as an opaque provider auth failure.
	llmToken, err := llm.GetToken(opts.LLMProvider)
	if err != nil {
		return nil, fmt.Errorf("llm analyzer: reading %q token from keyring: %w; run 'cbx llm api login %s' to store one", opts.LLMProvider, err, opts.LLMProvider)
	}

	// llm.Provider is the subset of config.LLMProvider the caller actually
	// reads — convert explicitly here at the composition root.
	prov := llm.Provider{
		Name:    provCfg.Name,
		BaseURL: provCfg.BaseURL,
		Model:   provCfg.Model,
	}

	return &llmAnalyzer{
		provider:          opts.LLMProvider,
		streamer:          llm.NewCaller(prov, llmToken),
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
		findings = l.appendRulesProvenanceFindings(findings)
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
		findings = l.appendRulesProvenanceFindings(findings)
	}
	return findings, nil
}

// postProcessGrounded threads the grounding trail (if the streamer surfaces
// one) into each Finding.CBSource, soft-warns ungrounded findings, and prints
// a stderr-only warning when the run exceeded --llm-max-cost. Returns the
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

	// Cost-cap breaches are operator diagnostics, not report content:
	// reports are shared artifacts and must not leak what the run cost.
	// Stderr-only, so the terminal user still sees it.
	if cost := trailer.TotalCostUSD(); l.maxCostUSD > 0 && cost > l.maxCostUSD {
		fmt.Fprintf(os.Stderr,
			"WARN: grounded audit cost $%.2f exceeded --llm-max-cost $%s; the run completed and findings are intact. Raise the cap or narrow the scope to spend less.\n",
			cost, formatCostCap(l.maxCostUSD),
		)
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
		if l.rules == nil {
			// newLLMAnalyzer always resolves a pack (and errors when it
			// can't); a nil pack here is a direct construction that
			// skipped resolution. The pack is API-distributed with no
			// embedded floor, so there is nothing to fall back to —
			// failing loud beats silently gutting the prompt's policy
			// sections (the false-green failure mode).
			panic("audit: grounded analyzer constructed without a rule pack (use newLLMAnalyzer, or set rules explicitly)")
		}
		return buildGroundedPrompt(l.iacType, files, resources, bundle, posture, l.rules)
	}
	return buildLLMPrompt(l.iacType, files)
}

// buildLLMPrompt assembles the user-side prompt. System prompt is set
// separately by callers that support it; internal/llm.Caller currently
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
// The policy prose — the baseline rule bullets, the no-merge-orthogonal
// block, and the severity rubric — comes from the resolved rules pack
// (API-distributed via /v1/knowledge/aws/rulepack, resolved through the
// override → network → cache ladder; see rulepack_resolve.go). rules
// must be non-nil and validated; Render reproduces the pack's canonical
// byte stream exactly, pinned by the prompt golden test against the
// synthetic fixture pack.
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
func buildGroundedPrompt(iacType string, files []SourceFile, resources []DiscoveredResource, bundle *GroundingBundle, posture *AccountPosture, rules *rulesbundle.RulePack) string {
	var sb strings.Builder
	sb.WriteString("You are CloudBooster's AWS security and architecture auditor.\n\n")
	sb.WriteString("You will be given: (a) a CB knowledge bundle with CloudBooster's curated AWS posture, (b) an account-posture block with account-level configuration, and (c) every discovered resource with its full deployed state (raw CFN Properties + describer enrichment).\n\n")
	sb.WriteString("DO NOT call any tools — none are available in this run.\n\n")
	sb.WriteString("Reasoning rules:\n")
	// Reasoning-rules item 1 (the 47 baseline rule bullets + sub-items,
	// intro/outro included) and item 2 (the DO-NOT-MERGE-ORTHOGONAL
	// block) render from the rule pack, byte-identical to the former
	// inline literals.
	sb.WriteString(rules.Render(rulesbundle.SectionBaselineRules))
	sb.WriteString(rules.Render(rulesbundle.SectionOrthogonality))
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

	sb.WriteString(rules.Render(rulesbundle.SectionSeverityRubric))

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
