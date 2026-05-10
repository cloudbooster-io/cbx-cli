package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/core/plan"
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
}

// newLLMAnalyzer wires a Stream-based analyzer against the user's logged-in
// provider. Returns an error when the provider isn't configured — caller
// should surface that to the user as "run cbx llm login <provider> first".
func newLLMAnalyzer(opts Options, iacType string) (*llmAnalyzer, error) {
	if opts.LLMProvider == "" {
		return nil, fmt.Errorf("llm analyzer: empty provider")
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

	prompt := buildLLMPrompt(l.iacType, files)

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
	return findings, nil
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
	RuleID      string `json:"rule_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Resource    string `json:"resource"`
	Service     string `json:"service"`
	Remediation string `json:"remediation"`
	File        string `json:"file"`
	Line        int    `json:"line"`
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
		findings = append(findings, Finding{
			RuleID:      ruleID,
			Title:       r.Title,
			Description: r.Description,
			Severity:    clampSeverity(r.Severity),
			Resource:    r.Resource,
			Service:     r.Service,
			Remediation: r.Remediation,
			File:        r.File,
			Line:        r.Line,
		})
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
