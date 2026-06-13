// Package rulesbundle holds the CB AWS audit rule pack: the prompt
// policy text (rule bullets, orthogonality guidance, severity rubric)
// that buildGroundedPrompt inlines into the grounded LLM prompt,
// wrapped in a versioned, validated JSON envelope.
//
// The pack is API-distributed: the registry (platform-app's
// GET /v1/knowledge/aws/rulepack) is the sole content source, resolved
// through the override → network → cache ladder in resolve.go. No copy
// of the production pack lives in this repo — unit tests run against
// the synthetic fixture pack in rulesbundletest, and the served pack's
// contract is exercised by the e2e_staging tier.
//
// Governing principle (plan §B.1): the prose IS the recall. The
// machine-readable fields on Rule (severity, selectors, requires_fields,
// refs, cross_refs, tags) are metadata for validation/provenance/CI
// only — they do not filter the prompt and do not gate findings. Render
// reproduces the pack's canonical byte stream exactly; the prompt
// golden test pins that property.
package rulesbundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/mod/semver"
)

// WireSeverities is the canonical wire vocabulary the audit engine's
// severity parser (internal/audit clampSeverity) speaks, in canonical
// order. A pack whose wire_contract does not match exactly is rejected
// at load — a bundle the engine can't speak must never be half-applied.
// internal/audit pins the equivalence with its own severity constants
// in a test.
var WireSeverities = []string{"critical", "high", "warning", "info"}

// ResponseSchemaVersion is the JSON response contract version the
// engine's parseLLMFindings/parseLLMConnections implement.
const ResponseSchemaVersion = 1

// Section identifies one renderable section of the pack. Each value
// corresponds to a contiguous block of the grounded prompt that moved
// out of buildGroundedPrompt (source line ranges at main@1eacc58).
type Section string

const (
	// SectionBaselineRules is the "Reasoning rules" item 1 block:
	// intro line + the pack's rule bullets (with sub-items, count is
	// server-owned) + outro line
	// (llm_analyzer.go:604–675).
	SectionBaselineRules Section = "baseline_rules"
	// SectionOrthogonality is the "DO NOT MERGE ORTHOGONAL ISSUES"
	// item 2 block (llm_analyzer.go:676–680).
	SectionOrthogonality Section = "orthogonality"
	// SectionSeverityRubric is the 5-bucket severity scale block
	// (llm_analyzer.go:705–710).
	SectionSeverityRubric Section = "severity_rubric"
)

// Meta-block ids the schema-1 renderer requires. Validate enforces the
// exact set: a pack missing one cannot render, and an unknown id would
// silently never render — both are rejected.
const (
	metaBaselineIntro     = "baseline-rules-intro"
	metaBaselineOutro     = "baseline-rules-outro"
	metaNoMergeOrthogonal = "no-merge-orthogonal"
)

// WireContract declares what the pack expects the engine to speak. It
// is validated against the compiled-in vocabulary at load.
type WireContract struct {
	Severities     []string `json:"severities"`
	ResponseSchema int      `json:"response_schema"`
}

// Manifest carries the pack's identity, versioning, and integrity
// metadata.
type Manifest struct {
	SchemaVersion    int    `json:"schema_version"`
	Pack             string `json:"pack"`
	PackVersion      int    `json:"pack_version"`
	Channel          string `json:"channel,omitempty"`
	KBVersion        int    `json:"kb_version,omitempty"`
	MinEngineVersion string `json:"min_engine_version,omitempty"`
	CreatedAt        string `json:"created_at,omitempty"`
	// ContentSHA256 is the canonical hash over the rendered sections in
	// order (see RulePack.CanonicalHash) — a self-check against
	// corruption, truncation, and editor reflow of the prose payload.
	ContentSHA256 string       `json:"content_sha256"`
	WireContract  WireContract `json:"wire_contract"`
}

// Ref names a compliance-framework control the rule maps to (CIS,
// FSBP, …). Provenance metadata only.
type Ref struct {
	Framework string `json:"framework"`
	ID        string `json:"id"`
}

// Selectors scopes a rule to resource shapes. Metadata in schema 1 —
// it does NOT filter the prompt.
type Selectors struct {
	CFNTypes []string `json:"cfn_types,omitempty"`
}

// Rule is one top-level prompt bullet. Mega-blocks (several items
// sharing one FP guard) are a single Rule with SubItems — splitting
// them would sever the shared guard from the items it protects.
//
// PromptText and SubItems are byte-for-byte payload (leading
// whitespace, bullet glyphs, trailing newline included); everything
// else is inert metadata in schema 1.
type Rule struct {
	ID    string `json:"id"`
	Title string `json:"title,omitempty"`
	// Severity is the wire severity the prose explicitly names for the
	// rule's finding, or "" when the prose decides per-condition
	// (mixed-severity mega-blocks, posture-dependent rules).
	Severity       string    `json:"severity,omitempty"`
	Group          string    `json:"group"`
	Order          int       `json:"order"`
	Selectors      Selectors `json:"selectors"`
	RequiresFields []string  `json:"requires_fields,omitempty"`
	Refs           []Ref     `json:"refs,omitempty"`
	PromptText     string    `json:"prompt_text"`
	SubItems       []string  `json:"sub_items,omitempty"`
	// CrossRefs names the rules this rule's prose references
	// positionally ("above"/"below", "mirrors …"). Ordering is
	// knowledge: re-orders that break a referent are a CI concern.
	CrossRefs []string `json:"cross_refs,omitempty"`
	Tags      []string `json:"tags,omitempty"`
}

// MetaBlock is a non-rule prose block (section intro/outro, the
// no-merge-orthogonal guidance).
type MetaBlock struct {
	ID         string `json:"id"`
	PromptText string `json:"prompt_text"`
}

// SeverityRubric is the severity-scale prose block.
type SeverityRubric struct {
	PromptText string `json:"prompt_text"`
}

// RulePack is the full bundle envelope (plan §B.1, schema_version 1).
type RulePack struct {
	Manifest       Manifest       `json:"manifest"`
	Rules          []Rule         `json:"rules"`
	MetaBlocks     []MetaBlock    `json:"meta_blocks"`
	SeverityRubric SeverityRubric `json:"severity_rubric"`
}

// Parse unmarshals and validates a rule pack. The returned pack is
// safe to Render.
func Parse(data []byte) (*RulePack, error) {
	var p RulePack
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("rulesbundle: parse: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

var ruleIDPattern = regexp.MustCompile(`^CB-AWS-[A-Z0-9]+(-[A-Z0-9]+)*$`)

// Validate checks the pack's structural invariants: manifest identity,
// wire-contract compatibility with the compiled engine, exactly the
// known meta-block sections, unique rule ids, unique (group, order),
// newline-terminated prose, resolvable cross-refs, and the canonical
// content hash. A pack that fails here must never reach the prompt.
func (p *RulePack) Validate() error {
	m := p.Manifest
	if m.SchemaVersion != 1 {
		return fmt.Errorf("rulesbundle: unsupported schema_version %d (engine speaks 1)", m.SchemaVersion)
	}
	if m.Pack != "cb-aws-audit" {
		return fmt.Errorf("rulesbundle: unexpected pack %q (want cb-aws-audit)", m.Pack)
	}
	if m.PackVersion < 1 {
		return fmt.Errorf("rulesbundle: invalid pack_version %d", m.PackVersion)
	}
	if m.MinEngineVersion != "" && !semver.IsValid(ensureV(m.MinEngineVersion)) {
		return fmt.Errorf("rulesbundle: invalid min_engine_version %q (want semver)", m.MinEngineVersion)
	}

	// Wire contract: exact match against the engine vocabulary, in
	// canonical order. Order-sensitive on purpose — a permuted list is
	// a hand-edited artifact, which is exactly what should fail loudly.
	if len(m.WireContract.Severities) != len(WireSeverities) {
		return fmt.Errorf("rulesbundle: wire_contract severities %v do not match engine vocabulary %v", m.WireContract.Severities, WireSeverities)
	}
	for i, s := range m.WireContract.Severities {
		if s != WireSeverities[i] {
			return fmt.Errorf("rulesbundle: wire_contract severities %v do not match engine vocabulary %v", m.WireContract.Severities, WireSeverities)
		}
	}
	if m.WireContract.ResponseSchema != ResponseSchemaVersion {
		return fmt.Errorf("rulesbundle: wire_contract response_schema %d not supported (engine speaks %d)", m.WireContract.ResponseSchema, ResponseSchemaVersion)
	}

	// Exactly the known meta-block sections, each non-empty.
	want := map[string]bool{metaBaselineIntro: false, metaBaselineOutro: false, metaNoMergeOrthogonal: false}
	for _, b := range p.MetaBlocks {
		seen, known := want[b.ID]
		if !known {
			return fmt.Errorf("rulesbundle: unknown meta_block id %q", b.ID)
		}
		if seen {
			return fmt.Errorf("rulesbundle: duplicate meta_block id %q", b.ID)
		}
		if b.PromptText == "" {
			return fmt.Errorf("rulesbundle: meta_block %q has empty prompt_text", b.ID)
		}
		want[b.ID] = true
	}
	for id, seen := range want {
		if !seen {
			return fmt.Errorf("rulesbundle: missing required meta_block %q", id)
		}
	}

	if len(p.Rules) == 0 {
		return fmt.Errorf("rulesbundle: pack has no rules")
	}
	wireOK := make(map[string]bool, len(WireSeverities))
	for _, s := range WireSeverities {
		wireOK[s] = true
	}
	ids := make(map[string]bool, len(p.Rules))
	orders := make(map[string]bool, len(p.Rules))
	for _, r := range p.Rules {
		if !ruleIDPattern.MatchString(r.ID) {
			return fmt.Errorf("rulesbundle: rule id %q does not match %s", r.ID, ruleIDPattern)
		}
		if ids[r.ID] {
			return fmt.Errorf("rulesbundle: duplicate rule id %q", r.ID)
		}
		ids[r.ID] = true
		if r.Group == "" {
			return fmt.Errorf("rulesbundle: rule %s has empty group", r.ID)
		}
		key := fmt.Sprintf("%s\x00%d", r.Group, r.Order)
		if orders[key] {
			return fmt.Errorf("rulesbundle: duplicate (group, order) (%s, %d) on rule %s", r.Group, r.Order, r.ID)
		}
		orders[key] = true
		if r.Severity != "" && !wireOK[r.Severity] {
			return fmt.Errorf("rulesbundle: rule %s severity %q outside wire vocabulary %v", r.ID, r.Severity, WireSeverities)
		}
		if r.PromptText == "" || !strings.HasSuffix(r.PromptText, "\n") {
			return fmt.Errorf("rulesbundle: rule %s prompt_text must be non-empty and newline-terminated", r.ID)
		}
		for i, s := range r.SubItems {
			if s == "" || !strings.HasSuffix(s, "\n") {
				return fmt.Errorf("rulesbundle: rule %s sub_items[%d] must be non-empty and newline-terminated", r.ID, i)
			}
		}
	}
	for _, r := range p.Rules {
		for _, ref := range r.CrossRefs {
			if !ids[ref] {
				return fmt.Errorf("rulesbundle: rule %s cross_refs unknown rule %q", r.ID, ref)
			}
		}
	}

	if p.SeverityRubric.PromptText == "" {
		return fmt.Errorf("rulesbundle: empty severity_rubric")
	}

	// Content self-check: the manifest hash must match the canonical
	// hash of the rendered sections. Catches corruption/truncation and
	// any reflow of the prose payload.
	got, err := p.CanonicalHash()
	if err != nil {
		return err
	}
	if !strings.EqualFold(m.ContentSHA256, got) {
		return fmt.Errorf("rulesbundle: content_sha256 mismatch: manifest=%s computed=%s", m.ContentSHA256, got)
	}
	return nil
}

// Render returns the canonical prompt text for one section,
// byte-identical to the sb.WriteString stream the prose was extracted
// from. The pack must have passed Validate (Parse guarantees this);
// rendering an unknown section panics — sections are
// compile-time constants, so that is a programmer error, and an empty
// string fallback would silently gut the prompt's recall.
func (p *RulePack) Render(section Section) string {
	out, err := p.renderSection(section)
	if err != nil {
		panic(err)
	}
	return out
}

func (p *RulePack) renderSection(section Section) (string, error) {
	switch section {
	case SectionBaselineRules:
		intro, err := p.metaBlock(metaBaselineIntro)
		if err != nil {
			return "", err
		}
		outro, err := p.metaBlock(metaBaselineOutro)
		if err != nil {
			return "", err
		}
		var sb strings.Builder
		sb.WriteString(intro)
		for _, r := range p.sortedRules() {
			sb.WriteString(r.PromptText)
			for _, s := range r.SubItems {
				sb.WriteString(s)
			}
		}
		sb.WriteString(outro)
		return sb.String(), nil
	case SectionOrthogonality:
		return p.metaBlock(metaNoMergeOrthogonal)
	case SectionSeverityRubric:
		if p.SeverityRubric.PromptText == "" {
			return "", fmt.Errorf("rulesbundle: empty severity_rubric")
		}
		return p.SeverityRubric.PromptText, nil
	}
	return "", fmt.Errorf("rulesbundle: unknown section %q", section)
}

// CanonicalHash computes the sha256 (lowercase hex) over the rendered
// sections in canonical order: baseline rules, orthogonality, severity
// rubric. This is the value Manifest.ContentSHA256 must carry.
func (p *RulePack) CanonicalHash() (string, error) {
	h := sha256.New()
	for _, s := range []Section{SectionBaselineRules, SectionOrthogonality, SectionSeverityRubric} {
		out, err := p.renderSection(s)
		if err != nil {
			return "", err
		}
		h.Write([]byte(out))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (p *RulePack) metaBlock(id string) (string, error) {
	for _, b := range p.MetaBlocks {
		if b.ID == id {
			if b.PromptText == "" {
				return "", fmt.Errorf("rulesbundle: meta_block %q has empty prompt_text", id)
			}
			return b.PromptText, nil
		}
	}
	return "", fmt.Errorf("rulesbundle: missing meta_block %q", id)
}

// sortedRules returns the rules in render order — (group, order)
// ascending, the pack's explicit total order. The slice is a copy; the
// pack itself is never mutated by rendering.
func (p *RulePack) sortedRules() []Rule {
	out := append([]Rule(nil), p.Rules...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Group != out[j].Group {
			return out[i].Group < out[j].Group
		}
		return out[i].Order < out[j].Order
	})
	return out
}
