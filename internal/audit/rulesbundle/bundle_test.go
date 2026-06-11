package rulesbundle

import (
	"strings"
	"testing"
)

// TestEmbeddedPackShape pins the structural facts of the P0 extraction:
// the embedded artifact parses, validates, and carries exactly the
// 47 top-level rules + 17 sub-items extracted from
// internal/audit/llm_analyzer.go:604–675 (main@1eacc58), plus the three
// known meta blocks and the severity rubric.
func TestEmbeddedPackShape(t *testing.T) {
	p := Embedded()

	if got := len(p.Rules); got != 47 {
		t.Errorf("embedded pack has %d rules, want 47", got)
	}
	subs := 0
	for _, r := range p.Rules {
		subs += len(r.SubItems)
	}
	if subs != 17 {
		t.Errorf("embedded pack has %d sub_items, want 17", subs)
	}
	if got := len(p.MetaBlocks); got != 3 {
		t.Errorf("embedded pack has %d meta_blocks, want 3", got)
	}

	// The mega-blocks must stay single rules with sub_items — splitting
	// would sever their shared FP guards from the items they protect.
	wantSubs := map[string]int{
		"CB-AWS-S3-HYGIENE":            7,
		"CB-AWS-BACKUP-VAULT-HYGIENE":  3,
		"CB-AWS-CLOUDFRONT-POSTURE":    4,
		"CB-AWS-ECS-CONTAINER-POSTURE": 3,
	}
	for _, r := range p.Rules {
		want := wantSubs[r.ID]
		if len(r.SubItems) != want {
			t.Errorf("rule %s has %d sub_items, want %d", r.ID, len(r.SubItems), want)
		}
	}
}

// TestEmbeddedRenderSections sanity-checks the rendered sections carry
// their load-bearing anchors. Exact bytes are pinned elsewhere (the
// prompt golden + content_sha256 + artifact SHA); this test exists so a
// failure names the broken section directly.
func TestEmbeddedRenderSections(t *testing.T) {
	p := Embedded()

	rules := p.Render(SectionBaselineRules)
	for _, anchor := range []string{
		"  1. Flag well-known AWS misconfigurations",      // intro
		"       • Security groups with 0.0.0.0/0 ingress", // first bullet
		"         – Versioning disabled",                  // S3 mega-block sub-item
		"     This list is NOT exhaustive",                // outro
	} {
		if !strings.Contains(rules, anchor) {
			t.Errorf("baseline_rules section missing anchor %q", anchor)
		}
	}

	ortho := p.Render(SectionOrthogonality)
	if !strings.Contains(ortho, "DO NOT MERGE ORTHOGONAL ISSUES") {
		t.Error("orthogonality section missing its header")
	}

	rubric := p.Render(SectionSeverityRubric)
	if !strings.Contains(rubric, "SEVERITY SCALE") || !strings.Contains(rubric, "per-rule instruction") {
		t.Error("severity_rubric section missing its anchors")
	}
}

// TestRenderUnknownSectionPanics: an unknown section must fail loudly —
// an empty-string fallback would silently gut the prompt's recall.
func TestRenderUnknownSectionPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Render(unknown) did not panic")
		}
	}()
	Embedded().Render(Section("nope"))
}

// TestValidateRejections drives Validate through each rejection class
// by mutating a copy of the embedded pack.
func TestValidateRejections(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(p *RulePack)
		wantErr string
	}{
		{"schema-version", func(p *RulePack) { p.Manifest.SchemaVersion = 2 }, "schema_version"},
		{"pack-name", func(p *RulePack) { p.Manifest.Pack = "cb-gcp-audit" }, "unexpected pack"},
		{"wire-severities", func(p *RulePack) { p.Manifest.WireContract.Severities = []string{"critical", "high", "medium", "info"} }, "wire_contract severities"},
		{"response-schema", func(p *RulePack) { p.Manifest.WireContract.ResponseSchema = 2 }, "response_schema"},
		{"unknown-meta-block", func(p *RulePack) { p.MetaBlocks = append(p.MetaBlocks, MetaBlock{ID: "mystery", PromptText: "x\n"}) }, "unknown meta_block"},
		{"missing-meta-block", func(p *RulePack) { p.MetaBlocks = p.MetaBlocks[:2] }, "missing required meta_block"},
		{"bad-rule-id", func(p *RulePack) { p.Rules[0].ID = "cb-aws-lowercase" }, "does not match"},
		{"dup-rule-id", func(p *RulePack) { p.Rules[1].ID = p.Rules[0].ID }, "duplicate rule id"},
		{"dup-group-order", func(p *RulePack) { p.Rules[1].Order = p.Rules[0].Order }, "duplicate (group, order)"},
		{"bad-severity", func(p *RulePack) { p.Rules[0].Severity = "medium" }, "outside wire vocabulary"},
		{"no-trailing-newline", func(p *RulePack) { p.Rules[0].PromptText = strings.TrimSuffix(p.Rules[0].PromptText, "\n") }, "newline-terminated"},
		{"dangling-cross-ref", func(p *RulePack) { p.Rules[0].CrossRefs = []string{"CB-AWS-NOT-A-RULE"} }, "cross_refs unknown rule"},
		{"empty-rubric", func(p *RulePack) { p.SeverityRubric.PromptText = "" }, "severity_rubric"},
		{"content-hash", func(p *RulePack) { p.Rules[0].PromptText = "       • Reworded prose.\n" }, "content_sha256 mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Re-parse for a deep, independent copy (rules slice and all).
			p, err := Parse(EmbeddedBytes())
			if err != nil {
				t.Fatalf("re-parse embedded: %v", err)
			}
			tc.mutate(p)
			err = p.Validate()
			if err == nil {
				t.Fatalf("Validate accepted a %s mutation", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestCanonicalHashMatchesManifest: the manifest self-check holds on
// the shipped artifact (Validate already enforces this; the explicit
// test makes the invariant visible).
func TestCanonicalHashMatchesManifest(t *testing.T) {
	p := Embedded()
	got, err := p.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}
	if got != p.Manifest.ContentSHA256 {
		t.Fatalf("canonical hash %s != manifest content_sha256 %s", got, p.Manifest.ContentSHA256)
	}
}
