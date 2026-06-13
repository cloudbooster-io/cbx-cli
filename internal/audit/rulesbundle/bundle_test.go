package rulesbundle_test

import (
	"strings"
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/rulesbundle"
	"github.com/cloudbooster-io/cbx-cli/internal/audit/rulesbundle/rulesbundletest"
)

// TestSyntheticPackRenders pins the rendering machinery against the
// synthetic fixture pack — the production pack is API-distributed and
// no longer lives in this repo, so the unit-testable surface is the
// renderer's composition contract, not production content: intro, then
// rules in (group, order), each mega-block's sub_items inline
// immediately after their parent rule (splitting them would sever the
// shared FP guard from the items it protects), then outro.
func TestSyntheticPackRenders(t *testing.T) {
	// Pack(t) validates inside Build — a broken fixture fails here, not
	// as a confusing mid-test render mismatch.
	p := rulesbundletest.Pack(t)

	rules := p.Render(rulesbundle.SectionBaselineRules)
	// Strictly increasing indexes pin presence AND order: ALPHA (test/1)
	// before BRAVO (test/2), BRAVO's sub-items between it and the next
	// rule, CHARLIE (zz-tail/1) last — the (group, order) total order.
	anchors := []string{
		"SYNTHETIC baseline rules intro.",
		"SYNTHETIC-ALPHA",
		"SYNTHETIC-BRAVO",
		"bravo sub-item one",
		"bravo sub-item two",
		"SYNTHETIC-CHARLIE",
		"SYNTHETIC baseline rules outro.",
	}
	prev := -1
	for _, anchor := range anchors {
		i := strings.Index(rules, anchor)
		if i < 0 {
			t.Fatalf("baseline_rules section missing anchor %q", anchor)
		}
		if i <= prev {
			t.Errorf("anchor %q renders out of order", anchor)
		}
		prev = i
	}

	// Declaration order must not leak into the render — reverse the
	// rules slice and the bytes must not move (sortedRules is the only
	// ordering authority; a pack author reordering JSON entries must not
	// be able to reshuffle the prompt).
	shuffled := rulesbundletest.Build(t, func(p *rulesbundle.RulePack) {
		for i, j := 0, len(p.Rules)-1; i < j; i, j = i+1, j-1 {
			p.Rules[i], p.Rules[j] = p.Rules[j], p.Rules[i]
		}
	})
	if shuffled.Render(rulesbundle.SectionBaselineRules) != rules {
		t.Error("render depends on rule declaration order, not (group, order)")
	}

	if ortho := p.Render(rulesbundle.SectionOrthogonality); !strings.Contains(ortho, "SYNTHETIC: do not merge orthogonal issues.") {
		t.Errorf("orthogonality section = %q, missing its prose", ortho)
	}
	if rubric := p.Render(rulesbundle.SectionSeverityRubric); !strings.Contains(rubric, "SYNTHETIC severity rubric") {
		t.Errorf("severity_rubric section = %q, missing its prose", rubric)
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
	rulesbundletest.Pack(t).Render(rulesbundle.Section("nope"))
}

// TestValidateRejections drives Validate through each rejection class.
// Pack(t) hands every subtest a fresh, fully validated deep copy, so
// the applied mutation is the single defect Validate sees.
func TestValidateRejections(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(p *rulesbundle.RulePack)
		wantErr string
	}{
		{"schema-version", func(p *rulesbundle.RulePack) { p.Manifest.SchemaVersion = 2 }, "schema_version"},
		{"pack-name", func(p *rulesbundle.RulePack) { p.Manifest.Pack = "cb-gcp-audit" }, "unexpected pack"},
		{"pack-version", func(p *rulesbundle.RulePack) { p.Manifest.PackVersion = 0 }, "invalid pack_version"},
		{"min-engine-version", func(p *rulesbundle.RulePack) { p.Manifest.MinEngineVersion = "latest" }, "min_engine_version"},
		// Order-sensitive on purpose: a permuted severity list is a
		// hand-edited artifact, which is exactly what should fail loudly.
		{"wire-severities-permuted", func(p *rulesbundle.RulePack) {
			s := p.Manifest.WireContract.Severities
			s[0], s[1] = s[1], s[0]
		}, "wire_contract severities"},
		{"wire-severities-vocabulary", func(p *rulesbundle.RulePack) {
			p.Manifest.WireContract.Severities = []string{"critical", "high", "medium", "info"}
		}, "wire_contract severities"},
		{"response-schema", func(p *rulesbundle.RulePack) { p.Manifest.WireContract.ResponseSchema = 2 }, "response_schema"},
		{"unknown-meta-block", func(p *rulesbundle.RulePack) {
			p.MetaBlocks = append(p.MetaBlocks, rulesbundle.MetaBlock{ID: "mystery", PromptText: "x\n"})
		}, "unknown meta_block"},
		{"duplicate-meta-block", func(p *rulesbundle.RulePack) { p.MetaBlocks = append(p.MetaBlocks, p.MetaBlocks[0]) }, "duplicate meta_block"},
		{"missing-meta-block", func(p *rulesbundle.RulePack) { p.MetaBlocks = p.MetaBlocks[:2] }, "missing required meta_block"},
		{"bad-rule-id", func(p *rulesbundle.RulePack) { p.Rules[0].ID = "cb-aws-lowercase" }, "does not match"},
		{"dup-rule-id", func(p *rulesbundle.RulePack) { p.Rules[1].ID = p.Rules[0].ID }, "duplicate rule id"},
		{"dup-group-order", func(p *rulesbundle.RulePack) { p.Rules[1].Order = p.Rules[0].Order }, "duplicate (group, order)"},
		{"bad-severity", func(p *rulesbundle.RulePack) { p.Rules[0].Severity = "medium" }, "outside wire vocabulary"},
		{"no-trailing-newline", func(p *rulesbundle.RulePack) {
			p.Rules[0].PromptText = strings.TrimSuffix(p.Rules[0].PromptText, "\n")
		}, "newline-terminated"},
		// Rules[1] is the BRAVO mega-block — the only rule with sub_items.
		{"sub-item-no-trailing-newline", func(p *rulesbundle.RulePack) {
			p.Rules[1].SubItems[0] = strings.TrimSuffix(p.Rules[1].SubItems[0], "\n")
		}, "sub_items[0]"},
		{"dangling-cross-ref", func(p *rulesbundle.RulePack) { p.Rules[0].CrossRefs = []string{"CB-AWS-NOT-A-RULE"} }, "cross_refs unknown rule"},
		{"empty-rubric", func(p *rulesbundle.RulePack) { p.SeverityRubric.PromptText = "" }, "severity_rubric"},
		// Newline-terminated so the prose change survives to the hash
		// check instead of tripping the formatting rule first.
		{"content-hash", func(p *rulesbundle.RulePack) { p.Rules[0].PromptText = "- SYNTHETIC reworded prose.\n" }, "content_sha256 mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := rulesbundletest.Pack(t)
			tc.mutate(p)
			err := p.Validate()
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
// the fixture pack (Validate already enforces this; the explicit test
// makes the invariant visible, and pins that the hash Build stamps is
// the one Validate recomputes).
func TestCanonicalHashMatchesManifest(t *testing.T) {
	p := rulesbundletest.Pack(t)
	got, err := p.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}
	if got != p.Manifest.ContentSHA256 {
		t.Fatalf("canonical hash %s != manifest content_sha256 %s", got, p.Manifest.ContentSHA256)
	}
}
