// Package rulesbundletest builds small synthetic rule packs for unit
// tests.
//
// The production pack is API-distributed (platform-app serves it at
// GET /v1/knowledge/aws/rulepack) and deliberately does NOT live in
// this repo — unit tests must not depend on production rule content,
// only on the machinery (schema validation, render determinism, the
// resolve ladder, caching). The packs built here satisfy every
// rulesbundle.Validate invariant while being unmistakably fake; the
// served pack's contract is exercised by the e2e_staging tier instead.
package rulesbundletest

import (
	"encoding/json"
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/rulesbundle"
)

// Pack returns the canonical synthetic pack: three rules (one of them
// a mega-block with sub_items and a cross_ref), the three required
// meta blocks, and a severity rubric, with the manifest content hash
// computed so Validate passes.
func Pack(tb testing.TB) *rulesbundle.RulePack {
	return Build(tb, nil)
}

// Build returns the synthetic pack after applying mutate (nil = none)
// and recomputing the manifest content hash. The result must still
// validate — tests that need an INVALID pack should corrupt the bytes
// from MarshalArtifact instead.
func Build(tb testing.TB, mutate func(*rulesbundle.RulePack)) *rulesbundle.RulePack {
	tb.Helper()
	p := base()
	if mutate != nil {
		mutate(p)
	}
	hash, err := p.CanonicalHash()
	if err != nil {
		tb.Fatalf("rulesbundletest: canonical hash: %v", err)
	}
	p.Manifest.ContentSHA256 = hash
	if err := p.Validate(); err != nil {
		tb.Fatalf("rulesbundletest: synthetic pack does not validate: %v", err)
	}
	return p
}

// MarshalArtifact serializes a pack as the registry/override-file
// artifact bytes: rulesbundle.Parse(MarshalArtifact(tb, p)) yields a
// pack equal to p.
func MarshalArtifact(tb testing.TB, p *rulesbundle.RulePack) []byte {
	tb.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		tb.Fatalf("rulesbundletest: marshal: %v", err)
	}
	return raw
}

// base is the fixture content. Prose is prefixed SYNTHETIC so any leak
// into a real prompt or report is immediately recognizable. Rule IDs
// must match rulesbundle's ^CB-AWS-… pattern and the manifest must
// claim pack "cb-aws-audit" — both are schema invariants, not content.
func base() *rulesbundle.RulePack {
	return &rulesbundle.RulePack{
		Manifest: rulesbundle.Manifest{
			SchemaVersion: 1,
			Pack:          "cb-aws-audit",
			PackVersion:   1,
			Channel:       "stable",
			CreatedAt:     "2026-01-01T00:00:00Z",
			WireContract: rulesbundle.WireContract{
				Severities:     append([]string(nil), rulesbundle.WireSeverities...),
				ResponseSchema: rulesbundle.ResponseSchemaVersion,
			},
		},
		Rules: []rulesbundle.Rule{
			{
				ID:         "CB-AWS-TEST-ALPHA",
				Title:      "Synthetic alpha rule",
				Severity:   "high",
				Group:      "test",
				Order:      1,
				PromptText: "- SYNTHETIC-ALPHA: flag the alpha condition (fixture rule, never ships).\n",
			},
			{
				ID:         "CB-AWS-TEST-BRAVO",
				Title:      "Synthetic bravo mega-block",
				Group:      "test",
				Order:      2,
				PromptText: "- SYNTHETIC-BRAVO: a mega-block whose sub-items share one FP guard:\n",
				SubItems: []string{
					"  - bravo sub-item one (fires only on explicit false).\n",
					"  - bravo sub-item two (skip when the field is absent).\n",
				},
				CrossRefs: []string{"CB-AWS-TEST-ALPHA"},
			},
			{
				ID:         "CB-AWS-TEST-CHARLIE",
				Title:      "Synthetic charlie rule",
				Severity:   "info",
				Group:      "zz-tail",
				Order:      1,
				PromptText: "- SYNTHETIC-CHARLIE: tail-group rule pinning (group, order) sort.\n",
			},
		},
		MetaBlocks: []rulesbundle.MetaBlock{
			{ID: "baseline-rules-intro", PromptText: "SYNTHETIC baseline rules intro.\n"},
			{ID: "baseline-rules-outro", PromptText: "SYNTHETIC baseline rules outro.\n"},
			{ID: "no-merge-orthogonal", PromptText: "SYNTHETIC: do not merge orthogonal issues.\n"},
		},
		SeverityRubric: rulesbundle.SeverityRubric{
			PromptText: "SYNTHETIC severity rubric: critical > high > warning > info.\n",
		},
	}
}
