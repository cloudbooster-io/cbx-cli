package audit

import (
	"context"
	"strings"
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/rulesbundle"
)

// rulePackTestEnv isolates the process memo and the on-disk cache for
// one test: fresh memo, temp XDG cache, cleared override envs.
func rulePackTestEnv(t *testing.T) {
	t.Helper()
	resetRulePackForTests()
	t.Cleanup(resetRulePackForTests)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("CBX_AUDIT_RULES_FILE", "")
	t.Setenv("CBX_RULEPACK_VERSION", "")
	t.Setenv("CBX_RULEPACK_CHANNEL", "")
}

// TestCurrentRulePackOfflineAndMemoized: the analyzer-side accessor
// never dials out — on a cold start with no cache it lands on the
// embedded pack — and the resolution is memoized process-wide.
func TestCurrentRulePackOfflineAndMemoized(t *testing.T) {
	rulePackTestEnv(t)

	pack, prov, err := currentRulePack(context.Background())
	if err != nil {
		t.Fatalf("currentRulePack: %v", err)
	}
	if prov.Source != "embedded" {
		t.Errorf("source = %q, want embedded (no network rung on the analyzer path)", prov.Source)
	}
	pack2, _, err := currentRulePack(context.Background())
	if err != nil {
		t.Fatalf("second currentRulePack: %v", err)
	}
	if pack2 != pack {
		t.Error("resolution not memoized — second call returned a different pack")
	}
}

// TestResolveRulePackEnvPin: CBX_RULEPACK_VERSION drives the pin when
// no flag value is passed; malformed and unsatisfiable values abort.
func TestResolveRulePackEnvPin(t *testing.T) {
	rulePackTestEnv(t)
	t.Setenv("CBX_RULEPACK_VERSION", "1")
	_, prov, err := ResolveRulePack(context.Background(), 0)
	if err != nil {
		t.Fatalf("pin=1 via env: %v", err)
	}
	if prov.PinnedVersion != 1 {
		t.Errorf("PinnedVersion = %d, want 1", prov.PinnedVersion)
	}

	resetRulePackForTests()
	t.Setenv("CBX_RULEPACK_VERSION", "99")
	if _, _, err := ResolveRulePack(context.Background(), 0); err == nil {
		t.Fatal("unsatisfiable env pin resolved")
	}

	resetRulePackForTests()
	t.Setenv("CBX_RULEPACK_VERSION", "latest")
	if _, _, err := ResolveRulePack(context.Background(), 0); err == nil || !strings.Contains(err.Error(), "CBX_RULEPACK_VERSION") {
		t.Fatalf("err = %v, want malformed-env abort", err)
	}

	// Abort-class failures must NOT memoize: a fixed env resolves fresh.
	t.Setenv("CBX_RULEPACK_VERSION", "")
	if _, _, err := ResolveRulePack(context.Background(), 0); err != nil {
		t.Fatalf("recovery after bad env: %v", err)
	}
}

// TestAppendRulesProvenanceFindings drives the meta-finding trio off
// provenance variants.
func TestAppendRulesProvenanceFindings(t *testing.T) {
	byID := func(fs []Finding) map[string]Finding {
		out := map[string]Finding{}
		for _, f := range fs {
			out[f.RuleID] = f
		}
		return out
	}

	t.Run("zero-value-provenance-is-silent", func(t *testing.T) {
		l := &llmAnalyzer{providerForRuleID: "claudecode"}
		if got := l.appendRulesProvenanceFindings(nil); len(got) != 0 {
			t.Fatalf("got %d findings for a zero-value provenance, want 0", len(got))
		}
	})

	t.Run("clean-embedded-emits-provenance-only", func(t *testing.T) {
		l := &llmAnalyzer{
			providerForRuleID: "claudecode",
			rules:             rulesbundle.Embedded(),
			rulesProv: rulesbundle.Provenance{
				Source: "embedded", PackVersion: 1, SchemaVersion: 1,
				ContentSHA256: rulesbundle.Embedded().Manifest.ContentSHA256,
			},
		}
		got := byID(l.appendRulesProvenanceFindings(nil))
		if len(got) != 1 {
			t.Fatalf("got %d findings, want 1 (provenance only): %v", len(got), got)
		}
		p, ok := got["LLM-CB-RULES-PROVENANCE"]
		if !ok {
			t.Fatal("missing LLM-CB-RULES-PROVENANCE")
		}
		if p.Severity != SeverityInfo {
			t.Errorf("provenance severity = %s, want info (must stay below the FP bar)", p.Severity)
		}
		if !strings.Contains(p.Description, "embedded") || !strings.Contains(p.Description, "version 1") {
			t.Errorf("provenance description lacks pack identity: %q", p.Description)
		}
	})

	t.Run("degraded-and-stale-emit-warning", func(t *testing.T) {
		l := &llmAnalyzer{
			providerForRuleID: "claudecode",
			rules:             rulesbundle.Embedded(),
			rulesProv: rulesbundle.Provenance{
				Source: "cache", PackVersion: 1, SchemaVersion: 1,
				ContentSHA256: rulesbundle.Embedded().Manifest.ContentSHA256,
				Degraded:      true, Stale: true,
				FetchError: "dial tcp: connection refused",
				FetchedAt:  "2026-06-01T00:00:00Z",
			},
		}
		got := byID(l.appendRulesProvenanceFindings(nil))
		s, ok := got["LLM-CB-RULES-STALE"]
		if !ok {
			t.Fatal("missing LLM-CB-RULES-STALE on a degraded+stale provenance")
		}
		if s.Severity != SeverityWarning {
			t.Errorf("stale severity = %s, want warning (exit-code-visible degradation)", s.Severity)
		}
		if !strings.Contains(s.Description, "connection refused") || !strings.Contains(s.Description, "2026-06-01") {
			t.Errorf("stale description lacks the why: %q", s.Description)
		}
	})

	t.Run("pack-ahead-of-engine-emits-info", func(t *testing.T) {
		pack := *rulesbundle.Embedded()
		rules := append([]rulesbundle.Rule(nil), pack.Rules...)
		rules[0].RequiresFields = append(append([]string(nil), rules[0].RequiresFields...),
			"cb_describer_field_from_the_future")
		pack.Rules = rules
		l := &llmAnalyzer{
			providerForRuleID: "claudecode",
			rules:             &pack,
			rulesProv: rulesbundle.Provenance{
				Source: "network", PackVersion: 9, SchemaVersion: 1, ContentSHA256: "abc",
			},
		}
		got := byID(l.appendRulesProvenanceFindings(nil))
		a, ok := got["LLM-CB-RULES-AHEAD"]
		if !ok {
			t.Fatal("missing LLM-CB-RULES-AHEAD")
		}
		if a.Severity != SeverityInfo {
			t.Errorf("ahead severity = %s, want info", a.Severity)
		}
		if !strings.Contains(a.Description, "cb_describer_field_from_the_future") ||
			!strings.Contains(a.Description, rules[0].ID) {
			t.Errorf("ahead description lacks rule/field detail: %q", a.Description)
		}
	})
}

// TestReportHeaderNamesRulePack: the markdown report header carries the
// rulepack provenance line when the context has one, and stays
// byte-identical to the old header when it doesn't.
func TestReportHeaderNamesRulePack(t *testing.T) {
	result := &Result{}
	base := AWSAuditContext{AccountID: "123456789012", Identity: "arn:aws:iam::123456789012:user/audit", Regions: []string{"eu-central-1"}}

	without := RenderAWSMarkdown(result, base)
	if strings.Contains(without, "**Rules**") {
		t.Error("header emitted a Rules line with no provenance on the context")
	}

	withPack := base
	withPack.RulePack = &rulesbundle.Provenance{
		Source: "embedded", PackVersion: 1, SchemaVersion: 1,
		ContentSHA256: "00218e44e3cd921582fc6c88912613a5bef4cbb76b5636483d3e3c94086fecf5",
	}
	md := RenderAWSMarkdown(result, withPack)
	if !strings.Contains(md, "> **Rules** pack v1 (schema 1)  ·  source `embedded`  ·  `00218e44e3cd`") {
		t.Errorf("header lacks the rulepack provenance line:\n%s", md[:min(len(md), 600)])
	}

	degraded := withPack
	prov := *withPack.RulePack
	prov.Stale = true
	degraded.RulePack = &prov
	if !strings.Contains(RenderAWSMarkdown(result, degraded), "LLM-CB-RULES-STALE") {
		t.Error("degraded header lacks the stale marker")
	}
}
