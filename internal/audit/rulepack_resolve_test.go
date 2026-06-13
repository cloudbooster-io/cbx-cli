package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/rulesbundle"
	"github.com/cloudbooster-io/cbx-cli/internal/audit/rulesbundle/rulesbundletest"
)

// rulePackTestEnv isolates the process memo, the on-disk cache, and the
// override/pin envs for one test. CB_API_URL points at an unroutable
// address so a regression that re-enables the network rung on a test
// path fails fast instead of dialing production.
func rulePackTestEnv(t *testing.T) {
	t.Helper()
	resetRulePackForTests()
	t.Cleanup(resetRulePackForTests)
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("CBX_AUDIT_RULES_FILE", "")
	t.Setenv("CBX_RULEPACK_VERSION", "")
	t.Setenv("CBX_RULEPACK_CHANNEL", "")
	t.Setenv(cbAPIURLEnv, "http://127.0.0.1:0")
}

// writeOverrideFile materialises a pack as a CBX_AUDIT_RULES_FILE
// artifact and points the env at it.
func writeOverrideFile(t *testing.T, pack *rulesbundle.RulePack) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rulepack.json")
	if err := os.WriteFile(path, rulesbundletest.MarshalArtifact(t, pack), 0o644); err != nil {
		t.Fatalf("write override file: %v", err)
	}
	t.Setenv("CBX_AUDIT_RULES_FILE", path)
	return path
}

// TestCurrentRulePackOfflineAndMemoized: the analyzer-side accessor
// never dials out, and the pack is API-distributed with no embedded
// floor — so a cold cache with no override is abort-class
// (ErrNoRulePack), never a silently rule-less grounded prompt. With an
// override file it resolves from the "file" rung and memoizes
// process-wide.
func TestCurrentRulePackOfflineAndMemoized(t *testing.T) {
	rulePackTestEnv(t)

	if _, _, err := currentRulePack(context.Background()); !errors.Is(err, rulesbundle.ErrNoRulePack) {
		t.Fatalf("cold cache + no override: err = %v, want rulesbundle.ErrNoRulePack", err)
	}

	// Abort-class failures are not memoized, so fixing the environment
	// (here: providing an override file) must resolve fresh.
	path := writeOverrideFile(t, rulesbundletest.Pack(t))
	pack, prov, err := currentRulePack(context.Background())
	if err != nil {
		t.Fatalf("currentRulePack with override file: %v", err)
	}
	if prov.Source != "file" {
		t.Errorf("source = %q, want file", prov.Source)
	}

	// Memoized: the second call must serve the memo, not re-read the
	// (now deleted) override file.
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove override file: %v", err)
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
// All resolutions go through an override file, so the pin checks run
// without the network rung ever being exercised.
func TestResolveRulePackEnvPin(t *testing.T) {
	rulePackTestEnv(t)
	writeOverrideFile(t, rulesbundletest.Build(t, func(p *rulesbundle.RulePack) {
		p.Manifest.PackVersion = 7
	}))

	t.Setenv("CBX_RULEPACK_VERSION", "7")
	_, prov, err := ResolveRulePack(context.Background(), 0)
	if err != nil {
		t.Fatalf("pin=7 via env: %v", err)
	}
	if prov.PinnedVersion != 7 {
		t.Errorf("PinnedVersion = %d, want 7", prov.PinnedVersion)
	}

	resetRulePackForTests()
	t.Setenv("CBX_RULEPACK_VERSION", "99")
	if _, _, err := ResolveRulePack(context.Background(), 0); err == nil || !strings.Contains(err.Error(), "99") {
		t.Fatalf("err = %v, want unsatisfiable-pin abort naming the pin", err)
	}

	resetRulePackForTests()
	t.Setenv("CBX_RULEPACK_VERSION", "latest")
	if _, _, err := ResolveRulePack(context.Background(), 0); err == nil || !strings.Contains(err.Error(), "CBX_RULEPACK_VERSION") {
		t.Fatalf("err = %v, want malformed-env abort", err)
	}

	// Abort-class failures must NOT memoize: a fixed env resolves fresh.
	t.Setenv("CBX_RULEPACK_VERSION", "7")
	if _, _, err := ResolveRulePack(context.Background(), 0); err != nil {
		t.Fatalf("recovery after bad env: %v", err)
	}
}

// TestAppendRulesProvenanceFindings drives the meta-finding trio off
// provenance variants. The analyzer carries the synthetic test pack —
// direct constructions never resolve the ladder, so provenance is
// injected per case.
func TestAppendRulesProvenanceFindings(t *testing.T) {
	byID := func(fs []Finding) map[string]Finding {
		out := map[string]Finding{}
		for _, f := range fs {
			out[f.RuleID] = f
		}
		return out
	}

	t.Run("zero-value-provenance-is-silent", func(t *testing.T) {
		l := &llmAnalyzer{providerForRuleID: "claudecode", rules: rulesbundletest.Pack(t)}
		if got := l.appendRulesProvenanceFindings(nil); len(got) != 0 {
			t.Fatalf("got %d findings for a zero-value provenance, want 0", len(got))
		}
	})

	t.Run("clean-network-emits-provenance-only", func(t *testing.T) {
		pack := rulesbundletest.Pack(t)
		l := &llmAnalyzer{
			providerForRuleID: "claudecode",
			rules:             pack,
			rulesProv: rulesbundle.Provenance{
				Source: "network", PackVersion: 1, SchemaVersion: 1,
				ContentSHA256: pack.Manifest.ContentSHA256,
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
		if !strings.Contains(p.Description, "network") || !strings.Contains(p.Description, "version 1") {
			t.Errorf("provenance description lacks pack identity: %q", p.Description)
		}
	})

	t.Run("degraded-and-stale-cache-emits-warning", func(t *testing.T) {
		pack := rulesbundletest.Pack(t)
		l := &llmAnalyzer{
			providerForRuleID: "claudecode",
			rules:             pack,
			rulesProv: rulesbundle.Provenance{
				Source: "cache", PackVersion: 1, SchemaVersion: 1,
				ContentSHA256: pack.Manifest.ContentSHA256,
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
		pack := rulesbundletest.Build(t, func(p *rulesbundle.RulePack) {
			p.Rules[0].RequiresFields = []string{"cb_describer_synthetic_never_exists"}
		})
		l := &llmAnalyzer{
			providerForRuleID: "claudecode",
			rules:             pack,
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
		if !strings.Contains(a.Description, "cb_describer_synthetic_never_exists") ||
			!strings.Contains(a.Description, pack.Rules[0].ID) {
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
		Source: "cache", PackVersion: 3, SchemaVersion: 1,
		ContentSHA256: strings.Repeat("ab", 32),
	}
	md := RenderAWSMarkdown(result, withPack)
	if !strings.Contains(md, "> **Rules** pack v3 (schema 1)  ·  source `cache`  ·  `abababababab`") {
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
