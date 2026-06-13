package audit

import (
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/rulesbundle"
)

// NOTE: the served-pack ⊆ engine-manifest check (every requires_fields
// entry names a field some describer/lister actually emits) used to
// live here as TestEmbeddedPackRequiresFieldsKnown. With the pack
// API-distributed there is no in-repo pack to check against, so that
// assertion moved to the e2e_staging tier, which validates the pack
// the registry actually serves.

// TestRulePackWireContractMatchesEngine ties the rulepack's declared
// wire contract to the engine's actual severity vocabulary.
// rulesbundle.Validate checks packs against rulesbundle.WireSeverities;
// this test is the other half of the handshake — it pins that list to
// the audit package's severity constants and to clampSeverity's
// behaviour, so the two can never drift apart silently (rulesbundle
// cannot import internal/audit, internal/audit imports rulesbundle).
func TestRulePackWireContractMatchesEngine(t *testing.T) {
	engine := []string{SeverityCritical, SeverityHigh, SeverityWarning, SeverityInfo}
	if len(rulesbundle.WireSeverities) != len(engine) {
		t.Fatalf("rulesbundle.WireSeverities %v does not match engine vocabulary %v", rulesbundle.WireSeverities, engine)
	}
	for i, s := range engine {
		if rulesbundle.WireSeverities[i] != s {
			t.Fatalf("rulesbundle.WireSeverities[%d] = %q, want %q", i, rulesbundle.WireSeverities[i], s)
		}
		// Every wire value must survive the engine's clamp unchanged —
		// a vocabulary the parser rewrites is not a shared contract.
		if got := clampSeverity(s); got != s {
			t.Errorf("clampSeverity(%q) = %q — wire value does not round-trip", s, got)
		}
	}

	// ResponseSchemaVersion is what Validate demands of every pack the
	// ladder accepts; 1 is the only response shape this engine's finding
	// parser implements. Bumping the constant without a parser change
	// would let packs through that the engine cannot honour.
	if rulesbundle.ResponseSchemaVersion != 1 {
		t.Errorf("rulesbundle.ResponseSchemaVersion = %d — the engine only implements response schema 1; a bump needs a matching parser change", rulesbundle.ResponseSchemaVersion)
	}
}
