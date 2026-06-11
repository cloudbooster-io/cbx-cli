package audit

import (
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/parsers"
	"github.com/cloudbooster-io/cbx-cli/internal/audit/rulesbundle"
)

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

	if got := rulesbundle.Embedded().Manifest.WireContract.ResponseSchema; got != rulesbundle.ResponseSchemaVersion {
		t.Errorf("embedded pack response_schema %d != engine version %d", got, rulesbundle.ResponseSchemaVersion)
	}
}

// TestEmbeddedPackRequiresFieldsKnown: every cb_describer_* field the
// embedded rulepack's rules declare in requires_fields must exist in
// the engine's generated describer-field manifest. The embedded pack
// ships WITH the engine, so it can never legitimately be AHEAD of it —
// a violation here means either rule metadata names a field wrong or a
// describer was removed without a rulepack update.
func TestEmbeddedPackRequiresFieldsKnown(t *testing.T) {
	for _, r := range rulesbundle.Embedded().Rules {
		for _, f := range r.RequiresFields {
			if !parsers.DescriberFieldKnown(f) {
				t.Errorf("rule %s requires_fields names %q, which no describer/lister/cross-ref emits", r.ID, f)
			}
		}
	}
}
