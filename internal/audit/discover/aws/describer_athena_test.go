package aws

import (
	"context"
	"testing"
)

// TestAthenaWorkGroupDescriber_FlagsDefaultOnly locks the distinction
// that fixes the `primary`-workgroup false positive: the AWS-managed
// default workgroup gets cb_describer_is_default_workgroup=true (so the
// grounded rule can carve it out deterministically), while a
// USER-created workgroup — even one with the identical unenforced /
// unencrypted config — is left unflagged AND with its config intact, so
// the real hardening signal still fires on it. Same shape as the
// GuardDuty disabled↔absent lock: the only deterministic surface is the
// describer flag (LLM firing itself isn't unit-testable).
func TestAthenaWorkGroupDescriber_FlagsDefaultOnly(t *testing.T) {
	d := athenaWorkGroupDescriber{}

	if got := d.CFNType(); got != "AWS::Athena::WorkGroup" {
		t.Fatalf("CFNType() = %q, want AWS::Athena::WorkGroup", got)
	}

	// An unenforced + unencrypted WorkGroupConfiguration — the exact
	// shape that should be a finding on a user workgroup and a non-finding
	// on the AWS default. Built fresh per resource so the assertions below
	// can prove the describer didn't mutate it.
	unenforcedCfg := func() map[string]any {
		return map[string]any{
			"WorkGroupConfiguration": map[string]any{
				"EnforceWorkGroupConfiguration": false,
			},
		}
	}

	t.Run("default primary is flagged", func(t *testing.T) {
		r := &DiscoveredResource{Type: "AWS::Athena::WorkGroup", ID: "primary"}
		r.Inputs = unenforcedCfg()
		r.Inputs["Name"] = "primary"
		if err := d.Enrich(context.Background(), awsCfg{}, r); err != nil {
			t.Fatalf("Enrich error: %v", err)
		}
		if v, _ := r.Inputs[cbDescriberIsDefaultWorkGroup].(bool); !v {
			t.Errorf("default `primary` workgroup not flagged: %s=%v",
				cbDescriberIsDefaultWorkGroup, r.Inputs[cbDescriberIsDefaultWorkGroup])
		}
	})

	t.Run("primary via identifier fallback (no Name property) is flagged", func(t *testing.T) {
		// CloudControl returns the name as the primary identifier; if
		// Properties.Name is absent the describer must still recognise it.
		r := &DiscoveredResource{Type: "AWS::Athena::WorkGroup", ID: "primary"}
		if err := d.Enrich(context.Background(), awsCfg{}, r); err != nil {
			t.Fatalf("Enrich error: %v", err)
		}
		if v, _ := r.Inputs[cbDescriberIsDefaultWorkGroup].(bool); !v {
			t.Errorf("`primary` via ID fallback not flagged")
		}
	})

	t.Run("user workgroup is NOT flagged and its config is preserved", func(t *testing.T) {
		r := &DiscoveredResource{Type: "AWS::Athena::WorkGroup", ID: "analytics-prod"}
		r.Inputs = unenforcedCfg()
		r.Inputs["Name"] = "analytics-prod"
		if err := d.Enrich(context.Background(), awsCfg{}, r); err != nil {
			t.Fatalf("Enrich error: %v", err)
		}
		if _, ok := r.Inputs[cbDescriberIsDefaultWorkGroup]; ok {
			t.Errorf("user workgroup wrongly flagged as the AWS default")
		}
		// Real signal must survive untouched so the rule still fires.
		wgc, ok := r.Inputs["WorkGroupConfiguration"].(map[string]any)
		if !ok {
			t.Fatalf("describer dropped WorkGroupConfiguration on a user workgroup")
		}
		if enforce, _ := wgc["EnforceWorkGroupConfiguration"].(bool); enforce {
			t.Errorf("describer mutated user WorkGroupConfiguration (EnforceWorkGroupConfiguration flipped)")
		}
	})
}
