package audit

import "testing"

func TestDiscoveryIntegrityFinding_Shape(t *testing.T) {
	f := DiscoveryIntegrityFinding("AWS::S3::Bucket", "eu-central-1", 3)

	if f.RuleID != DiscoveryIntegrityRuleID {
		t.Errorf("RuleID = %q, want %q", f.RuleID, DiscoveryIntegrityRuleID)
	}
	// Severity MUST be warning (exit 2): a fired probe means the audit may be
	// a false-clean, and CI must not stay green on it. Guard against a silent
	// downgrade to info.
	if f.Severity != SeverityWarning {
		t.Errorf("Severity = %q, want %q (a possible false-clean must not be info)", f.Severity, SeverityWarning)
	}
	if f.Service != "S3" {
		t.Errorf("Service = %q, want S3", f.Service)
	}
	// Resource is unique per (type, region) so the RuleID|Resource dedup in
	// RunProviders cannot collapse two distinct misses.
	if f.Resource != "AWS::S3::Bucket@eu-central-1" {
		t.Errorf("Resource = %q, want AWS::S3::Bucket@eu-central-1", f.Resource)
	}
}

func TestDiscoveryIntegrityFinding_DistinctResourcesPerRegion(t *testing.T) {
	a := DiscoveryIntegrityFinding("AWS::SQS::Queue", "us-east-1", 1)
	b := DiscoveryIntegrityFinding("AWS::SQS::Queue", "eu-west-1", 1)
	if a.Resource == b.Resource {
		t.Errorf("same type in two regions produced identical Resource %q — dedup would collapse them", a.Resource)
	}
}

func TestDiscoveryIntegrityFinding_GlobalRegionOmitted(t *testing.T) {
	f := DiscoveryIntegrityFinding("AWS::IAM::Role", "", 2)
	if f.Resource != "AWS::IAM::Role" {
		t.Errorf("Resource = %q, want AWS::IAM::Role (no @region for global)", f.Resource)
	}
	if f.Service != "IAM" {
		t.Errorf("Service = %q, want IAM", f.Service)
	}
}

// Raw-mapping contract: an integrity finding on its own maps to a code-2 exit
// under ExitWithSeverity. This is the gating that `--strict` restores; the CLI
// default now routes through ExitWithSeverityStrict, which treats it as advisory
// (see the ExitWithSeverityStrict tests below).
func TestDiscoveryIntegrityFinding_DrivesExitCode2(t *testing.T) {
	f := DiscoveryIntegrityFinding("AWS::S3::Bucket", "eu-central-1", 1)
	err := ExitWithSeverity([]Finding{f})
	if err == nil {
		t.Fatal("expected a non-nil ExitCodeError for a warning finding")
	}
	ece, ok := err.(*ExitCodeError)
	if !ok {
		t.Fatalf("expected *ExitCodeError, got %T", err)
	}
	if ece.Code != 2 {
		t.Errorf("exit code = %d, want 2 (warning)", ece.Code)
	}
}

// exitCode unwraps the *ExitCodeError from ExitWithSeverityStrict; 0 means nil
// (clean exit).
func exitCode(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	ece, ok := err.(*ExitCodeError)
	if !ok {
		t.Fatalf("expected *ExitCodeError, got %T (%v)", err, err)
	}
	return ece.Code
}

// Default (non-strict): a lone discovery-integrity warning is ADVISORY — it must
// NOT redden an otherwise-clean audit, because the probe reads two flaky
// CloudControl calls and a transient miss shouldn't fail a good run.
func TestExitWithSeverityStrict_IntegrityOnly_NonStrictIsClean(t *testing.T) {
	f := DiscoveryIntegrityFinding("AWS::S3::Bucket", "eu-central-1", 1)
	if code := exitCode(t, ExitWithSeverityStrict([]Finding{f}, false)); code != 0 {
		t.Errorf("non-strict exit = %d, want 0 (integrity warning is advisory by default)", code)
	}
}

// --strict restores the gating: the same lone integrity warning exits 2.
func TestExitWithSeverityStrict_IntegrityOnly_StrictGates(t *testing.T) {
	f := DiscoveryIntegrityFinding("AWS::S3::Bucket", "eu-central-1", 1)
	if code := exitCode(t, ExitWithSeverityStrict([]Finding{f}, true)); code != 2 {
		t.Errorf("strict exit = %d, want 2 (integrity warning gates under --strict)", code)
	}
}

// Non-strict only suppresses the integrity finding's OWN contribution: a real
// warning sitting alongside it still gates, so a genuine problem next to a flaky
// probe never goes green.
func TestExitWithSeverityStrict_RealWarningStillGates(t *testing.T) {
	integrity := DiscoveryIntegrityFinding("AWS::S3::Bucket", "eu-central-1", 1)
	real := Finding{RuleID: "CBX-REAL-RULE", Severity: SeverityWarning}
	if code := exitCode(t, ExitWithSeverityStrict([]Finding{integrity, real}, false)); code != 2 {
		t.Errorf("non-strict exit = %d, want 2 (a real warning beside the integrity finding must still gate)", code)
	}
}

// A non-integrity high finding gates to 3 in BOTH modes — the filter is scoped
// strictly to the integrity rule id and touches nothing else.
func TestExitWithSeverityStrict_NonIntegrityHighGatesInBothModes(t *testing.T) {
	high := Finding{RuleID: "CBX-REAL-RULE", Severity: SeverityHigh}
	if code := exitCode(t, ExitWithSeverityStrict([]Finding{high}, false)); code != 3 {
		t.Errorf("non-strict exit = %d, want 3 (a real high finding gates regardless of strict)", code)
	}
	if code := exitCode(t, ExitWithSeverityStrict([]Finding{high}, true)); code != 3 {
		t.Errorf("strict exit = %d, want 3", code)
	}
}

// Discriminator is the stable RuleID, not severity: even if applySeverityFloor
// ever promoted an integrity finding above warning, non-strict must still treat
// it as advisory (exit 0). Locks in "filter by id, not severity".
func TestExitWithSeverityStrict_FiltersByRuleIDNotSeverity(t *testing.T) {
	promoted := Finding{RuleID: DiscoveryIntegrityRuleID, Severity: SeverityHigh}
	if code := exitCode(t, ExitWithSeverityStrict([]Finding{promoted}, false)); code != 0 {
		t.Errorf("non-strict exit = %d, want 0 (integrity finding is filtered by rule id even when promoted to high)", code)
	}
	if code := exitCode(t, ExitWithSeverityStrict([]Finding{promoted}, true)); code != 3 {
		t.Errorf("strict exit = %d, want 3 (under --strict the promoted integrity finding gates)", code)
	}
}

// The exit calculation must not mutate or drop the caller's slice — the integrity
// finding has to survive into result.Findings for the report and JSON payload.
func TestExitWithSeverityStrict_DoesNotMutateInput(t *testing.T) {
	in := []Finding{DiscoveryIntegrityFinding("AWS::S3::Bucket", "eu-central-1", 1)}
	_ = ExitWithSeverityStrict(in, false)
	if len(in) != 1 || in[0].RuleID != DiscoveryIntegrityRuleID {
		t.Errorf("input slice was mutated: len=%d, first rule=%q", len(in), in[0].RuleID)
	}
}
