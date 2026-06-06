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

// End-to-end contract: an integrity finding on its own drives a code-2 exit, so
// `cbx audit aws` (and CI) cannot go green on a possibly-incomplete discovery.
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
