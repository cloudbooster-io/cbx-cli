package audit

import (
	"context"
	"strings"
	"testing"
	"time"
)

// findingByRuleID extracts the first finding with the given rule id, or
// nil if absent. Lets a single test assert "this rule fired exactly once
// for this resource" by chaining with len().
func findingByRuleID(t *testing.T, findings []Finding, ruleID, resource string) *Finding {
	t.Helper()
	for i, f := range findings {
		if f.RuleID == ruleID && f.Resource == resource {
			return &findings[i]
		}
	}
	return nil
}

func TestOrphanProvider_FiltersOutNonAWS(t *testing.T) {
	// Pulumi-shaped and Terraform-shaped types must NOT trigger any
	// orphan finding — the provider runs in any mode but should be a
	// no-op outside `cbx audit aws`.
	resources := []Resource{
		{Type: "aws:s3/bucket:Bucket", URN: "urn:pulumi:s3:bucket:foo", ID: "foo"},
		{Type: "aws_ebs_volume", URN: "tf:ebs_volume.bar", ID: "bar"},
	}
	got, err := orphanProvider{}.Scan(context.Background(), resources)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected zero findings on non-AWS types, got %d: %+v", len(got), got)
	}
}

func TestOrphanProvider_UnattachedEBS(t *testing.T) {
	resources := []Resource{
		{
			Type: "AWS::EC2::Volume",
			URN:  "aws://us-east-1/AWS::EC2::Volume/vol-orphan",
			ID:   "vol-orphan",
			Inputs: map[string]any{
				"Size":        float64(100),
				"VolumeType":  "gp3",
				"Attachments": []any{}, // empty list — orphan
			},
		},
		{
			Type: "AWS::EC2::Volume",
			URN:  "aws://us-east-1/AWS::EC2::Volume/vol-attached",
			ID:   "vol-attached",
			Inputs: map[string]any{
				"Size":        float64(50),
				"Attachments": []any{map[string]any{"InstanceId": "i-abc"}},
			},
		},
	}

	got, err := orphanProvider{}.Scan(context.Background(), resources)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly one orphan finding, got %d", len(got))
	}
	f := findingByRuleID(t, got, "ORPHAN-EBS-UNATTACHED", "aws://us-east-1/AWS::EC2::Volume/vol-orphan")
	if f == nil {
		t.Fatalf("expected unattached EBS finding on vol-orphan; got %+v", got)
	}
	if f.Severity != SeverityInfo {
		t.Errorf("severity = %q, want %q", f.Severity, SeverityInfo)
	}
	if !strings.Contains(f.Description, "$8.00") {
		t.Errorf("expected 100 GB × $0.08 = $8.00/mo cost estimate, got %q", f.Description)
	}
}

func TestOrphanProvider_UnassociatedEIP(t *testing.T) {
	resources := []Resource{
		{
			Type:   "AWS::EC2::EIP",
			URN:    "aws://us-east-1/AWS::EC2::EIP/eipalloc-orphan",
			ID:     "eipalloc-orphan",
			Inputs: map[string]any{}, // no AssociationId
		},
		{
			Type: "AWS::EC2::EIP",
			URN:  "aws://us-east-1/AWS::EC2::EIP/eipalloc-used",
			ID:   "eipalloc-used",
			Inputs: map[string]any{
				"AssociationId": "eipassoc-abc",
			},
		},
	}
	got, err := orphanProvider{}.Scan(context.Background(), resources)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one EIP finding, got %d", len(got))
	}
	f := findingByRuleID(t, got, "ORPHAN-EIP-UNASSOCIATED", "aws://us-east-1/AWS::EC2::EIP/eipalloc-orphan")
	if f == nil {
		t.Fatalf("expected EIP finding on orphan; got %+v", got)
	}
	if !strings.Contains(f.Description, "$3.65") {
		t.Errorf("expected $3.65/mo flat cost, got %q", f.Description)
	}
}

func TestOrphanProvider_UnusedIAMRole(t *testing.T) {
	oldDate := time.Now().UTC().Add(-100 * 24 * time.Hour).Format("2006-01-02T15:04:05Z")
	recentDate := time.Now().UTC().Add(-10 * 24 * time.Hour).Format("2006-01-02T15:04:05Z")

	resources := []Resource{
		{
			Type: "AWS::IAM::Role",
			URN:  "aws://global/AWS::IAM::Role/role-stale",
			ID:   "role-stale",
			Inputs: map[string]any{
				"cb_describer_last_used": oldDate,
			},
		},
		{
			Type: "AWS::IAM::Role",
			URN:  "aws://global/AWS::IAM::Role/role-recent",
			ID:   "role-recent",
			Inputs: map[string]any{
				"cb_describer_last_used": recentDate,
			},
		},
		{
			Type: "AWS::IAM::Role",
			URN:  "aws://global/AWS::IAM::Role/role-never",
			ID:   "role-never",
			Inputs: map[string]any{
				"cb_describer_last_used": nil, // never assumed
			},
		},
		{
			Type:   "AWS::IAM::Role",
			URN:    "aws://global/AWS::IAM::Role/role-no-data",
			ID:     "role-no-data",
			Inputs: map[string]any{}, // describer hit AccessDenied — skip
		},
	}

	got, err := orphanProvider{}.Scan(context.Background(), resources)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected stale + never-used, got %d: %+v", len(got), got)
	}
	if findingByRuleID(t, got, "ORPHAN-IAM-ROLE-UNUSED", "aws://global/AWS::IAM::Role/role-stale") == nil {
		t.Error("missing stale-role finding")
	}
	if findingByRuleID(t, got, "ORPHAN-IAM-ROLE-UNUSED", "aws://global/AWS::IAM::Role/role-never") == nil {
		t.Error("missing never-used-role finding")
	}
}

func TestOrphanProvider_EmptyS3Bucket(t *testing.T) {
	oldDate := time.Now().UTC().Add(-60 * 24 * time.Hour).Format("2006-01-02T15:04:05.000Z")
	recentDate := time.Now().UTC().Add(-5 * 24 * time.Hour).Format("2006-01-02T15:04:05.000Z")

	resources := []Resource{
		{
			Type: "AWS::S3::Bucket",
			URN:  "aws://us-east-1/AWS::S3::Bucket/bucket-empty-old",
			ID:   "bucket-empty-old",
			Inputs: map[string]any{
				"cb_describer_has_objects":   false,
				"cb_describer_creation_date": oldDate,
			},
		},
		{
			Type: "AWS::S3::Bucket",
			URN:  "aws://us-east-1/AWS::S3::Bucket/bucket-empty-young",
			ID:   "bucket-empty-young",
			Inputs: map[string]any{
				"cb_describer_has_objects":   false,
				"cb_describer_creation_date": recentDate,
			},
		},
		{
			Type: "AWS::S3::Bucket",
			URN:  "aws://us-east-1/AWS::S3::Bucket/bucket-with-data",
			ID:   "bucket-with-data",
			Inputs: map[string]any{
				"cb_describer_has_objects":   true,
				"cb_describer_creation_date": oldDate,
			},
		},
		{
			Type: "AWS::S3::Bucket",
			URN:  "aws://us-east-1/AWS::S3::Bucket/bucket-no-probe",
			ID:   "bucket-no-probe",
			Inputs: map[string]any{
				"cb_describer_creation_date": oldDate,
				// missing cb_describer_has_objects — skip (probe failed)
			},
		},
	}

	got, err := orphanProvider{}.Scan(context.Background(), resources)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one empty-bucket finding, got %d: %+v", len(got), got)
	}
	if findingByRuleID(t, got, "ORPHAN-S3-EMPTY", "aws://us-east-1/AWS::S3::Bucket/bucket-empty-old") == nil {
		t.Error("missing empty-bucket finding for bucket-empty-old")
	}
}

func TestOrphanProvider_UnreferencedSecurityGroup(t *testing.T) {
	resources := []Resource{
		{
			Type: "AWS::EC2::SecurityGroup",
			URN:  "aws://us-east-1/AWS::EC2::SecurityGroup/sg-0ab12cd34ef56789a",
			ID:   "sg-0ab12cd34ef56789a",
			Inputs: map[string]any{
				"GroupId":   "sg-0ab12cd34ef56789a",
				"GroupName": "web-old",
			},
		},
		{
			Type: "AWS::EC2::SecurityGroup",
			URN:  "aws://us-east-1/AWS::EC2::SecurityGroup/sg-1bb22cc33dd44ee55",
			ID:   "sg-1bb22cc33dd44ee55",
			Inputs: map[string]any{
				"GroupId":   "sg-1bb22cc33dd44ee55",
				"GroupName": "web",
			},
		},
		{
			Type: "AWS::EC2::SecurityGroup",
			URN:  "aws://us-east-1/AWS::EC2::SecurityGroup/sg-2cc33dd44ee55ff66",
			ID:   "sg-2cc33dd44ee55ff66",
			Inputs: map[string]any{
				"GroupId":   "sg-2cc33dd44ee55ff66",
				"GroupName": "default", // VPC default — must be skipped
			},
		},
		{
			Type: "AWS::Lambda::Function",
			URN:  "aws://us-east-1/AWS::Lambda::Function/fn-1",
			ID:   "fn-1",
			Inputs: map[string]any{
				"VpcConfig": map[string]any{
					"SecurityGroupIds": []any{"sg-1bb22cc33dd44ee55"},
				},
			},
		},
	}

	got, err := orphanProvider{}.Scan(context.Background(), resources)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly one SG finding, got %d: %+v", len(got), got)
	}
	f := findingByRuleID(t, got, "ORPHAN-SG-UNREFERENCED", "aws://us-east-1/AWS::EC2::SecurityGroup/sg-0ab12cd34ef56789a")
	if f == nil {
		t.Fatalf("expected orphan SG finding on sg-0ab12cd34ef56789a; got %+v", got)
	}
}

func TestOrphanProvider_DoesNotSupportSource(t *testing.T) {
	p := orphanProvider{}
	if p.SupportsSource() {
		t.Error("orphan provider must not opt into source mode")
	}
	if _, err := p.ScanSource(context.Background(), "."); err != ErrSourceModeUnsupported {
		t.Errorf("ScanSource err = %v, want ErrSourceModeUnsupported", err)
	}
}

func TestOrphanProvider_RegisteredInMockScanners(t *testing.T) {
	var found bool
	for _, s := range MockScanners() {
		if s.Name() == "orphan" {
			found = true
		}
	}
	if !found {
		t.Error("orphan provider missing from MockScanners() — `cbx audit aws` MockScanners path will skip it")
	}
}

func TestParseCFNTimestamp(t *testing.T) {
	cases := []struct {
		in   string
		want string // RFC3339 representation; "" means parse failure expected
	}{
		{"2024-01-15T10:30:00Z", "2024-01-15T10:30:00Z"},
		{"2024-01-15T10:30:00.000Z", "2024-01-15T10:30:00Z"},
		{"2024-01-15T10:30:00+02:00", "2024-01-15T10:30:00+02:00"},
		{"not a date", ""},
	}
	for _, tc := range cases {
		got, err := parseCFNTimestamp(tc.in)
		if tc.want == "" {
			if err == nil {
				t.Errorf("parseCFNTimestamp(%q) = %v, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseCFNTimestamp(%q) err = %v", tc.in, err)
			continue
		}
		if got.Format(time.RFC3339) != tc.want {
			t.Errorf("parseCFNTimestamp(%q) = %q, want %q", tc.in, got.Format(time.RFC3339), tc.want)
		}
	}
}
