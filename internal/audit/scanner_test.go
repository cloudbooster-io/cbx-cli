package audit

import "testing"

func TestStaticScannerS3(t *testing.T) {
	scanners := MockScanners()
	resources := []DiscoveredResource{
		{Type: "aws:s3/bucket:Bucket", URN: "urn:pulumi:dev::stack::aws:s3/bucket:Bucket::my-bucket"},
	}
	findings, err := RunScanners(scanners, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings for S3 bucket, got %d", len(findings))
	}
	var hasS3001, hasS3002 bool
	for _, f := range findings {
		if f.RuleID == "S3-001" {
			hasS3001 = true
		}
		if f.RuleID == "S3-002" {
			hasS3002 = true
		}
	}
	if !hasS3001 {
		t.Fatal("expected S3-001 finding")
	}
	if !hasS3002 {
		t.Fatal("expected S3-002 finding")
	}
}

func TestStaticScannerSecurityGroup(t *testing.T) {
	scanners := MockScanners()
	resources := []DiscoveredResource{
		{Type: "aws_security_group", URN: "sg-123"},
	}
	findings, err := RunScanners(scanners, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for security group, got %d", len(findings))
	}
	if findings[0].RuleID != "EC2-001" {
		t.Fatalf("expected EC2-001, got %s", findings[0].RuleID)
	}
}

func TestStaticScannerNoMatch(t *testing.T) {
	scanners := MockScanners()
	resources := []DiscoveredResource{
		{Type: "aws:unknown:Type", URN: "unknown"},
	}
	findings, err := RunScanners(scanners, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for unknown type, got %d", len(findings))
	}
}

func TestRunScannersDedupe(t *testing.T) {
	// Run the same scanner twice to verify deduplication.
	scanners := []Scanner{&staticScanner{}, &staticScanner{}}
	resources := []DiscoveredResource{
		{Type: "aws:s3/bucket:Bucket", URN: "urn:pulumi:dev::stack::aws:s3/bucket:Bucket::my-bucket"},
	}
	findings, err := RunScanners(scanners, resources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 deduplicated findings, got %d", len(findings))
	}
}
