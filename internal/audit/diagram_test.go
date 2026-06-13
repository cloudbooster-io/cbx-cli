package audit

import (
	"strings"
	"testing"
)

func TestBuildArchitectureDiagram_EmptyResources(t *testing.T) {
	if got := BuildArchitectureDiagram(nil, nil); got != "" {
		t.Errorf("expected empty diagram for no resources, got %q", got)
	}
}

// TestBuildArchitectureDiagram_ArchitectureBeta verifies the new
// mermaid output uses architecture-beta syntax and AWS iconify
// icons.
func TestBuildArchitectureDiagram_ArchitectureBeta(t *testing.T) {
	resources := []DiscoveredResource{
		{Type: "AWS::CloudFront::Distribution", URN: "aws://global/AWS::CloudFront::Distribution/cf-1", ID: "cf-1"},
		{Type: "AWS::S3::Bucket", URN: "aws://us-east-1/AWS::S3::Bucket/web", ID: "web"},
		{Type: "AWS::Lambda::Function", URN: "aws://us-east-1/AWS::Lambda::Function/fn", ID: "fn"},
	}
	got := BuildArchitectureDiagram(resources, nil)

	wants := []string{
		"architecture-beta",
		"group g_region",
		"service svc_users(internet)",
		"(internet)", // CloudFront → network → internet
		"(disk)",     // S3 → storage → disk
		"(server)",   // Lambda → compute → server
	}
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("output missing %q\n---\n%s", w, got)
		}
	}
	// architecture-beta uses --> with side hints, not the flowchart's
	// arrow-label syntax.
	if !strings.Contains(got, ":R --> L:") {
		t.Errorf("expected directional arrow syntax, got:\n%s", got)
	}
}

// TestBuildArchitectureDiagram_HidesNoiseBuckets confirms KMS Aliases,
// Snapshots and Target Groups don't render in the mermaid output.
func TestBuildArchitectureDiagram_HidesNoiseBuckets(t *testing.T) {
	resources := []DiscoveredResource{
		{Type: "AWS::S3::Bucket", URN: "aws://us-east-1/AWS::S3::Bucket/keep-me", ID: "keep-me"},
		{Type: "AWS::KMS::Alias", URN: "aws://us-east-1/AWS::KMS::Alias/alias/aws/s3", ID: "alias/aws/s3"},
		{Type: "AWS::EC2::Snapshot", URN: "aws://us-east-1/AWS::EC2::Snapshot/snap-1", ID: "snap-1"},
	}
	got := BuildArchitectureDiagram(resources, nil)
	if !strings.Contains(got, "keep-me") {
		t.Errorf("expected S3 bucket to render, got:\n%s", got)
	}
	if strings.Contains(got, "alias/aws/s3") {
		t.Errorf("KMS Alias should be hidden, got:\n%s", got)
	}
	if strings.Contains(got, "snap-1") {
		t.Errorf("Snapshot should be hidden, got:\n%s", got)
	}
}

// TestBuildArchitectureDiagram_DataFlowEdges checks the single
// Lambda + single ALB heuristic fires.
func TestBuildArchitectureDiagram_DataFlowEdges(t *testing.T) {
	resources := []DiscoveredResource{
		{Type: "AWS::ElasticLoadBalancingV2::LoadBalancer", URN: "aws://us-east-1/AWS::ELBv2::LoadBalancer/alb", ID: "alb"},
		{Type: "AWS::Lambda::Function", URN: "aws://us-east-1/AWS::Lambda::Function/fn", ID: "fn"},
	}
	got := BuildArchitectureDiagram(resources, nil)
	// Both endpoints should have an svcN id and one arrow line linking them.
	if strings.Count(got, ":R --> L:") < 1 {
		t.Errorf("expected at least one directional edge, got:\n%s", got)
	}
}

func TestServiceFromCFNType(t *testing.T) {
	cases := map[string]string{
		"AWS::EC2::Instance": "EC2",
		"AWS::S3::Bucket":    "S3",
		"AWS::IAM::Role":     "IAM",
		"weird":              "weird",
		"":                   "Other",
	}
	for in, want := range cases {
		if got := serviceFromCFNType(in); got != want {
			t.Errorf("serviceFromCFNType(%q) = %q, want %q", in, got, want)
		}
	}
}
