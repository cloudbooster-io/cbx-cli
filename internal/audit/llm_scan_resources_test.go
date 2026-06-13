package audit

import (
	"context"
	"strings"
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/parsers"
	"github.com/cloudbooster-io/cbx-cli/internal/audit/rulesbundle/rulesbundletest"
)

func TestScanResources_BuildsAWSModePrompt_NoSourceFiles(t *testing.T) {
	useFakeKnowledgeBackend(t)
	stream := &fakeStreamer{chunks: []string{`{"findings":[]}`}}
	a := newTestAnalyzer(stream)
	a.iacType = IaCTypeCloudFormation
	a.cbKnowledge = true
	a.rules = rulesbundletest.Pack(t)

	resources := []DiscoveredResource{
		{
			Type:   "AWS::S3::Bucket",
			URN:    "aws://us-east-1/AWS::S3::Bucket/web-cdn",
			ID:     "web-cdn",
			Region: "us-east-1",
			Inputs: map[string]any{
				"cb_describer_public_access_block": nil,
				"cb_describer_versioning":          map[string]any{"status": "Suspended"},
			},
		},
		{
			Type: "AWS::RDS::DBInstance",
			URN:  "aws://us-east-1/AWS::RDS::DBInstance/prod-db",
			ID:   "prod-db",
			Inputs: map[string]any{
				parsers.CBDescriberPrimitiveResolved: "aws:db/postgres@v1",
				"cb_describer_storage_encrypted":     true,
			},
		},
	}

	if _, err := a.ScanResources(context.Background(), resources); err != nil {
		t.Fatalf("ScanResources: %v", err)
	}

	prompt := stream.prompt
	if strings.Contains(prompt, "Source files follow.") {
		t.Errorf("AWS-mode prompt must NOT include the source-files header (no files exist)")
	}
	if !strings.Contains(prompt, "LIVE AWS resources") {
		t.Errorf("AWS-mode prompt missing the live-resources header. Got:\n%s", prompt)
	}
	if !strings.Contains(prompt, "aws://us-east-1/AWS::S3::Bucket/web-cdn") {
		t.Errorf("prompt missing S3 URN line")
	}
	if !strings.Contains(prompt, "aws:db/postgres@v1") {
		t.Errorf("prompt missing engine-resolved RDS primitive id")
	}
	if !strings.Contains(prompt, "cb_describer_public_access_block") {
		t.Errorf("prompt missing describer enrichment for S3 bucket")
	}
}

func TestScanResources_EmptyResourceSetShortCircuits(t *testing.T) {
	stream := &fakeStreamer{chunks: []string{`{"findings":[{"title":"shouldn't run"}]}`}}
	a := newTestAnalyzer(stream)

	got, err := a.ScanResources(context.Background(), nil)
	if err != nil {
		t.Fatalf("ScanResources: %v", err)
	}
	if got != nil {
		t.Errorf("empty input must return nil findings, got %+v", got)
	}
	if stream.prompt != "" {
		t.Errorf("streamer must not have been invoked on empty input")
	}
}

func TestScanResources_GroundedPathRunsPostProcessing(t *testing.T) {
	useFakeKnowledgeBackend(t)
	// Mirror ScanSource's grounded soft-warn behaviour. A finding without
	// cb_source must trigger the "ungrounded findings" info line.
	stream := &fakeGroundedStreamer{
		response: `{"findings":[{"rule_id":"LLM-CB-001","title":"empty PAB","severity":"high","resource":"aws://us-east-1/AWS::S3::Bucket/x","service":"S3","remediation":"Enable PAB"}]}`,
		cost:     0.05,
	}
	a := newGroundedTestAnalyzer(t, stream, 2.0)
	a.iacType = IaCTypeCloudFormation

	findings, err := a.ScanResources(context.Background(), []DiscoveredResource{
		{Type: "AWS::S3::Bucket", URN: "aws://us-east-1/AWS::S3::Bucket/x", ID: "x"},
	})
	if err != nil {
		t.Fatalf("ScanResources: %v", err)
	}

	var rules []string
	for _, f := range findings {
		rules = append(rules, f.RuleID)
	}
	if !contains(rules, "LLM-CB-001") || !contains(rules, "LLM-CB-UNGROUNDED") {
		t.Errorf("expected original finding + ungrounded summary, got %v", rules)
	}
}

func TestCollectFromResources_LLMBranchBypassesScannerPipeline(t *testing.T) {
	// When opts.LLMProvider is set the LLM path replaces selectProviders.
	// We can't exercise the full path without a configured provider — but
	// we can assert the dispatch with an unknown provider returns the
	// "provider not configured" error from newLLMAnalyzer rather than
	// silently falling back to scanners.
	opts := Options{
		AWS:         true,
		LLMProvider: "bogus-provider-not-registered",
	}
	_, err := CollectFromResources(opts, []DiscoveredResource{{Type: "AWS::S3::Bucket"}})
	if err == nil {
		t.Fatalf("expected newLLMAnalyzer to surface a configuration error for an unknown provider")
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
