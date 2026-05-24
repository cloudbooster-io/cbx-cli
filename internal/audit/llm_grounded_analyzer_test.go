package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeGroundedStreamer is a test double that satisfies both llmStreamer and
// groundingTrailer so the analyzer's grounded path can be exercised without
// spawning a subprocess.
type fakeGroundedStreamer struct {
	response string
	trail    []GroundingEvent
	cost     float64
}

func (f *fakeGroundedStreamer) Stream(_ context.Context, _ string, onToken func(string)) error {
	onToken(f.response)
	return nil
}

func (f *fakeGroundedStreamer) GroundingTrail() []GroundingEvent { return f.trail }
func (f *fakeGroundedStreamer) TotalCostUSD() float64             { return f.cost }

func newGroundedTestAnalyzer(s llmStreamer, maxCost float64) *llmAnalyzer {
	return &llmAnalyzer{
		provider:          ClaudeCodeProvider,
		streamer:          s,
		maxFiles:          50,
		maxBytesPerFile:   64 * 1024,
		iacType:           IaCTypeTerraform,
		providerForRuleID: "claudecode",
		cbKnowledge:       true,
		maxCostUSD:        maxCost,
	}
}

func TestLLMAnalyzer_Grounded_ParsesCBSourceField(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "aws_s3_bucket" "x" {}`), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	stream := &fakeGroundedStreamer{
		response: `{"findings":[{"rule_id":"LLM-CB-001","title":"S3 public ACL","severity":"high","resource":"aws_s3_bucket.x","service":"S3","remediation":"Disable","cb_source":{"tool":"aws_lookup_primitive","key":"aws:s3/bucket@v1","snippet":"Private bucket; CloudFront OAC."}}]}`,
		cost:     0.10,
	}
	a := newGroundedTestAnalyzer(stream, 2.0)

	findings, err := a.ScanSource(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanSource: %v", err)
	}
	// Expect 1 finding (no ungrounded summary because cb_source is present).
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	got := findings[0]
	if got.CBSource == nil {
		t.Fatalf("cb_source not parsed: %+v", got)
	}
	if got.CBSource.Tool != "aws_lookup_primitive" || got.CBSource.Key != "aws:s3/bucket@v1" {
		t.Errorf("cb_source mismatch: %+v", got.CBSource)
	}
}

func TestLLMAnalyzer_Grounded_SoftWarnsUngrounded(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "aws_s3_bucket" "x" {}`), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	stream := &fakeGroundedStreamer{
		response: `{"findings":[{"rule_id":"LLM-CB-002","title":"Generic","severity":"warning","resource":"aws_s3_bucket.x","service":"S3"}]}`,
		cost:     0.10,
	}
	a := newGroundedTestAnalyzer(stream, 2.0)

	findings, err := a.ScanSource(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanSource: %v", err)
	}
	// Expect 2 findings: original + the LLM-CB-UNGROUNDED summary.
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (orig+ungrounded summary), got %d: %+v", len(findings), findings)
	}
	if findings[1].RuleID != "LLM-CB-UNGROUNDED" {
		t.Errorf("expected LLM-CB-UNGROUNDED summary as second finding, got %q", findings[1].RuleID)
	}
}

func TestLLMAnalyzer_Grounded_CostCapWarning(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "aws_s3_bucket" "x" {}`), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	stream := &fakeGroundedStreamer{
		response: `{"findings":[{"rule_id":"LLM-CB-003","title":"Grounded","severity":"high","resource":"r","cb_source":{"tool":"aws_lookup_primitive","key":"aws:s3/bucket@v1"}}]}`,
		cost:     5.0,
	}
	a := newGroundedTestAnalyzer(stream, 2.0)

	findings, err := a.ScanSource(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanSource: %v", err)
	}
	// 1 grounded + cost-cap warning = 2.
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(findings), findings)
	}
	if findings[1].RuleID != "LLM-CB-COST-CAP" {
		t.Errorf("expected LLM-CB-COST-CAP, got %q", findings[1].RuleID)
	}
}

func TestLLMAnalyzer_Grounded_BackfillsSnippetFromTrail(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "aws_s3_bucket" "x" {}`), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	stream := &fakeGroundedStreamer{
		response: `{"findings":[{"rule_id":"LLM-CB-004","title":"S3","severity":"high","resource":"r","cb_source":{"tool":"aws_lookup_primitive","key":"aws:s3/bucket@v1"}}]}`,
		trail: []GroundingEvent{
			{
				Tool:  "aws_lookup_primitive",
				Input: map[string]interface{}{"type_id": "aws:s3/bucket@v1"},
				StructuredResult: map[string]interface{}{
					"kb_version": "stub",
					"chunks": []interface{}{
						map[string]interface{}{"chunk_text": "Private bucket; CloudFront OAC."},
					},
				},
			},
		},
	}
	a := newGroundedTestAnalyzer(stream, 2.0)

	findings, err := a.ScanSource(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanSource: %v", err)
	}
	if findings[0].CBSource == nil || !strings.Contains(findings[0].CBSource.Snippet, "Private bucket") {
		t.Errorf("snippet not backfilled from trail: %+v", findings[0].CBSource)
	}
}

func TestBuildGroundedPrompt_ListsWorkloadsAndPrimitives(t *testing.T) {
	files := []SourceFile{{Path: "main.tf", Content: []byte(`resource "aws_s3_bucket" "x" {}`)}}
	resources := []DiscoveredResource{
		{Type: "aws_s3_bucket", URN: "aws_s3_bucket.x"},
		{Type: "aws_cloudfront_distribution"},
	}
	// In the deterministic grounding path the prompt builder consumes a
	// pre-fetched GroundingBundle, not workload slugs. Synthesise a
	// representative bundle here so the prompt carries the expected
	// keys/snippets.
	bundle := &GroundingBundle{
		Primitives: []PrimitiveKnowledge{
			{TypeID: "aws:cdn/distribution@v1", Missing: true},
			{TypeID: "aws:s3/bucket@v1", Missing: true},
		},
		Practices: []WorkloadKnowledge{
			{Workload: "static-site", Missing: true},
		},
	}
	prompt := buildGroundedPrompt(IaCTypeTerraform, files, resources, bundle)
	for _, want := range []string{
		"CB KNOWLEDGE BUNDLE",
		"aws_lookup_primitive",
		"aws_best_practices_for",
		"static-site",
		"aws:s3/bucket@v1",
		"aws:cdn/distribution@v1",
		"cb_source",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
}

func TestNewLLMAnalyzer_CBKnowledgeRequiresClaudeCode(t *testing.T) {
	_, err := newLLMAnalyzer(Options{LLMProvider: "claude", CBKnowledge: true}, IaCTypeTerraform)
	if err == nil || !strings.Contains(err.Error(), "--cb-knowledge requires --llm claude-code") {
		t.Errorf("expected guard error for non-claude-code + --cb-knowledge, got %v", err)
	}
}
