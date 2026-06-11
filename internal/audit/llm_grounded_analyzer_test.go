package audit

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/rulesbundle"
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
func (f *fakeGroundedStreamer) TotalCostUSD() float64            { return f.cost }

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
	useFakeKnowledgeBackend(t)
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
	useFakeKnowledgeBackend(t)
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
	useFakeKnowledgeBackend(t)
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
	useFakeKnowledgeBackend(t)
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
	prompt := buildGroundedPrompt(IaCTypeTerraform, files, resources, bundle, nil, rulesbundle.Embedded())
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

// TestBuildGroundedPrompt_S3HygieneBaselineRules is a WIRING CHECK only: it
// confirms the S3-hygiene baseline rules (and their describer-field hooks +
// the intent-scoping FP guard) are present in the prompt text. It does NOT
// validate that the findings actually fire or that the FP control bucket
// stays clean — that is LLM behavior, validated by the deferred live e2e run.
func TestBuildGroundedPrompt_S3HygieneBaselineRules(t *testing.T) {
	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, nil, &GroundingBundle{}, nil, rulesbundle.Embedded())
	for _, want := range []string{
		"cb_describer_versioning_enabled",
		"cb_describer_sse_is_kms",
		"cb_describer_mfa_delete_enabled",
		"cb_describer_lifecycle_present",
		"cb_describer_access_logging_enabled",
		"cb_describer_access_logging_target_bucket",
		"cb_describer_object_lock_enabled",
		"INTENT-SCOPED", // the FP guard must be stated, not implied
		"never describe the bucket as unencrypted",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("grounded prompt missing S3-hygiene wiring %q", want)
		}
	}
}

// TestBuildGroundedPrompt_RDSBackupRetentionBaselineRule is a WIRING CHECK: it
// confirms the replica-aware RDS backup-retention bullet (and its two carve-out
// describer hooks) is present in the prompt text. Whether the finding fires is
// LLM behavior, validated by the deferred live run.
func TestBuildGroundedPrompt_RDSBackupRetentionBaselineRule(t *testing.T) {
	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, nil, &GroundingBundle{}, nil, rulesbundle.Embedded())
	for _, want := range []string{
		"cb_describer_backup_retention_days <= 1",
		"cb_describer_is_read_replica",
		"cb_describer_is_cluster_member",
		"read replicas legitimately run retention 0", // the replica carve-out rationale
		"Multi-AZ DB cluster members",                // the cluster-member carve-out covers Multi-AZ DB clusters
		"UNKNOWN and do NOT flag",                    // absence polarity must be explicit
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("grounded prompt missing RDS backup-retention wiring %q", want)
		}
	}
}

// TestBuildGroundedPrompt_RendersFalseAndZeroDescriberFields guards the path
// the LLM actually reads: the carve-out booleans and the retention number must
// serialize into the resource table (serialiseInputs → JSON) as `false` / `0`,
// NOT be dropped as zero-values. If the serializer ever started omitting them,
// a standalone primary would render with the keys absent and the rule (which
// keys off `== false` / `<= 1`) would silently become a no-op on exactly the
// cases it targets — including the headline `backup_retention_days: 0` "backups
// disabled" finding.
func TestBuildGroundedPrompt_RendersFalseAndZeroDescriberFields(t *testing.T) {
	resources := []DiscoveredResource{{
		Type: "AWS::RDS::DBInstance",
		URN:  "arn:aws:rds:us-east-1:111122223333:db:db-standalone",
		ID:   "db-standalone",
		Inputs: map[string]any{
			"cb_describer_is_read_replica":       false,
			"cb_describer_is_cluster_member":     false,
			"cb_describer_backup_retention_days": float64(0),
		},
	}}
	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, resources, &GroundingBundle{}, nil, rulesbundle.Embedded())
	for _, want := range []string{
		`"cb_describer_is_read_replica": false`,
		`"cb_describer_is_cluster_member": false`,
		`"cb_describer_backup_retention_days": 0`,
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("resource table dropped a zero/false describer field — prompt missing %q", want)
		}
	}
}

// The §4.2 structural HIGH rules each pair a deterministic floor with a prompt
// detection bullet: applySeverityFloor only RAISES findings the LLM emits, so
// without the bullet the rule is a silent no-op. Guard that the key phrases the
// floor's text gates expect — and the cb_describer_* keys / raw fields the
// bullets reference — survive in the grounded prompt.
func TestBuildGroundedPrompt_MentionsStructural42Rules(t *testing.T) {
	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, nil, &GroundingBundle{}, nil, rulesbundle.Embedded())
	for _, want := range []string{
		"cb_describer_storage_encrypted",
		"unencrypted at rest",
		"MetadataOptions.HttpTokens",
		"IMDSv1",
		"cb_describer_assume_role_policy_raw",
		"ExternalId",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("grounded prompt missing §4.2 detection phrase %q (the paired floor would be a silent no-op)", want)
		}
	}
}

// TestBuildGroundedPrompt_CloudFrontSecurityRules is a WIRING CHECK: it confirms
// the four CloudFront security bullets (default-cert/weak-TLS, no-WAF, access-
// logging-disabled, S3-global-endpoint) and their explicit wire severities are
// present in the prompt text. These are LLM-emitted findings with NO severity
// floor, so naming the severity in the bullet is the only thing that pins the
// emission — a dropped phrase silently weakens the rule. Whether the findings
// fire is LLM behavior, validated by the deferred live run.
func TestBuildGroundedPrompt_CloudFrontSecurityRules(t *testing.T) {
	prompt := buildGroundedPrompt(IaCTypeTerraform, nil, nil, &GroundingBundle{}, nil, rulesbundle.Embedded())
	for _, want := range []string{
		"AWS::CloudFront::Distribution`) — evaluate the raw `DistributionConfig`",
		"ViewerCertificate.CloudFrontDefaultCertificate",
		"MinimumProtocolVersion=TLSv1.2_2021",
		"No WAF web ACL",
		"do NOT rate it higher than `info`", // no-WAF must stay info, not inflated
		"`WebACLId` is empty or absent",
		"Access logging disabled",
		"`DistributionConfig.Logging` is absent",
		"S3 global-endpoint form `<bucket>.s3.amazonaws.com`",
		"307 redirects",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("grounded prompt missing CloudFront wiring %q", want)
		}
	}
}

func TestNewLLMAnalyzer_CBKnowledgeRequiresClaudeCode(t *testing.T) {
	_, err := newLLMAnalyzer(Options{LLMProvider: "claude", CBKnowledge: true}, IaCTypeTerraform)
	if err == nil || !strings.Contains(err.Error(), "--cb-knowledge requires --llm claude-code") {
		t.Errorf("expected guard error for non-claude-code + --cb-knowledge, got %v", err)
	}
}
