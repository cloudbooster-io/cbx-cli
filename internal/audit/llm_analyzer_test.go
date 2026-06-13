package audit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/rulesbundle/rulesbundletest"
)

// fakeStreamer feeds a pre-canned response one chunk at a time so the
// analyzer's stream-accumulate-then-parse path exercises the same code
// path it would in production, without booting a real LLM provider.
type fakeStreamer struct {
	chunks []string
	err    error
	prompt string
}

func (f *fakeStreamer) Stream(_ context.Context, prompt string, onToken func(string)) error {
	f.prompt = prompt
	if f.err != nil {
		return f.err
	}
	for _, c := range f.chunks {
		onToken(c)
	}
	return nil
}

func newTestAnalyzer(streamer llmStreamer) *llmAnalyzer {
	return &llmAnalyzer{
		provider:          "claude",
		streamer:          streamer,
		maxFiles:          50,
		maxBytesPerFile:   64 * 1024,
		iacType:           IaCTypeTerraform,
		providerForRuleID: "claude",
	}
}

func TestLLMAnalyzer_ParsesStructuredOutput(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "aws_s3_bucket" "x" {}`), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	streamer := &fakeStreamer{chunks: []string{`{"findings":[`, `{"rule_id":"LLM-CUSTOM-001","title":"Open bucket","description":"S3 bucket lacks SSE","severity":"high","resource":"aws_s3_bucket.x","service":"S3","remediation":"Add encryption","file":"main.tf","line":1}`, `]}`}}
	a := newTestAnalyzer(streamer)

	findings, err := a.ScanSource(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanSource: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d (%v)", len(findings), findings)
	}
	got := findings[0]
	if got.RuleID != "LLM-CUSTOM-001" {
		t.Errorf("RuleID = %q, want LLM-CUSTOM-001", got.RuleID)
	}
	if got.Severity != SeverityHigh {
		t.Errorf("Severity = %q, want %q", got.Severity, SeverityHigh)
	}
	if !strings.Contains(streamer.prompt, "FILE: main.tf") {
		t.Errorf("prompt should embed source file; got: %s", streamer.prompt)
	}
}

func TestLLMAnalyzer_HandlesFencedAndChattyOutput(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "aws_s3_bucket" "x" {}`), 0o644)

	// Provider wraps JSON in markdown fence and adds a preamble — must still parse.
	resp := "Here's what I found:\n```json\n{\"findings\":[{\"title\":\"Issue A\",\"severity\":\"medium\",\"resource\":\"r1\"}]}\n```\n"
	a := newTestAnalyzer(&fakeStreamer{chunks: []string{resp}})

	findings, err := a.ScanSource(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanSource: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityWarning {
		t.Errorf("severity 'medium' should clamp to warning, got %q", findings[0].Severity)
	}
	if !strings.HasPrefix(findings[0].RuleID, "LLM-claude-") {
		t.Errorf("RuleID should be LLM-claude-<hash>, got %q", findings[0].RuleID)
	}
}

func TestLLMAnalyzer_MalformedJSONBecomesErrorFinding(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "x" "y" {}`), 0o644)

	a := newTestAnalyzer(&fakeStreamer{chunks: []string{"not even close to JSON"}})

	findings, err := a.ScanSource(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanSource shouldn't fail outright on parse error: %v", err)
	}
	if len(findings) != 1 || findings[0].RuleID != "LLM-ERROR" {
		t.Fatalf("expected single LLM-ERROR finding, got %v", findings)
	}
}

func TestLLMAnalyzer_StreamErrorBecomesErrorFinding(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "x" "y" {}`), 0o644)

	a := newTestAnalyzer(&fakeStreamer{err: errors.New("transport failure")})

	findings, err := a.ScanSource(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanSource: %v", err)
	}
	if len(findings) != 1 || findings[0].RuleID != "LLM-ERROR" {
		t.Fatalf("expected LLM-ERROR, got %v", findings)
	}
	if findings[0].Severity != SeverityWarning {
		t.Errorf("LLM-ERROR is a total analysis failure and must be warning (exit 2), got %q", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Description, "transport failure") {
		t.Errorf("stream error should surface in description, got %q", findings[0].Description)
	}
}

func TestLLMAnalyzer_NoSourceFilesYieldsNoFindings(t *testing.T) {
	dir := t.TempDir()
	// no IaC files
	a := newTestAnalyzer(&fakeStreamer{chunks: []string{`{"findings":[{"title":"shouldnt run"}]}`}})

	findings, err := a.ScanSource(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanSource: %v", err)
	}
	if findings != nil {
		t.Fatalf("expected nil findings when no IaC files matched, got %v", findings)
	}
}

func TestLLMAnalyzer_StateModeUnsupported(t *testing.T) {
	a := newTestAnalyzer(&fakeStreamer{})
	_, err := a.Scan(context.Background(), nil)
	if !errors.Is(err, ErrSourceModeUnsupported) {
		t.Fatalf("expected ErrSourceModeUnsupported, got %v", err)
	}
}

func TestCollectSourceFiles_TruncatesAndCaps(t *testing.T) {
	dir := t.TempDir()
	// 3 files, max-files=2; one file longer than per-file cap.
	for i, body := range []string{
		strings.Repeat("a", 100),
		strings.Repeat("b", 5000),
		strings.Repeat("c", 200),
	} {
		_ = os.WriteFile(filepath.Join(dir, "f"+strings.Repeat("x", i)+".tf"), []byte(body), 0o644)
	}

	files, err := collectSourceFiles(dir, IaCTypeTerraform, 2, 1024)
	if err != nil {
		t.Fatalf("collectSourceFiles: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("max-files cap not enforced; got %d files", len(files))
	}
	for _, f := range files {
		if f.Bytes > 1024 {
			t.Errorf("per-file cap not enforced: bytes=%d", f.Bytes)
		}
	}
}

func TestClampSeverity(t *testing.T) {
	cases := map[string]string{
		"critical": SeverityCritical,
		"high":     SeverityHigh,
		"medium":   SeverityWarning,
		"warning":  SeverityWarning,
		"low":      SeverityInfo,
		"info":     SeverityInfo,
		"":         SeverityInfo,
		"weird":    SeverityInfo,
	}
	for in, want := range cases {
		if got := clampSeverity(in); got != want {
			t.Errorf("clampSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

// syntheticResources builds n small, distinctly-URN'd resources whose
// sorted order is deterministic (zero-padded index in the URN).
func syntheticResources(n int) []DiscoveredResource {
	out := make([]DiscoveredResource, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, DiscoveredResource{
			Type:   "AWS::S3::Bucket",
			URN:    fmt.Sprintf("aws://us-east-1/AWS::S3::Bucket/b-%04d", i),
			ID:     fmt.Sprintf("b-%04d", i),
			Region: "us-east-1",
			Inputs: map[string]any{"BucketName": fmt.Sprintf("b-%04d", i)},
		})
	}
	return out
}

func TestCapPromptResources_CountCap(t *testing.T) {
	resources := syntheticResources(defaultLLMMaxPromptResources + 10)

	kept, omitted := capPromptResources(resources)
	if len(kept) != defaultLLMMaxPromptResources {
		t.Fatalf("kept = %d, want %d", len(kept), defaultLLMMaxPromptResources)
	}
	if omitted != 10 {
		t.Fatalf("omitted = %d, want 10", omitted)
	}
	// Truncation must be stable: the kept set is the sorted prefix, so the
	// last kept URN is the (cap-1)th in sorted order on every run.
	wantLast := fmt.Sprintf("aws://us-east-1/AWS::S3::Bucket/b-%04d", defaultLLMMaxPromptResources-1)
	if got := kept[len(kept)-1].resource.URN; got != wantLast {
		t.Errorf("last kept URN = %q, want %q (deterministic prefix)", got, wantLast)
	}

	kept2, omitted2 := capPromptResources(resources)
	if len(kept2) != len(kept) || omitted2 != omitted {
		t.Errorf("second run diverged: kept %d/omitted %d vs kept %d/omitted %d",
			len(kept2), omitted2, len(kept), omitted)
	}
}

func TestCapPromptResources_ByteCapKeepsAtLeastOne(t *testing.T) {
	// Each resource serialises to well over half the byte budget, so the
	// second one trips the cap — but the first must always survive (a
	// single oversized resource can't blank the whole table).
	big := strings.Repeat("x", defaultLLMMaxResourceTableBytes*3/4)
	resources := []DiscoveredResource{
		{Type: "AWS::S3::Bucket", URN: "aws://r/a", Inputs: map[string]any{"Blob": big}},
		{Type: "AWS::S3::Bucket", URN: "aws://r/b", Inputs: map[string]any{"Blob": big}},
		{Type: "AWS::S3::Bucket", URN: "aws://r/c", Inputs: map[string]any{"Blob": big}},
	}

	kept, omitted := capPromptResources(resources)
	if len(kept) != 1 {
		t.Fatalf("kept = %d, want 1 (byte cap after first oversized resource)", len(kept))
	}
	if omitted != 2 {
		t.Fatalf("omitted = %d, want 2", omitted)
	}
	if kept[0].resource.URN != "aws://r/a" {
		t.Errorf("kept URN = %q, want the sorted-first resource", kept[0].resource.URN)
	}
}

func TestWriteResourceTable_MarksTruncation(t *testing.T) {
	resources := syntheticResources(defaultLLMMaxPromptResources + 3)

	var sb strings.Builder
	writeResourceTable(&sb, resources)
	table := sb.String()
	if !strings.Contains(table, "TRUNCATED: 3 additional resources omitted") {
		t.Errorf("table missing the explicit TRUNCATED marker:\n%s", table[len(table)-400:])
	}
	wantLast := fmt.Sprintf("b-%04d", defaultLLMMaxPromptResources-1)
	if !strings.Contains(table, wantLast) {
		t.Errorf("table missing last kept resource %s", wantLast)
	}
	if strings.Contains(table, fmt.Sprintf("b-%04d", defaultLLMMaxPromptResources)) {
		t.Errorf("table contains a resource past the cap")
	}
}

func TestScanResources_EmitsTruncationFinding(t *testing.T) {
	useFakeKnowledgeBackend(t)
	stream := &fakeStreamer{chunks: []string{`{"findings":[]}`}}
	a := newTestAnalyzer(stream)
	a.iacType = IaCTypeCloudFormation
	a.cbKnowledge = true
	a.rules = rulesbundletest.Pack(t)

	resources := syntheticResources(defaultLLMMaxPromptResources + 7)

	findings, err := a.ScanResources(context.Background(), resources)
	if err != nil {
		t.Fatalf("ScanResources: %v", err)
	}

	var trunc *Finding
	for i := range findings {
		if findings[i].RuleID == "LLM-CB-TRUNCATED" {
			trunc = &findings[i]
		}
	}
	if trunc == nil {
		t.Fatalf("expected an LLM-CB-TRUNCATED finding, got %+v", findings)
	}
	if trunc.Severity != SeverityInfo {
		t.Errorf("truncation finding severity = %q, want %q", trunc.Severity, SeverityInfo)
	}
	if !strings.Contains(trunc.Title, "7") {
		t.Errorf("truncation finding title should carry the omitted count, got %q", trunc.Title)
	}
}

func TestScanResources_NoTruncationFindingUnderCap(t *testing.T) {
	useFakeKnowledgeBackend(t)
	stream := &fakeStreamer{chunks: []string{`{"findings":[]}`}}
	a := newTestAnalyzer(stream)
	a.iacType = IaCTypeCloudFormation
	a.cbKnowledge = true
	a.rules = rulesbundletest.Pack(t)

	findings, err := a.ScanResources(context.Background(), syntheticResources(3))
	if err != nil {
		t.Fatalf("ScanResources: %v", err)
	}
	for _, f := range findings {
		if f.RuleID == "LLM-CB-TRUNCATED" {
			t.Errorf("no truncation finding expected under the cap, got %+v", f)
		}
		if f.RuleID == "LLM-CB-KNOWLEDGE-PARTIAL" {
			t.Errorf("no knowledge-partial finding expected against a healthy backend, got %+v", f)
		}
	}
}

// flakyPrimitiveResource is a resource whose describer-resolved primitive
// id contains "flaky", so a newFailingKnowledgeServer(t, "flaky", …)
// backend 5xx's exactly this one lookup and nothing else.
func flakyPrimitiveResource() DiscoveredResource {
	return DiscoveredResource{
		Type:   "AWS::Lambda::Function",
		URN:    "aws://us-east-1/AWS::Lambda::Function/f-flaky",
		ID:     "f-flaky",
		Region: "us-east-1",
		Inputs: map[string]any{"cb_describer_primitive_resolved": "aws:fake/flaky@v1"},
	}
}

// TestScanResources_EmitsKnowledgePartialFinding is the analyzer-level
// half of the review-L24 degradation policy: one primitive's CB
// knowledge 503s (after retry), the analysis must still run on the
// fetched remainder, and the report must carry exactly ONE
// warning-severity LLM-CB-KNOWLEDGE-PARTIAL finding naming the missed
// primitive — never the abort-everything LLM-ERROR.
func TestScanResources_EmitsKnowledgePartialFinding(t *testing.T) {
	srv := newFailingKnowledgeServer(t, "flaky", http.StatusServiceUnavailable)
	t.Cleanup(srv.Close)
	t.Setenv(cbAPIURLEnv, srv.URL)

	stream := &fakeStreamer{chunks: []string{`{"findings":[]}`}}
	a := newTestAnalyzer(stream)
	a.iacType = IaCTypeCloudFormation
	a.cbKnowledge = true
	a.rules = rulesbundletest.Pack(t)

	resources := append(syntheticResources(3), flakyPrimitiveResource())

	findings, err := a.ScanResources(context.Background(), resources)
	if err != nil {
		t.Fatalf("ScanResources: %v", err)
	}

	var partial *Finding
	for i := range findings {
		switch findings[i].RuleID {
		case "LLM-ERROR":
			t.Fatalf("a transient knowledge miss must degrade, not abort: %+v", findings[i])
		case "LLM-CB-KNOWLEDGE-PARTIAL":
			if partial != nil {
				t.Fatalf("expected exactly ONE knowledge-partial finding, got a second: %+v", findings[i])
			}
			partial = &findings[i]
		}
	}
	if partial == nil {
		t.Fatalf("expected an LLM-CB-KNOWLEDGE-PARTIAL finding, got %+v", findings)
	}
	if partial.Severity != SeverityWarning {
		t.Errorf("knowledge-partial severity = %q, want %q (reduced grounding must be exit-code visible)", partial.Severity, SeverityWarning)
	}
	if !strings.Contains(partial.Description, "aws:fake/flaky@v1") {
		t.Errorf("knowledge-partial finding should list the missed primitive, got %q", partial.Description)
	}
	// The analysis itself must have run: the prompt was built and streamed.
	if stream.prompt == "" {
		t.Errorf("the LLM stream should still run on the partial bundle")
	}
}

// TestScanResources_PartialAndTruncationCoexist guards the interplay of
// the two degradation findings: a capped resource table (LLM-CB-TRUNCATED,
// !74) and a partial knowledge bundle (LLM-CB-KNOWLEDGE-PARTIAL) trip on
// independent conditions and must BOTH land in the same report.
func TestScanResources_PartialAndTruncationCoexist(t *testing.T) {
	srv := newFailingKnowledgeServer(t, "flaky", http.StatusServiceUnavailable)
	t.Cleanup(srv.Close)
	t.Setenv(cbAPIURLEnv, srv.URL)

	stream := &fakeStreamer{chunks: []string{`{"findings":[]}`}}
	a := newTestAnalyzer(stream)
	a.iacType = IaCTypeCloudFormation
	a.cbKnowledge = true
	a.rules = rulesbundletest.Pack(t)

	resources := append(syntheticResources(defaultLLMMaxPromptResources+2), flakyPrimitiveResource())

	findings, err := a.ScanResources(context.Background(), resources)
	if err != nil {
		t.Fatalf("ScanResources: %v", err)
	}
	seen := map[string]int{}
	for _, f := range findings {
		seen[f.RuleID]++
	}
	if seen["LLM-CB-TRUNCATED"] != 1 {
		t.Errorf("expected exactly one LLM-CB-TRUNCATED finding, got %d", seen["LLM-CB-TRUNCATED"])
	}
	if seen["LLM-CB-KNOWLEDGE-PARTIAL"] != 1 {
		t.Errorf("expected exactly one LLM-CB-KNOWLEDGE-PARTIAL finding, got %d", seen["LLM-CB-KNOWLEDGE-PARTIAL"])
	}
}

// TestScanResources_KnowledgeAuthErrorAborts pins the retained abort
// path at the analyzer level: an auth-class (401) knowledge backend
// means the grounding premise is broken — the analysis must NOT run on
// an empty bundle; it degrades to the single LLM-ERROR finding exactly
// as before L24.
func TestScanResources_KnowledgeAuthErrorAborts(t *testing.T) {
	srv := newFailingKnowledgeServer(t, "", http.StatusUnauthorized)
	t.Cleanup(srv.Close)
	t.Setenv(cbAPIURLEnv, srv.URL)

	stream := &fakeStreamer{chunks: []string{`{"findings":[]}`}}
	a := newTestAnalyzer(stream)
	a.iacType = IaCTypeCloudFormation
	a.cbKnowledge = true
	a.rules = rulesbundletest.Pack(t)

	findings, err := a.ScanResources(context.Background(), syntheticResources(2))
	if err != nil {
		t.Fatalf("ScanResources: %v", err)
	}
	if len(findings) != 1 || findings[0].RuleID != "LLM-ERROR" {
		t.Fatalf("expected the single LLM-ERROR abort finding, got %+v", findings)
	}
	if !strings.Contains(findings[0].Description, "401") {
		t.Errorf("abort finding should surface the auth status, got %q", findings[0].Description)
	}
	if stream.prompt != "" {
		t.Errorf("the LLM stream must not run when grounding aborts")
	}
}
