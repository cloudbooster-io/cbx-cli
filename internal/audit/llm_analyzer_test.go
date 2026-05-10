package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
