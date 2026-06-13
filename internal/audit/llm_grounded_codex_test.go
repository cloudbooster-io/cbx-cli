package audit

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/rulesbundle/rulesbundletest"
)

// withFakeCodexBinary writes a tiny shell script that mimics `codex exec`
// at <tmp>/codex, prepends its dir to PATH, and points codexBinary at it.
// The script reads stdin and echoes the supplied response on stdout,
// optionally exiting non-zero. Mirrors withFakeClaudeBinary. Returns a
// restore function.
func withFakeCodexBinary(t *testing.T, response string, exitCode int) func() {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary trick is POSIX-only; subprocess path covered on linux/darwin")
	}

	dir := t.TempDir()
	script := "#!/bin/sh\n"
	script += "cat > /dev/null\n" // drain stdin so the cmd doesn't block on a closed pipe
	script += "printf '%s' " + shellQuote(response) + "\n"
	if exitCode != 0 {
		script += "exit " + itoa(exitCode) + "\n"
	}
	binPath := filepath.Join(dir, "codex")
	if err := os.WriteFile(binPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	origBinary := codexBinary
	codexBinary = "codex"

	return func() { codexBinary = origBinary }
}

func TestGroundedCodexStreamer_Stream_HappyPath(t *testing.T) {
	useFakeKnowledgeBackend(t) // newGroundedCodexStreamer preflights the CB backend
	restore := withFakeCodexBinary(t, `{"findings":[{"title":"From Codex","severity":"high","resource":"r1"}]}`, 0)
	defer restore()

	s, err := newGroundedCodexStreamer("")
	if err != nil {
		t.Fatalf("newGroundedCodexStreamer: %v", err)
	}
	var sb strings.Builder
	if err := s.Stream(context.Background(), "audit this", func(tok string) { sb.WriteString(tok) }); err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if !strings.Contains(sb.String(), "From Codex") {
		t.Errorf("expected fake codex response on stdout, got %q", sb.String())
	}
}

func TestGroundedCodexStreamer_NonZeroExitSurfacesMessage(t *testing.T) {
	useFakeKnowledgeBackend(t)
	// codex (like claude) can report failures on stdout with empty stderr;
	// the error must carry that message, not a bare "exited 1".
	restore := withFakeCodexBinary(t, "stream error: 401 Unauthorized", 1)
	defer restore()

	s, err := newGroundedCodexStreamer("")
	if err != nil {
		t.Fatalf("newGroundedCodexStreamer: %v", err)
	}
	streamErr := s.Stream(context.Background(), "x", func(string) {})
	if streamErr == nil {
		t.Fatal("expected error on non-zero exit")
	}
	if !strings.Contains(streamErr.Error(), "401 Unauthorized") || !strings.Contains(streamErr.Error(), "exited 1") {
		t.Errorf("expected codex message + exit code in error; got %v", streamErr)
	}
}

func TestGroundedCodexStreamer_TrailAndZeroCost(t *testing.T) {
	// Construct directly — no binary/backend needed to exercise the
	// grounding-interface contract the analyzer relies on.
	g := &groundedCodexStreamer{}
	if g.TotalCostUSD() != 0 {
		t.Fatalf("codex must report 0 cost (cap unenforced); got %v", g.TotalCostUSD())
	}
	if g.GroundingTrail() != nil {
		t.Fatalf("expected nil trail before InstallBundle")
	}
	g.InstallBundle(&GroundingBundle{
		Primitives: []PrimitiveKnowledge{{TypeID: "aws:s3/bucket@v1", Missing: true}},
	})
	if len(g.GroundingTrail()) == 0 {
		t.Fatalf("InstallBundle should seed the grounding trail")
	}
	// Cost stays 0 even after a bundle install — codex exec has no cost.
	if g.TotalCostUSD() != 0 {
		t.Fatalf("codex cost must remain 0; got %v", g.TotalCostUSD())
	}
	// nil bundle clears the trail.
	g.InstallBundle(nil)
	if g.GroundingTrail() != nil {
		t.Fatalf("nil bundle should clear the trail")
	}
}

// TestGroundedCodexStreamer_SatisfiesGroundingInterfaces pins that the
// codex grounded streamer implements the optional capabilities the analyzer
// probes via type assertion (bundleInstaller + groundingTrailer). If it ever
// stops, postProcessGrounded silently skips snippet backfill for codex.
func TestGroundedCodexStreamer_SatisfiesGroundingInterfaces(t *testing.T) {
	var s any = &groundedCodexStreamer{}
	if _, ok := s.(llmStreamer); !ok {
		t.Error("groundedCodexStreamer must implement llmStreamer")
	}
	if _, ok := s.(bundleInstaller); !ok {
		t.Error("groundedCodexStreamer must implement bundleInstaller")
	}
	if _, ok := s.(groundingTrailer); !ok {
		t.Error("groundedCodexStreamer must implement groundingTrailer")
	}
}

func TestNewGroundedCLIStreamer_DispatchesByExecutor(t *testing.T) {
	useFakeKnowledgeBackend(t)
	restoreCodex := withFakeCodexBinary(t, "ok", 0)
	defer restoreCodex()
	restoreClaude := withFakeClaudeBinary(t, "ok", 0)
	defer restoreClaude()

	cs, err := newGroundedCLIStreamer(CodexProvider, "")
	if err != nil {
		t.Fatalf("newGroundedCLIStreamer(codex): %v", err)
	}
	if _, ok := cs.(*groundedCodexStreamer); !ok {
		t.Errorf("expected *groundedCodexStreamer, got %T", cs)
	}

	cc, err := newGroundedCLIStreamer(ClaudeCodeProvider, "")
	if err != nil {
		t.Fatalf("newGroundedCLIStreamer(claude-code): %v", err)
	}
	if _, ok := cc.(*groundedClaudeStreamer); !ok {
		t.Errorf("expected *groundedClaudeStreamer, got %T", cc)
	}

	if _, err := newGroundedCLIStreamer("nope", ""); err == nil {
		t.Errorf("expected error for unknown grounded executor")
	}
}

func TestNewLLMAnalyzer_CodexProvider_NonGrounded(t *testing.T) {
	restore := withFakeCodexBinary(t, `{"findings":[]}`, 0)
	defer restore()

	a, err := newLLMAnalyzer(Options{LLMProvider: CodexProvider}, IaCTypeTerraform)
	if err != nil {
		t.Fatalf("newLLMAnalyzer(codex): %v", err)
	}
	if a.provider != CodexProvider {
		t.Errorf("provider = %q, want %q", a.provider, CodexProvider)
	}
	if a.providerForRuleID != "codex" {
		t.Errorf("providerForRuleID = %q, want codex", a.providerForRuleID)
	}
	if _, ok := a.streamer.(*codexCLIStreamer); !ok {
		t.Errorf("expected *codexCLIStreamer, got %T", a.streamer)
	}
}

// TestLLMAnalyzer_GroundedCodex_ParsesFindingsAndConnections runs the full
// grounded source path through a real groundedCodexStreamer backed by a fake
// codex binary. It proves findings parse from a codex-shaped (code-fenced)
// response, connections are extracted, and the cost cap degrades silently:
// codex reports 0 cost, so even a tiny --llm-max-cost adds no finding and
// never panics.
func TestLLMAnalyzer_GroundedCodex_ParsesFindingsAndConnections(t *testing.T) {
	useFakeKnowledgeBackend(t)
	// gpt-class models commonly wrap JSON in a ```json fence — the tolerant
	// parser must still extract it.
	resp := "```json\n" +
		`{"findings":[{"rule_id":"LLM-CB-700","title":"S3 public","severity":"high","resource":"aws_s3_bucket.x","service":"S3","cb_source":{"tool":"aws_lookup_primitive","key":"aws:s3/bucket@v1","snippet":"Private bucket."}}],` +
		`"connections":[{"from":"aws_s3_bucket.x","to":"aws_cloudfront_distribution.cdn","label":"origin"}]}` +
		"\n```"
	restore := withFakeCodexBinary(t, resp, 0)
	defer restore()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`resource "aws_s3_bucket" "x" {}`), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	streamer, err := newGroundedCodexStreamer("")
	if err != nil {
		t.Fatalf("newGroundedCodexStreamer: %v", err)
	}
	a := &llmAnalyzer{
		provider:          CodexProvider,
		streamer:          streamer,
		maxFiles:          50,
		maxBytesPerFile:   64 * 1024,
		iacType:           IaCTypeTerraform,
		providerForRuleID: "codex",
		cbKnowledge:       true,
		rules:             rulesbundletest.Pack(t),
		// Tiny cap: codex's 0 cost must NOT trip it (no panic, no finding).
		maxCostUSD: 0.01,
	}

	findings, err := a.ScanSource(context.Background(), dir)
	if err != nil {
		t.Fatalf("ScanSource: %v", err)
	}
	// Grounded finding present (cb_source set → no ungrounded summary, no
	// cost finding — exactly one finding).
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (cost cap must add none), got %d: %+v", len(findings), findings)
	}
	if findings[0].RuleID != "LLM-CB-700" || findings[0].CBSource == nil {
		t.Errorf("grounded finding not parsed from codex response: %+v", findings[0])
	}
	conns := a.LastConnections()
	if len(conns) != 1 || conns[0].From != "aws_s3_bucket.x" || conns[0].To != "aws_cloudfront_distribution.cdn" {
		t.Errorf("connection not parsed from codex response: %+v", conns)
	}
	// Degradation contract: codex surfaces no cost regardless of the run.
	if streamer.TotalCostUSD() != 0 {
		t.Errorf("codex cost must be 0; got %v", streamer.TotalCostUSD())
	}
}
