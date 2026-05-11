package audit

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// withFakeClaudeStreamJSON installs a fake `claude` on PATH that emits
// pre-canned NDJSON on stdout. The script ignores its argv and prompt
// payload; tests assert on the parser, not on argv plumbing (the latter is
// covered separately via TestGroundedStreamer_AssertsCBXConnected).
func withFakeClaudeStreamJSON(t *testing.T, ndjson string) func() {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary trick is POSIX-only")
	}

	dir := t.TempDir()
	script := "#!/bin/sh\n"
	script += "cat > /dev/null\n"
	script += "cat <<'__CBX_EOF__'\n" + ndjson + "\n__CBX_EOF__\n"
	binPath := filepath.Join(dir, "claude")
	if err := os.WriteFile(binPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+origPath)
	origBinary := claudeCodeBinary
	claudeCodeBinary = "claude"
	return func() { claudeCodeBinary = origBinary }
}

// withFakeCBXMCPCheckout writes a stub cbx-mcp pyproject.toml so
// resolveCBXMCPPath succeeds without depending on the real sibling checkout.
func withFakeCBXMCPCheckout(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pyproject.toml"), []byte("[project]\nname=\"cbx-mcp\"\n"), 0o644); err != nil {
		t.Fatalf("seed pyproject.toml: %v", err)
	}
	t.Setenv(cbxMCPPathEnv, dir)
	return dir
}

const grounded_initOK = `{"type":"system","subtype":"init","mcp_servers":[{"name":"cbx","status":"connected"}],"model":"claude-opus","session_id":"s1"}`
const grounded_initFailed = `{"type":"system","subtype":"init","mcp_servers":[{"name":"cbx","status":"failed"}],"model":"claude-opus","session_id":"s1"}`
const grounded_initMissing = `{"type":"system","subtype":"init","mcp_servers":[{"name":"other","status":"connected"}],"model":"claude-opus","session_id":"s1"}`
const grounded_toolCall = `{"type":"assistant","message":{"content":[{"type":"tool_use","id":"tu1","name":"mcp__cbx__aws_lookup_primitive","input":{"type_id":"aws:s3/bucket@v1"}}]}}`
const grounded_toolResult = `{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"tu1","content":"{\"kb_version\":\"stub\",\"chunks\":[]}"}]},"tool_use_result":{"structuredContent":{"kb_version":"stub","chunks":[{"doc_path":"aws/s3/bucket","chunk_text":"Private bucket; CloudFront OAC."}]}}}`
const grounded_resultOK = `{"type":"result","result":"{\"findings\":[]}","num_turns":3,"total_cost_usd":0.17,"duration_ms":1234,"is_error":false}`

func TestGroundedStreamer_ParsesTrailAndFinalResult(t *testing.T) {
	withFakeCBXMCPCheckout(t)
	restore := withFakeClaudeStreamJSON(t, strings.Join([]string{
		grounded_initOK,
		grounded_toolCall,
		grounded_toolResult,
		grounded_resultOK,
	}, "\n"))
	defer restore()

	s, err := newGroundedClaudeStreamer()
	if err != nil {
		t.Fatalf("newGroundedClaudeStreamer: %v", err)
	}

	var sb strings.Builder
	if err := s.Stream(context.Background(), "prompt", func(tok string) { sb.WriteString(tok) }); err != nil {
		t.Fatalf("Stream: %v", err)
	}

	if got := sb.String(); !strings.Contains(got, "findings") {
		t.Errorf("expected final result.result to be surfaced via onToken; got %q", got)
	}
	if got := s.TotalCostUSD(); got != 0.17 {
		t.Errorf("total_cost_usd = %f, want 0.17", got)
	}
	trail := s.GroundingTrail()
	if len(trail) != 1 {
		t.Fatalf("expected 1 grounding event, got %d", len(trail))
	}
	if trail[0].Tool != "aws_lookup_primitive" {
		t.Errorf("tool = %q, want aws_lookup_primitive (prefix stripped)", trail[0].Tool)
	}
	if trail[0].StructuredResult == nil || trail[0].StructuredResult["kb_version"] != "stub" {
		t.Errorf("structured result not parsed: %+v", trail[0].StructuredResult)
	}
}

func TestGroundedStreamer_FailsFastOnCBXNotConnected(t *testing.T) {
	withFakeCBXMCPCheckout(t)
	restore := withFakeClaudeStreamJSON(t, strings.Join([]string{
		grounded_initFailed,
		grounded_resultOK,
	}, "\n"))
	defer restore()

	s, err := newGroundedClaudeStreamer()
	if err != nil {
		t.Fatalf("newGroundedClaudeStreamer: %v", err)
	}
	err = s.Stream(context.Background(), "prompt", func(string) {})
	if err == nil {
		t.Fatal("expected error when cbx mcp server reports status!=connected")
	}
	if !strings.Contains(err.Error(), "cbx-mcp connection failed") {
		t.Errorf("error should mention connection failure; got %v", err)
	}
}

func TestGroundedStreamer_FailsFastWhenCBXMissingFromInit(t *testing.T) {
	withFakeCBXMCPCheckout(t)
	restore := withFakeClaudeStreamJSON(t, strings.Join([]string{
		grounded_initMissing,
		grounded_resultOK,
	}, "\n"))
	defer restore()

	s, err := newGroundedClaudeStreamer()
	if err != nil {
		t.Fatalf("newGroundedClaudeStreamer: %v", err)
	}
	err = s.Stream(context.Background(), "prompt", func(string) {})
	if err == nil {
		t.Fatal("expected error when init event omits cbx server")
	}
	if !strings.Contains(err.Error(), "MCP server") {
		t.Errorf("error should hint at MCP wiring; got %v", err)
	}
}

func TestGroundedStreamer_FailsWhenResultEventMissing(t *testing.T) {
	withFakeCBXMCPCheckout(t)
	restore := withFakeClaudeStreamJSON(t, grounded_initOK)
	defer restore()

	s, err := newGroundedClaudeStreamer()
	if err != nil {
		t.Fatalf("newGroundedClaudeStreamer: %v", err)
	}
	err = s.Stream(context.Background(), "prompt", func(string) {})
	if err == nil || !strings.Contains(err.Error(), "result") {
		t.Fatalf("expected missing-result error, got %v", err)
	}
}

func TestWriteMCPConfig_StubModeInjectsEnv(t *testing.T) {
	dir := t.TempDir()
	cbxPath := "/tmp/fake-cbx-mcp"
	cfgPath, err := writeMCPConfig(dir, cbxPath, true)
	if err != nil {
		t.Fatalf("writeMCPConfig: %v", err)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read cfg: %v", err)
	}
	s := string(data)
	for _, want := range []string{`"cbx"`, `"uvx"`, `"--from"`, cbxPath, `"CBX_MCP_KB_STUB": "1"`} {
		if !strings.Contains(s, want) {
			t.Errorf("config missing %q in:\n%s", want, s)
		}
	}
}

func TestWriteMCPConfig_BackendModeOmitsStubEnv(t *testing.T) {
	dir := t.TempDir()
	cfgPath, err := writeMCPConfig(dir, "/tmp/fake-cbx-mcp", false)
	if err != nil {
		t.Fatalf("writeMCPConfig: %v", err)
	}
	data, _ := os.ReadFile(cfgPath)
	if strings.Contains(string(data), "CBX_MCP_KB_STUB") {
		t.Errorf("backend mode must not set CBX_MCP_KB_STUB:\n%s", data)
	}
}

func TestResolveCBXMCPPath_EnvVarWins(t *testing.T) {
	dir := withFakeCBXMCPCheckout(t)
	got, err := resolveCBXMCPPath()
	if err != nil {
		t.Fatalf("resolveCBXMCPPath: %v", err)
	}
	if got != dir {
		t.Errorf("path = %q, want %q", got, dir)
	}
}

func TestResolveCBXMCPPath_RejectsNonCheckout(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(cbxMCPPathEnv, dir)
	if _, err := resolveCBXMCPPath(); err == nil {
		t.Fatal("expected error when CBX_MCP_PATH lacks pyproject.toml")
	}
}
