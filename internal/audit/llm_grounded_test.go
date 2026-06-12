package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/knowledge"
)

// requireLocalCBBackend skips the test when the resolved CB backend
// (CB_API_URL when set, otherwise the production default) isn't
// reachable. We deliberately do NOT stand up a fake server: the
// preflight is part of the contract being tested and faking it out
// would defeat the point.
func requireLocalCBBackend(t *testing.T) {
	t.Helper()
	apiURL := resolvedCBAPIURL()
	client := &http.Client{Timeout: 1 * time.Second}
	resp, err := client.Get(apiURL + "/health")
	if err != nil {
		t.Skipf("CB backend not running at %s (%v); skipping grounded streamer tests", apiURL, err)
	}
	resp.Body.Close()
}

// fakeClaudeStreamJSON wraps a response text in the minimal stream-json
// shape a real `claude -p --output-format stream-json` run emits: an
// init event plus the final result event carrying the text and cost.
func fakeClaudeStreamJSON(t *testing.T, text string, cost float64) string {
	t.Helper()
	result, err := json.Marshal(map[string]any{
		"type":           "result",
		"subtype":        "success",
		"result":         text,
		"total_cost_usd": cost,
	})
	if err != nil {
		t.Fatalf("marshal fake result event: %v", err)
	}
	return `{"type":"system","subtype":"init"}` + "\n" + string(result)
}

// withFakeClaudeText installs a fake `claude` on PATH that echoes a
// canned text response. The script ignores stdin and argv; tests assert
// on the streamer wiring, not the model.
func withFakeClaudeText(t *testing.T, response string) func() {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary trick is POSIX-only")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\ncat > /dev/null\ncat <<'__CBX_EOF__'\n" + response + "\n__CBX_EOF__\n"
	binPath := filepath.Join(dir, "claude")
	if err := os.WriteFile(binPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	origBinary := claudeCodeBinary
	claudeCodeBinary = "claude"
	return func() { claudeCodeBinary = origBinary }
}

func TestGroundedStreamer_EchoesStdoutAsFinalText(t *testing.T) {
	requireLocalCBBackend(t)
	restore := withFakeClaudeText(t, fakeClaudeStreamJSON(t, `{"findings":[]}`, 0.01))
	defer restore()

	s, err := newGroundedClaudeStreamer("")
	if err != nil {
		t.Fatalf("newGroundedClaudeStreamer: %v", err)
	}

	var sb strings.Builder
	if err := s.Stream(context.Background(), "prompt", func(tok string) { sb.WriteString(tok) }); err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if got := sb.String(); !strings.Contains(got, `"findings"`) {
		t.Errorf("expected stdout surfaced via onToken; got %q", got)
	}
}

func TestGroundedStreamer_InstallBundleSeedsTrail(t *testing.T) {
	requireLocalCBBackend(t)
	restore := withFakeClaudeText(t, fakeClaudeStreamJSON(t, `{"findings":[]}`, 0.01))
	defer restore()

	s, err := newGroundedClaudeStreamer("")
	if err != nil {
		t.Fatalf("newGroundedClaudeStreamer: %v", err)
	}

	bundle := &GroundingBundle{
		Primitives: []PrimitiveKnowledge{
			{
				TypeID: "aws:s3/bucket@v1",
				Data: &knowledge.Response{
					KBVersion: 7,
					Chunks: []knowledge.Chunk{
						{DocPath: "aws/s3/bucket/primitive.md", ChunkText: "Private bucket; CloudFront OAC."},
					},
				},
			},
		},
	}
	s.InstallBundle(bundle)

	trail := s.GroundingTrail()
	if len(trail) != 1 {
		t.Fatalf("expected 1 trail event, got %d", len(trail))
	}
	if trail[0].Tool != "aws_lookup_primitive" {
		t.Errorf("tool = %q, want aws_lookup_primitive", trail[0].Tool)
	}
	if got := trail[0].Input["type_id"]; got != "aws:s3/bucket@v1" {
		t.Errorf("type_id = %v, want aws:s3/bucket@v1", got)
	}
}

func TestPreflightCBBackend_RejectsBadURL(t *testing.T) {
	if err := preflightCBBackend("not-a-url"); err == nil {
		t.Fatal("expected error for malformed URL")
	}
}

// fakeClaudeBinaryAt writes a fake `claude` script that drains stdin and
// echoes a canned response, returning the binary's path so tests can
// construct groundedClaudeStreamer directly — no PATH mutation, no CB
// backend preflight.
func fakeClaudeBinaryAt(t *testing.T, response string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary trick is POSIX-only")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\ncat > /dev/null\ncat <<'__CBX_EOF__'\n" + response + "\n__CBX_EOF__\n"
	binPath := filepath.Join(dir, "claude")
	if err := os.WriteFile(binPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	return binPath
}

func TestParseClaudeStreamJSON_ResultEventAndCost(t *testing.T) {
	out := strings.Join([]string{
		`{"type":"system","subtype":"init","session_id":"s1"}`,
		`{"type":"assistant","message":{"content":[{"type":"text","text":"thinking…"}]}}`,
		`{"type":"result","subtype":"success","result":"{\"findings\":[]}","total_cost_usd":0.042}`,
	}, "\n")

	text, cost, ok := parseClaudeStreamJSON([]byte(out))
	if !ok {
		t.Fatal("expected ok for valid stream-json output")
	}
	if text != `{"findings":[]}` {
		t.Errorf("text = %q, want the result event's result field", text)
	}
	if cost != 0.042 {
		t.Errorf("cost = %v, want 0.042", cost)
	}
}

func TestParseClaudeStreamJSON_LastResultEventWins(t *testing.T) {
	out := strings.Join([]string{
		`{"type":"result","result":"first","total_cost_usd":0.01}`,
		`{"type":"result","result":"second","total_cost_usd":0.02}`,
	}, "\n")

	text, cost, ok := parseClaudeStreamJSON([]byte(out))
	if !ok || text != "second" || cost != 0.02 {
		t.Errorf("got (%q, %v, %v), want the last result event (second, 0.02, true)", text, cost, ok)
	}
}

func TestParseClaudeStreamJSON_LegacyCostSpelling(t *testing.T) {
	text, cost, ok := parseClaudeStreamJSON([]byte(`{"type":"result","result":"r","cost_usd":0.5}`))
	if !ok || text != "r" || cost != 0.5 {
		t.Errorf("got (%q, %v, %v), want cost_usd honored when total_cost_usd absent", text, cost, ok)
	}
}

func TestParseClaudeStreamJSON_PlainTextNotOK(t *testing.T) {
	for _, raw := range []string{
		`{"findings":[]}`,   // plain JSON response, no result event
		"not json at all",   // prose
		`{"type":"result"}`, // result event without a result field
		"",                  // empty
	} {
		if _, _, ok := parseClaudeStreamJSON([]byte(raw)); ok {
			t.Errorf("parseClaudeStreamJSON(%q) ok = true, want false (fallback path)", raw)
		}
	}
}

func TestGroundedStreamer_StreamJSON_ExtractsResultAndCost(t *testing.T) {
	response := `{"type":"system","subtype":"init"}` + "\n" +
		`{"type":"result","subtype":"success","result":"{\"findings\":[]}","total_cost_usd":1.25}`
	s := &groundedClaudeStreamer{binary: fakeClaudeBinaryAt(t, response)}

	var sb strings.Builder
	if err := s.Stream(context.Background(), "prompt", func(tok string) { sb.WriteString(tok) }); err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if got := sb.String(); got != `{"findings":[]}` {
		t.Errorf("onToken text = %q, want the result event's text only", got)
	}
	if got := s.TotalCostUSD(); got != 1.25 {
		t.Errorf("TotalCostUSD = %v, want 1.25 (assigned from total_cost_usd)", got)
	}
}

func TestGroundedStreamer_PlainTextFallback_CostStaysZero(t *testing.T) {
	// Older claude builds (or shims) that ignore --output-format stream-json
	// emit plain text; the streamer must degrade to surfacing raw stdout
	// with cost 0 instead of failing the audit.
	s := &groundedClaudeStreamer{binary: fakeClaudeBinaryAt(t, `{"findings":[]}`)}

	var sb strings.Builder
	if err := s.Stream(context.Background(), "prompt", func(tok string) { sb.WriteString(tok) }); err != nil {
		t.Fatalf("Stream: %v", err)
	}
	if got := sb.String(); !strings.Contains(got, `"findings"`) {
		t.Errorf("fallback should surface raw stdout, got %q", got)
	}
	if got := s.TotalCostUSD(); got != 0 {
		t.Errorf("TotalCostUSD = %v, want 0 on the plain-text fallback path", got)
	}
}

// fakeClaudeArgsRecorderAt is fakeClaudeBinaryAt plus argv capture: the
// script writes its arguments (one per line) to args.txt next to the
// binary before echoing the response, so tests can assert the exact
// flags Stream passes.
func fakeClaudeArgsRecorderAt(t *testing.T, response string) (binPath, argsFile string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary trick is POSIX-only")
	}
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args.txt")
	script := "#!/bin/sh\ncat > /dev/null\nprintf '%s\\n' \"$@\" > '" + argsFile + "'\ncat <<'__CBX_EOF__'\n" + response + "\n__CBX_EOF__\n"
	binPath = filepath.Join(dir, "claude")
	if err := os.WriteFile(binPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	return binPath, argsFile
}

func TestGroundedStreamer_ModelPin_PassesModelFlag(t *testing.T) {
	bin, argsFile := fakeClaudeArgsRecorderAt(t, fakeClaudeStreamJSON(t, `{"findings":[]}`, 0))
	s := &groundedClaudeStreamer{binary: bin, model: "claude-opus-4-8"}

	if err := s.Stream(context.Background(), "prompt", func(string) {}); err != nil {
		t.Fatalf("Stream: %v", err)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read recorded args: %v", err)
	}
	args := strings.Split(strings.TrimSpace(string(raw)), "\n")
	found := false
	for i, a := range args {
		if a == "--model" && i+1 < len(args) && args[i+1] == "claude-opus-4-8" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected --model claude-opus-4-8 in claude argv, got %v", args)
	}
}

func TestGroundedStreamer_NoModelPin_NoModelFlag(t *testing.T) {
	bin, argsFile := fakeClaudeArgsRecorderAt(t, fakeClaudeStreamJSON(t, `{"findings":[]}`, 0))
	s := &groundedClaudeStreamer{binary: bin}

	if err := s.Stream(context.Background(), "prompt", func(string) {}); err != nil {
		t.Fatalf("Stream: %v", err)
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read recorded args: %v", err)
	}
	if strings.Contains(string(raw), "--model") {
		t.Errorf("no model pinned but --model passed: %q", string(raw))
	}
}

func TestGroundedStreamer_NonZeroExit_FallsBackToStdout(t *testing.T) {
	// `claude -p` reports auth/model/limit failures on STDOUT with an
	// empty stderr; the streamer error must carry that message instead
	// of a bare "exited 1".
	if runtime.GOOS == "windows" {
		t.Skip("fake-binary trick is POSIX-only")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\ncat > /dev/null\nprintf '%s' 'Invalid API key · Please run /login'\nexit 1\n"
	binPath := filepath.Join(dir, "claude")
	if err := os.WriteFile(binPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	s := &groundedClaudeStreamer{binary: binPath}

	streamErr := s.Stream(context.Background(), "prompt", func(string) {})
	if streamErr == nil {
		t.Fatal("expected error on non-zero exit")
	}
	if !strings.Contains(streamErr.Error(), "Invalid API key") {
		t.Errorf("expected stdout message in error; got %v", streamErr)
	}
	if !strings.Contains(streamErr.Error(), "exited 1") {
		t.Errorf("expected exit code in error; got %v", streamErr)
	}
}
