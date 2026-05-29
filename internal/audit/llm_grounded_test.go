package audit

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/knowledge"
)

// requireLocalCBBackend skips the test when the local platform-app dev
// backend isn't reachable on the default URL. We deliberately do NOT
// stand up a fake server: the preflight is part of the contract being
// tested and faking it out would defeat the point.
func requireLocalCBBackend(t *testing.T) {
	t.Helper()
	client := &http.Client{Timeout: 1 * time.Second}
	resp, err := client.Get(defaultCBAPIURL + "/health")
	if err != nil {
		t.Skipf("local CB backend not running at %s (%v); skipping grounded streamer tests", defaultCBAPIURL, err)
	}
	resp.Body.Close()
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
	restore := withFakeClaudeText(t, `{"findings":[]}`)
	defer restore()

	s, err := newGroundedClaudeStreamer()
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
	restore := withFakeClaudeText(t, `{"findings":[]}`)
	defer restore()

	s, err := newGroundedClaudeStreamer()
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
