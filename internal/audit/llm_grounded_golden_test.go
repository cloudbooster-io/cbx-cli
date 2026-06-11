package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/rulesbundle"
)

// TestGroundedPromptGolden pins the fully-assembled grounded prompt for
// the kitchen-sink fixture byte-for-byte. Together with the embedded
// rulepack's content_sha256 self-check and TestEmbeddedBundleSHA, this
// is the permanent successor of the P0 dual-builder byte-identity test
// (the legacy inline-literal builder was deleted once that test proved
// the extraction byte-identical — see the refactor commit).
//
// The prose IS the recall: an unexplained diff here is a recall
// regression, not a cosmetic change. Deliberate prompt changes must
// regenerate the golden (CBX_UPDATE_GOLDEN=1 go test ./internal/audit
// -run TestGroundedPromptGolden) and are fixtures-sweep-gated.
func TestGroundedPromptGolden(t *testing.T) {
	var fx groundedPromptFixture
	for _, f := range groundedPromptFixtures() {
		if f.name == "kitchen-sink" {
			fx = f
		}
	}
	if fx.name == "" {
		t.Fatal("kitchen-sink fixture missing from groundedPromptFixtures")
	}

	got := buildGroundedPrompt(IaCTypeTerraform, fx.files, fx.resources, fx.bundle, fx.posture, rulesbundle.Embedded())

	path := filepath.Join("testdata", "grounded_prompt_kitchen_sink.golden")
	if os.Getenv("CBX_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (CBX_UPDATE_GOLDEN=1 regenerates): %v", err)
	}
	if got == string(want) {
		return
	}
	i := firstByteDiff(got, string(want))
	t.Fatalf("assembled grounded prompt diverged from golden at byte %d (got %d bytes, want %d):\ngolden:  %q\ncurrent: %q\nIf this change is deliberate: regenerate with CBX_UPDATE_GOLDEN=1 and treat it as sweep-gated.",
		i, len(got), len(want), contextWindow(string(want), i), contextWindow(got, i))
}

func firstByteDiff(a, b string) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

func contextWindow(s string, i int) string {
	start := i - 80
	if start < 0 {
		start = 0
	}
	end := i + 80
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}
