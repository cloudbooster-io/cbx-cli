package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/rulesbundle/rulesbundletest"
)

// TestGroundedPromptGolden pins the fully-assembled grounded prompt for
// the kitchen-sink fixture byte-for-byte — built against the SYNTHETIC
// rulesbundletest pack, so what it locks is the ASSEMBLY: section
// order, separators, the rulepack render (groups, sub-items,
// cross-refs), and every compiled-in serializer (posture, knowledge
// bundle, resource table incl. truncation, source files). It is
// deliberately content-free: production rule prose is server-owned and
// its contract is exercised by the e2e_staging tier, not here.
//
// An unexplained diff here means the prompt builder changed shape.
// Deliberate assembly changes must regenerate the golden:
//
//	CBX_UPDATE_GOLDEN=1 go test ./internal/audit -run TestGroundedPromptGolden
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

	got := buildGroundedPrompt(IaCTypeTerraform, fx.files, fx.resources, fx.bundle, fx.posture, rulesbundletest.Pack(t))

	path := filepath.Join("testdata", "grounded_prompt_kitchen_sink.golden")
	if os.Getenv("CBX_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v\nRegenerate: CBX_UPDATE_GOLDEN=1 go test ./internal/audit -run TestGroundedPromptGolden", err)
	}
	if strings.HasPrefix(string(want), "REGENERATE:") {
		t.Fatal("golden is a placeholder, not a recorded prompt.\nRegenerate: CBX_UPDATE_GOLDEN=1 go test ./internal/audit -run TestGroundedPromptGolden")
	}
	if got == string(want) {
		return
	}
	i := firstByteDiff(got, string(want))
	t.Fatalf("assembled grounded prompt diverged from golden at byte %d (got %d bytes, want %d):\ngolden:  %q\ncurrent: %q\nIf this assembly change is deliberate: regenerate with CBX_UPDATE_GOLDEN=1.",
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
