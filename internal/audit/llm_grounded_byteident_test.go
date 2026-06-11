package audit

import (
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/rulesbundle"
)

// TestGroundedPromptByteIdentical is the P0 acceptance gate for the
// rulepack extraction: the rulepack-backed buildGroundedPrompt must
// reproduce the legacy inline-literal builder BYTE-FOR-BYTE across the
// whole fixture matrix. The prose is the recall — any drift (a glyph,
// a space, an ordering change) is a recall regression, not a cosmetic
// diff.
//
// This test (and buildGroundedPromptLegacy) lives only for the
// migration commit; the follow-up commit replaces both with a pinned
// prompt golden file + the embedded-artifact SHA pin.
func TestGroundedPromptByteIdentical(t *testing.T) {
	pack := rulesbundle.Embedded()
	for _, fx := range groundedPromptFixtures() {
		t.Run(fx.name, func(t *testing.T) {
			want := buildGroundedPromptLegacy(IaCTypeTerraform, fx.files, fx.resources, fx.bundle, fx.posture)
			got := buildGroundedPrompt(IaCTypeTerraform, fx.files, fx.resources, fx.bundle, fx.posture, pack)
			if got == want {
				return
			}
			i := firstByteDiff(got, want)
			t.Fatalf("grounded prompt diverged from legacy builder at byte %d:\nlegacy: %q\nrulepack: %q",
				i, contextWindow(want, i), contextWindow(got, i))
		})
	}
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
