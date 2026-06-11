package rulesbundle

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// embeddedArtifactSHA256 pins the exact bytes of
// embedded/cb-aws-audit.schema1.json. The artifact is generated, never
// hand-edited — this pin catches editor reflow, formatter passes, and
// accidental whitespace churn forever, on top of the manifest's
// content_sha256 self-check (which covers only the rendered prose).
//
// If you changed the artifact DELIBERATELY: the prose is the recall, so
// the change is fixtures-sweep-gated; update this constant in the same
// commit and reference the sweep in the MR.
const embeddedArtifactSHA256 = "f9311799a843d288583d1c185fb424b5a8175da6d56c4fcb9ded18b435f2bd98"

func TestEmbeddedBundleSHA(t *testing.T) {
	sum := sha256.Sum256(EmbeddedBytes())
	if got := hex.EncodeToString(sum[:]); got != embeddedArtifactSHA256 {
		t.Fatalf("embedded rulepack artifact sha256 = %s, pinned %s — the artifact bytes changed; if deliberate, update the pin in the same commit and sweep-gate the change", got, embeddedArtifactSHA256)
	}
}
