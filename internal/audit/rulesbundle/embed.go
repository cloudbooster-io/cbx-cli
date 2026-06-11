package rulesbundle

import (
	_ "embed"
	"fmt"
	"sync"
)

// embeddedRaw is the rule pack compiled into the binary. In P0 it is
// the ONLY pack source; later phases resolve network → cache →
// embedded, with this artifact as the last-known-good floor. It is
// refreshed by regenerating the JSON (never hand-edited): the
// TestEmbeddedBundleSHA pin and the manifest content_sha256 self-check
// both fail on any drift, including editor reflow.
//
//go:embed embedded/cb-aws-audit.schema1.json
var embeddedRaw []byte

var (
	embeddedOnce sync.Once
	embeddedPack *RulePack
	embeddedErr  error
)

// Embedded returns the validated rule pack compiled into the binary.
// Parsing and validation run once; failure panics, because a binary
// whose embedded artifact is corrupt cannot produce a grounded audit —
// this is a build-time invariant (any `go test ./...` run trips it),
// not a runtime condition to degrade through.
func Embedded() *RulePack {
	embeddedOnce.Do(func() {
		embeddedPack, embeddedErr = Parse(embeddedRaw)
	})
	if embeddedErr != nil {
		panic(fmt.Sprintf("rulesbundle: embedded rule pack invalid: %v", embeddedErr))
	}
	return embeddedPack
}

// EmbeddedBytes returns a copy of the raw embedded artifact, for
// integrity pinning (sha256) in tests and provenance reporting.
func EmbeddedBytes() []byte {
	out := make([]byte, len(embeddedRaw))
	copy(out, embeddedRaw)
	return out
}
