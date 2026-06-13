// Package assets serves embedded binary assets shared across the
// cbx-cli codebase. The mermaid runtime lives here so `cbx audit aws`'s
// HTML report can render diagrams from the embedded payload (~300KB
// gzipped) without a network fetch.
package assets

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"io"
	"sync"
)

//go:embed mermaid.min.js.gz
var mermaidJSGz []byte

var (
	mermaidOnce sync.Once
	mermaidJS   string
	mermaidErr  error
)

// MermaidJS returns the decompressed mermaid.min.js source ready to be
// inlined inside a <script> tag. Decompression happens once per process
// and the result is cached.
func MermaidJS() (string, error) {
	mermaidOnce.Do(func() {
		r, err := gzip.NewReader(bytes.NewReader(mermaidJSGz))
		if err != nil {
			mermaidErr = fmt.Errorf("opening embedded mermaid gzip: %w", err)
			return
		}
		defer func() { _ = r.Close() }()
		data, err := io.ReadAll(r)
		if err != nil {
			mermaidErr = fmt.Errorf("reading embedded mermaid bytes: %w", err)
			return
		}
		mermaidJS = string(data)
	})
	return mermaidJS, mermaidErr
}
