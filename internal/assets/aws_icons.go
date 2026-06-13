// Package assets — AWS Architecture Icons loader.
//
// All icons in this directory are official AWS Architecture Icons
// (https://aws.amazon.com/architecture/icons/) and are used in
// accordance with AWS's terms (free for visualization with attribution).
// The package release dates are encoded in the source filenames inside
// the upstream zip; we curate a stable subset here.
//
// The loader returns the SVG icon as an inline-ready fragment (the
// inner content of the upstream <svg> root, minus the XML preamble and
// outer <svg> tag) so the audit diagram renderer can drop the icon
// into its larger SVG with `<g transform="translate(x,y) scale(s)">…</g>`.
package assets

import (
	"embed"
	"fmt"
	"path"
	"regexp"
	"strings"
	"sync"
)

//go:embed aws-icons/service/*.svg aws-icons/resource/*.svg aws-icons/group/*.svg
var awsIconsFS embed.FS

// AWSIcon describes one inline-ready icon: the inner SVG fragment plus
// the upstream viewBox dimension so callers can scale it to whatever
// pixel size the diagram needs.
type AWSIcon struct {
	Inner    string // SVG content ready to wrap in <g transform=...>
	ViewSize int    // upstream native size (square; viewBox 0 0 N N)
}

var (
	iconCacheMu sync.Mutex
	iconCache   = map[string]*AWSIcon{}
)

// LoadAWSIcon returns the cached inline-ready fragment for the icon
// named like "service/lambda" or "group/vpc". Returns nil + an error
// when the icon name doesn't resolve.
func LoadAWSIcon(name string) (*AWSIcon, error) {
	iconCacheMu.Lock()
	if ic, ok := iconCache[name]; ok {
		iconCacheMu.Unlock()
		return ic, nil
	}
	iconCacheMu.Unlock()

	rel := path.Join("aws-icons", name+".svg")
	raw, err := awsIconsFS.ReadFile(rel)
	if err != nil {
		return nil, fmt.Errorf("aws-icon %q: %w", name, err)
	}

	inner, vb := stripSVGWrapper(string(raw))
	ic := &AWSIcon{Inner: inner, ViewSize: vb}

	iconCacheMu.Lock()
	iconCache[name] = ic
	iconCacheMu.Unlock()
	return ic, nil
}

// HasAWSIcon reports whether `name` resolves to a bundled icon.
func HasAWSIcon(name string) bool {
	_, err := awsIconsFS.ReadFile(path.Join("aws-icons", name+".svg"))
	return err == nil
}

var (
	xmlDecl   = regexp.MustCompile(`(?s)<\?xml.*?\?>\s*`)
	svgOpen   = regexp.MustCompile(`(?s)<svg[^>]*viewBox=["']\s*0\s+0\s+(\d+)\s+(\d+)\s*["'][^>]*>`)
	svgClose  = regexp.MustCompile(`(?s)\s*</svg>\s*$`)
	commentRE = regexp.MustCompile(`(?s)<!--.*?-->`)
)

// stripSVGWrapper strips the <?xml…?> + outer <svg> + closing </svg>
// from a complete SVG document, returning just the inner draw content.
// Also extracts the viewBox square dimension so callers can scale.
// Falls back to a viewSize of 48 when the viewBox isn't square or
// can't be parsed (matches the typical AWS resource icon size).
func stripSVGWrapper(s string) (inner string, viewSize int) {
	out := xmlDecl.ReplaceAllString(s, "")
	out = commentRE.ReplaceAllString(out, "")

	vb := 48
	if m := svgOpen.FindStringSubmatch(out); m != nil {
		var w, h int
		// The (\d+) captures are digits-only, so a parse failure just
		// leaves the zero value — which the w > 0 guard below rejects.
		_, _ = fmt.Sscanf(m[1], "%d", &w)
		_, _ = fmt.Sscanf(m[2], "%d", &h)
		if w == h && w > 0 {
			vb = w
		}
		out = strings.Replace(out, m[0], "", 1)
	}
	out = svgClose.ReplaceAllString(out, "")
	return strings.TrimSpace(out), vb
}
