package audit

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestBuildArchitectureSVG_ThemeAware verifies the dark-mode plumbing:
// the root carries the .cbx-arch hook, the theme stylesheet is embedded
// (with its standalone prefers-color-scheme block), and the elements
// that opt in/out of remapping carry their marker classes.
func TestBuildArchitectureSVG_ThemeAware(t *testing.T) {
	resources := []DiscoveredResource{
		{Type: "AWS::S3::Bucket", URN: "aws://us-east-1/AWS::S3::Bucket/web", ID: "web"},
		{Type: "AWS::Lambda::Function", URN: "aws://us-east-1/AWS::Lambda::Function/fn", ID: "fn"},
	}
	findings := []Finding{
		{RuleID: "s3-public", Title: "Bucket is public", Severity: SeverityCritical, Resource: "web"},
	}
	svg := BuildArchitectureSVG(resources, nil, AWSAuditContext{}, nil, findings)

	wants := []string{
		`class="cbx-arch"`,        // root hook the page/report CSS targets
		"<style>",                 // embedded theme stylesheet
		"prefers-color-scheme",    // standalone dark support
		"var(--bp-paper,#FAF7F0)", // attr→var remapping present
		`class="bp-node"`,         // node cards opt INTO theming
		`class="bp-chip"`,         // severity chips opt OUT (stay static)
	}
	for _, w := range wants {
		if !strings.Contains(svg, w) {
			t.Errorf("SVG missing %q", w)
		}
	}
}

// TestDiagramSVGPaletteIsThemed is the tripwire that keeps future
// colours honest: every literal fill="#…"/stroke="#…" the diagram
// renderers emit must either be remapped in svgThemeStyle or be on the
// documented exempt list. Without this, a new hard-coded colour would
// silently render light-on-dark.
func TestDiagramSVGPaletteIsThemed(t *testing.T) {
	srcFiles := []string{"diagram_svg.go", "diagram_blueprint.go", "diagram_icons.go"}
	attrRe := regexp.MustCompile(`(fill|stroke)="(#[0-9A-Fa-f]{6})"`)
	// Pure white is exempt by design: node cards theme via the .bp-node
	// class instead, and chip/monogram text deliberately stays white
	// over its saturated static fill. Parameterised colours (fill="%s")
	// are covered by the attribute rules on their serialized hex or by
	// the .bp-chip / .bp-tile carve-outs.
	exempt := map[string]bool{"#FFFFFF": true}
	for _, f := range srcFiles {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		for _, m := range attrRe.FindAllStringSubmatch(string(src), -1) {
			attr, hex := m[1], strings.ToUpper(m[2])
			if exempt[hex] {
				continue
			}
			needle := `[` + attr + `="` + hex + `"]`
			if !strings.Contains(svgThemeStyle, needle) {
				t.Errorf("%s: %s=%q has no %s remapping in svgThemeStyle — add a var or an exemption", f, attr, hex, needle)
			}
		}
	}
}
