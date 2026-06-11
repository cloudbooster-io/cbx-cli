// diagram-replay re-renders an AWS audit report from a saved
// .state.json sidecar — no discovery, no scanners, no LLM call.
//
// Usage:
//
//	go run ./tools/diagram-replay <state.json> [<out.html>]
//
// When <out.html> is omitted, the tool writes next to the input as
// <basename>.replay.html. The companion .replay.svg is also dumped so
// you can open the SVG standalone (handy for screenshotting at a
// specific zoom).
//
// Typical dev loop:
//
//  1. Run a real audit once: `cbx audit aws --region eu-central-1 --cb-knowledge`
//     — produces 123456789012_audit_report.md + .html + .state.json.
//  2. Iterate on diagram_svg.go / diagram_icons.go.
//  3. `go run ./tools/diagram-replay 123456789012_audit_report.state.json`
//     — refreshes the HTML in <1s.
//  4. Reload the file:// URL in the browser.
//
// The tool is intentionally tiny — single file, no flags beyond the
// two positional args. Production paths stay in cbx itself.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudbooster-io/cbx-cli/internal/audit"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: diagram-replay <state.json> [<out.html>]")
		os.Exit(2)
	}
	statePath := os.Args[1]
	outPath := ""
	if len(os.Args) >= 3 {
		outPath = os.Args[2]
	}
	if outPath == "" {
		base := strings.TrimSuffix(filepath.Base(statePath), ".state.json")
		base = strings.TrimSuffix(base, ".json")
		dir := filepath.Dir(statePath)
		outPath = filepath.Join(dir, base+".replay.html")
	}

	state, err := audit.LoadAuditState(statePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load state: %v\n", err)
		os.Exit(1)
	}

	// Re-derive the diagram + report. We deliberately don't re-run
	// the LLM or scanners — Findings/Connections are read straight
	// from the state so iteration is deterministic.
	// Sibling SVG basename so the markdown picks up
	// `![Architecture](file.svg)` instead of inlining the SVG.
	svgBasename := strings.TrimSuffix(filepath.Base(outPath), ".html") + ".svg"
	result := &audit.Result{
		Findings:       state.Findings,
		Components:     state.Components,
		Diagram:        audit.BuildArchitectureDiagram(state.Resources, state.Components),
		DiagramSVG:     audit.BuildArchitectureSVG(state.Resources, state.Components, state.Context, state.LLMConnections, state.Findings),
		DiagramSVGFile: svgBasename,
		LLMConnections: state.LLMConnections,
	}

	md := audit.RenderAWSMarkdown(result, state.Context)
	html := audit.RenderAWSHTML(result, state.Context, md)

	if err := os.WriteFile(outPath, []byte(html), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write html: %v\n", err)
		os.Exit(1)
	}
	// Companion bare SVG — useful for screenshots without the
	// surrounding HTML chrome.
	svgPath := strings.TrimSuffix(outPath, ".html") + ".svg"
	if err := os.WriteFile(svgPath, []byte(result.DiagramSVG), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write svg: %v\n", err)
	}
	// Companion fresh markdown — so the mermaid diagram can be
	// inspected without unpacking the HTML <script> envelope.
	mdPath := strings.TrimSuffix(outPath, ".html") + ".md"
	if err := os.WriteFile(mdPath, []byte(md), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write md: %v\n", err)
	}

	fmt.Printf("rendered %d resources / %d components / %d LLM-connections\n",
		len(state.Resources), len(state.Components), len(state.LLMConnections))
	fmt.Printf("  html: %s\n", outPath)
	fmt.Printf("   svg: %s\n", svgPath)
	fmt.Printf("    md: %s\n", mdPath)
}
