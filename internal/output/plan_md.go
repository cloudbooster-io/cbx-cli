package output

import (
	"fmt"
	"strings"
	"time"
)

// timeNow is overridable for deterministic tests.
var timeNow = time.Now

// RenderPlanMD consumes a plan's metadata, pre-rendered ADR text, and Mermaid
// source and emits a single combined markdown document.
func RenderPlanMD(intent string, version int, adrContent, mermaidContent string) string {
	var sb strings.Builder

	// Front-matter
	sb.WriteString("---\n")
	sb.WriteString(fmt.Sprintf("title: \"ADR: %s\"\n", TitleCase(intent)))
	sb.WriteString(fmt.Sprintf("generated-at: %s\n", timeNow().Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("intent: %q\n", intent))
	sb.WriteString(fmt.Sprintf("variant: %d\n", version))
	sb.WriteString("---\n\n")

	// ADR body
	sb.WriteString(adrContent)
	sb.WriteString("\n\n")

	// Diagram section
	sb.WriteString("## Diagram\n\n")
	sb.WriteString("```mermaid\n")
	sb.WriteString(mermaidContent)
	sb.WriteString("\n```\n")

	return sb.String()
}

func TitleCase(s string) string {
	if s == "" {
		return ""
	}
	words := strings.Fields(s)
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}
