package output

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ParsedURN is the human-readable decomposition of an AWS resource URN
// of the form aws://<region>/AWS::<Service>::<Type>/<name>. Fields that
// the URN doesn't supply remain empty strings — the renderer skips them.
type ParsedURN struct {
	Service string // e.g. "iam", "rds", "s3" (lower-cased)
	Kind    string // e.g. "role", "dbinstance", "bucket"
	Name    string // e.g. "cbx-audit-lambda-admin"
	Region  string // e.g. "eu-central-1", or "" for global services
	Raw     string // the unmodified input, for fallback rendering
}

// ParseURN attempts to decompose an AWS resource URN. On any parsing
// failure it returns a ParsedURN with Raw set and the other fields empty,
// letting the caller fall back to printing the raw string.
func ParseURN(urn string) ParsedURN {
	p := ParsedURN{Raw: urn}
	rest, ok := strings.CutPrefix(urn, "aws://")
	if !ok {
		return p
	}
	// rest = "<region>/AWS::<Service>::<Type>/<name>"
	regionEnd := strings.Index(rest, "/")
	if regionEnd <= 0 {
		return p
	}
	p.Region = rest[:regionEnd]
	body := rest[regionEnd+1:]

	// body should now look like "AWS::Service::Type/name"
	slash := strings.Index(body, "/")
	if slash <= 0 {
		return p
	}
	typeSeg := body[:slash]
	p.Name = body[slash+1:]

	// typeSeg = AWS::Service::Type
	parts := strings.Split(typeSeg, "::")
	if len(parts) == 3 {
		p.Service = strings.ToLower(parts[1])
		p.Kind = strings.ToLower(parts[2])
	} else {
		// Unknown shape — keep what we have. Caller decides whether to
		// show .Raw instead.
		p.Service = strings.ToLower(typeSeg)
	}
	return p
}

// RenderResourceChip returns the pretty `service · kind · name · region`
// chip used in finding cards. Long names are middle-elided to keep the
// chip on one line within the supplied width. width <= 0 means no clip.
func RenderResourceChip(urn string, width int) string {
	p := ParseURN(urn)
	if p.Service == "" && p.Kind == "" && p.Name == "" {
		// Couldn't parse — fall back to the raw URN.
		return ellipsizeMiddle(urn, width)
	}

	dot := " · "
	if !Enabled() {
		dot = " | "
	}

	bits := []string{}
	if p.Service != "" {
		bits = append(bits, styleResourceMeta(p.Service))
	}
	if p.Kind != "" {
		bits = append(bits, styleResourceMeta(p.Kind))
	}
	if p.Name != "" {
		bits = append(bits, styleResourceName(ellipsizeMiddle(p.Name, nameClip(width))))
	}
	if p.Region != "" {
		bits = append(bits, styleResourceMeta(p.Region))
	}
	return strings.Join(bits, Dim.Render(dot))
}

func styleResourceMeta(s string) string {
	if !Enabled() {
		return s
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("39")).Render(s)
}

func styleResourceName(s string) string {
	if !Enabled() {
		return s
	}
	return lipgloss.NewStyle().Bold(true).Render(s)
}

func nameClip(total int) int {
	if total <= 0 {
		return 0
	}
	// Leave headroom for the other chip segments + separators.
	clip := total - 30
	if clip < 16 {
		clip = 16
	}
	return clip
}

// ellipsizeMiddle shortens s to fit in width characters by replacing the
// middle with an ellipsis. width <= 0 disables clipping. Width counts
// runes, not styled cells — callers should pass plain strings here.
func ellipsizeMiddle(s string, width int) string {
	if width <= 0 {
		return s
	}
	runes := []rune(s)
	if len(runes) <= width {
		return s
	}
	if width <= 3 {
		return strings.Repeat(".", width)
	}
	keep := width - 1 // 1 char for the ellipsis
	half := keep / 2
	return string(runes[:half]) + "…" + string(runes[len(runes)-(keep-half):])
}
