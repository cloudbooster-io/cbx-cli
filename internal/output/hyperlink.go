package output

import "fmt"

// Hyperlink wraps text in an OSC-8 escape so terminals that honour the
// sequence (iTerm2, Ghostty, WezTerm, kitty, recent VTEs) render `text`
// as a clickable link to `url`. Unsupported terminals show `text` as-is
// — OSC-8 degrades cleanly, no detection needed beyond the global
// Enabled() gate. Empty url returns text unmodified.
func Hyperlink(text, url string) string {
	if url == "" || !Enabled() {
		return text
	}
	// ESC]8;;<url>BEL <text> ESC]8;;BEL
	return fmt.Sprintf("\x1b]8;;%s\x07%s\x1b]8;;\x07", url, text)
}

// FileLink returns an OSC-8 hyperlink for a local filesystem path. The
// path should be absolute for terminals that honour file:// URIs.
func FileLink(text, absPath string) string {
	if absPath == "" {
		return text
	}
	return Hyperlink(text, "file://"+absPath)
}
