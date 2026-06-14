package audit

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
)

// lineSep / paraSep are the JavaScript line terminators U+2028 / U+2029.
// Embedded raw into a JS string literal they break the literal in
// pre-ES2019 engines, so the renderer must not let them reach a <script>
// context unencoded.
const (
	lineSep = "\u2028"
	paraSep = "\u2029"
)

// base64Alphabet matches a (possibly empty) standard base64 string. The
// alphabet is [A-Za-z0-9+/=] only — no quotes, backslashes, angle
// brackets, or line terminators — which is exactly why embedding the
// markdown source and filename base64-encoded can't break out of the
// surrounding <script> / string literal (CodeQL go/unsafe-quoting #1).
var base64Alphabet = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)

// TestRenderAWSHTML_EmbedsAreInjectionSafe guards the go/unsafe-quoting
// fix: both the embedded markdown source and the markdown filename flow
// into JavaScript contexts in the HTML report, so a report or account ID
// containing </script>, quotes, or the U+2028/U+2029 line terminators
// must not be able to break out of its enclosing literal.
func TestRenderAWSHTML_EmbedsAreInjectionSafe(t *testing.T) {
	// Hostile payload routed through BOTH embed sites: the markdown
	// source (direct arg) and the filename (derived from AccountID).
	payload := "INJECT</script><img src=x onerror=alert(1)>'\"" + lineSep + paraSep + "END"
	markdownSource := "# Audit\n\n" + payload + "\n"

	ctx := AWSAuditContext{AccountID: payload}
	result := &Result{Findings: nil, Components: nil}

	html := RenderAWSHTML(result, ctx, markdownSource)

	// 1) The raw payload must never reach a JS context verbatim — the
	// </script> would close the block and the quotes/terminators would
	// break the literal. Base64-encoding leaves nothing to inject.
	if strings.Contains(html, "INJECT</script>") {
		t.Fatal("payload's </script> survived unencoded — script-block breakout")
	}

	// 2) Extract the two embeds and confirm each is pure base64 (so it
	// cannot carry a quote, angle bracket, or line terminator).
	srcB64 := extractAfter(t, html, `<script id="md-source" type="text/plain">`, "</script>")
	mdFileB64 := extractAfter(t, html, `b64ToUtf8("`, `")`)
	for _, e := range []struct{ name, b64 string }{{"md-source", srcB64}, {"mdFile", mdFileB64}} {
		if !base64Alphabet.MatchString(e.b64) {
			t.Fatalf("%s embed is not pure base64: %q", e.name, e.b64)
		}
	}

	// 3) Both embeds must decode back to the original bytes — this is the
	// Download-button round-trip (the JS does the same atob + UTF-8 decode).
	gotMD, err := base64.StdEncoding.DecodeString(srcB64)
	if err != nil {
		t.Fatalf("md-source base64 did not decode: %v", err)
	}
	if string(gotMD) != markdownSource {
		t.Fatalf("markdown source did not round-trip:\n got %q\nwant %q", gotMD, markdownSource)
	}
	gotFile, err := base64.StdEncoding.DecodeString(mdFileB64)
	if err != nil {
		t.Fatalf("mdFile base64 did not decode: %v", err)
	}
	if want := defaultMarkdownFilename(ctx); string(gotFile) != want {
		t.Fatalf("mdFile did not round-trip: got %q want %q", gotFile, want)
	}
}

// extractAfter returns the substring of s between the first occurrence of
// start and the next occurrence of end after it.
func extractAfter(t *testing.T, s, start, end string) string {
	t.Helper()
	i := strings.Index(s, start)
	if i < 0 {
		t.Fatalf("marker %q not found", start)
	}
	rest := s[i+len(start):]
	j := strings.Index(rest, end)
	if j < 0 {
		t.Fatalf("terminator %q not found after %q", end, start)
	}
	return rest[:j]
}
