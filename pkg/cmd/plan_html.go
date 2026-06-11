package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cloudbooster-io/cbx-cli/internal/assets"
	"github.com/cloudbooster-io/cbx-cli/internal/output"
)

// heading represents a single TOC entry extracted from markdown.
type heading struct {
	Level int
	Text  string
	ID    string
}

// planHTMLData is the template payload. MermaidSource stays a plain string —
// the component names inside it are LLM/user-influenced, so html/template
// must entity-escape it inside the .mermaid div (the bundled mermaid runtime
// entity-decodes the div's innerHTML before parsing, so escaped source
// renders identically).
type planHTMLData struct {
	Title         string
	Timestamp     string
	ADRHTML       template.HTML
	Headings      []heading
	MermaidSource string
	MermaidJS     template.JS
}

// generatePlanHTML creates a self-contained HTML preview page.
func generatePlanHTML(intent, adrMarkdown, mermaidSource string) ([]byte, error) {
	adrHTML, headings, err := markdownToHTML(adrMarkdown)
	if err != nil {
		return nil, fmt.Errorf("rendering markdown: %w", err)
	}

	mermaidJS, err := assets.MermaidJS()
	if err != nil {
		return nil, fmt.Errorf("decompressing mermaid runtime: %w", err)
	}

	data := planHTMLData{
		Title:         titleCase(intent),
		Timestamp:     time.Now().Format(time.RFC1123),
		ADRHTML:       template.HTML(adrHTML),
		Headings:      headings,
		MermaidSource: mermaidSource,
		MermaidJS:     template.JS(mermaidJS),
	}

	tmpl, err := template.New("plan").Parse(planTemplate)
	if err != nil {
		return nil, fmt.Errorf("parsing template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("executing template: %w", err)
	}
	return buf.Bytes(), nil
}

// titleCase upper-cases the first letter of each space-separated ASCII word.
// Replaces the deprecated strings.Title for the plan title; intents are
// free-form prose, so simple ASCII word boundaries are good enough.
func titleCase(s string) string {
	b := []byte(s)
	prevSpace := true
	for i, c := range b {
		if prevSpace && c >= 'a' && c <= 'z' {
			b[i] = c - ('a' - 'A')
		}
		prevSpace = c == ' '
	}
	return string(b)
}

// markdownToHTML converts a small subset of markdown to HTML and extracts headings.
func markdownToHTML(md string) (string, []heading, error) {
	var headings []heading
	var out strings.Builder
	lines := strings.Split(md, "\n")
	var inList bool

	flushList := func() {
		if inList {
			out.WriteString("</ul>\n")
			inList = false
		}
	}

	for i := 0; i < len(lines); i++ {
		line := strings.TrimRight(lines[i], " \t\r")
		trimmed := strings.TrimSpace(line)

		if trimmed == "" {
			flushList()
			continue
		}

		// Fenced code blocks
		if strings.HasPrefix(trimmed, "```") {
			flushList()
			lang := strings.TrimSpace(trimmed[3:])
			var codeLines []string
			i++
			for i < len(lines) {
				if strings.TrimSpace(lines[i]) == "```" {
					break
				}
				codeLines = append(codeLines, lines[i])
				i++
			}
			code := strings.Join(codeLines, "\n")
			highlighted := highlightCode(code, lang)
			out.WriteString(fmt.Sprintf("<pre><code class=\"language-%s\">%s</code></pre>\n", escapeHTML(lang), highlighted))
			continue
		}

		// Headings
		if strings.HasPrefix(trimmed, "#") {
			flushList()
			level := 0
			for level < len(trimmed) && trimmed[level] == '#' {
				level++
			}
			text := strings.TrimSpace(trimmed[level:])
			id := slugify(text)
			headings = append(headings, heading{Level: level, Text: text, ID: id})
			out.WriteString(fmt.Sprintf("<h%d id=\"%s\">%s</h%d>\n", level, id, escapeHTML(text), level))
			continue
		}

		// List items
		if strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* ") {
			if !inList {
				out.WriteString("<ul>\n")
				inList = true
			}
			item := strings.TrimSpace(trimmed[2:])
			out.WriteString(fmt.Sprintf("<li>%s</li>\n", inlineMarkdownToHTML(item)))
			continue
		}

		// Paragraph
		flushList()
		out.WriteString(fmt.Sprintf("<p>%s</p>\n", inlineMarkdownToHTML(trimmed)))
	}
	flushList()

	return out.String(), headings, nil
}

var boldRe = regexp.MustCompile(`\*\*(.+?)\*\*`)

func inlineMarkdownToHTML(text string) string {
	text = escapeHTML(text)
	text = boldRe.ReplaceAllString(text, "<strong>$1</strong>")
	return text
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

func slugify(s string) string {
	s = strings.ToLower(s)
	var out strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			out.WriteRune(r)
		} else if r == ' ' || r == '-' || r == '_' {
			out.WriteByte('-')
		}
	}
	return out.String()
}

func highlightCode(code, lang string) string {
	var out strings.Builder
	lines := strings.Split(code, "\n")
	for li, line := range lines {
		if li > 0 {
			out.WriteByte('\n')
		}
		out.WriteString(highlightLine(line))
	}
	return out.String()
}

func highlightLine(line string) string {
	var out strings.Builder
	i := 0
	for i < len(line) {
		// Line comments
		if strings.HasPrefix(line[i:], "//") || strings.HasPrefix(line[i:], "#") {
			out.WriteString(`<span class="com">` + escapeHTML(line[i:]) + `</span>`)
			break
		}

		// Block comments (single-line only)
		if strings.HasPrefix(line[i:], "/*") {
			end := strings.Index(line[i+2:], "*/")
			if end != -1 {
				end += i + 4
				out.WriteString(`<span class="com">` + escapeHTML(line[i:end]) + `</span>`)
				i = end
				continue
			}
		}

		// String literals
		if line[i] == '"' {
			end := findStringEnd(line, i+1, '"')
			out.WriteString(`<span class="str">` + escapeHTML(line[i:end]) + `</span>`)
			i = end
			continue
		}
		if line[i] == '\'' {
			end := findStringEnd(line, i+1, '\'')
			out.WriteString(`<span class="str">` + escapeHTML(line[i:end]) + `</span>`)
			i = end
			continue
		}
		if line[i] == '`' {
			end := findStringEnd(line, i+1, '`')
			out.WriteString(`<span class="str">` + escapeHTML(line[i:end]) + `</span>`)
			i = end
			continue
		}

		// Numbers
		if isDigit(line[i]) || (line[i] == '.' && i+1 < len(line) && isDigit(line[i+1])) {
			end := i
			hasX := false
			for end < len(line) {
				c := line[end]
				if isDigit(c) || c == '_' {
					end++
				} else if c == '.' {
					end++
				} else if (c == 'x' || c == 'X') && !hasX && end == i+1 && line[i] == '0' {
					hasX = true
					end++
				} else if hasX && isHexDigit(c) {
					end++
				} else {
					break
				}
			}
			out.WriteString(`<span class="num">` + escapeHTML(line[i:end]) + `</span>`)
			i = end
			continue
		}

		// Keywords and identifiers
		if isAlpha(line[i]) || line[i] == '_' {
			end := i
			for end < len(line) && (isAlphaNum(line[end]) || line[end] == '_') {
				end++
			}
			word := line[i:end]
			if isKeyword(word) {
				out.WriteString(`<span class="kw">` + escapeHTML(word) + `</span>`)
			} else {
				out.WriteString(escapeHTML(word))
			}
			i = end
			continue
		}

		out.WriteString(escapeHTML(line[i : i+1]))
		i++
	}
	return out.String()
}

func findStringEnd(s string, start int, quote byte) int {
	i := start
	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			i += 2
		} else if s[i] == quote {
			return i + 1
		} else {
			i++
		}
	}
	return len(s)
}

func isDigit(b byte) bool    { return b >= '0' && b <= '9' }
func isAlpha(b byte) bool    { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }
func isAlphaNum(b byte) bool { return isAlpha(b) || isDigit(b) }
func isHexDigit(b byte) bool { return isDigit(b) || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F') }

var keywords = map[string]bool{
	"func": true, "var": true, "const": true, "type": true, "struct": true,
	"interface": true, "map": true, "chan": true, "go": true, "defer": true,
	"return": true, "if": true, "else": true, "for": true, "range": true,
	"switch": true, "case": true, "default": true, "break": true, "continue": true,
	"package": true, "import": true,
	"def": true, "class": true, "from": true, "as": true, "try": true,
	"except": true, "finally": true, "with": true, "yield": true, "lambda": true,
	"async": true, "await": true, "pass": true,
	"function": true, "let": true, "new": true, "this": true,
	"typeof": true, "instanceof": true,
	"public": true, "private": true, "protected": true, "static": true,
	"void": true, "int": true, "string": true, "bool": true, "float": true,
	"true": true, "false": true, "nil": true, "null": true, "None": true,
}

func isKeyword(word string) bool {
	return keywords[word]
}

func generateRandomPath() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// startPreviewServer starts a local HTTP server, opens the browser, and blocks until shutdown.
func startPreviewServer(dir string, htmlContent []byte, requestedPort int, noOpen bool) error {
	prefix, err := generateRandomPath()
	if err != nil {
		return fmt.Errorf("generating path prefix: %w", err)
	}

	listener, port, err := bindListener(requestedPort)
	if err != nil {
		return fmt.Errorf("binding listener: %w", err)
	}
	if requestedPort != 0 && port != requestedPort {
		if !quietFlag {
			fmt.Fprintf(os.Stderr, "warning: requested port %d unavailable, using port %d\n", requestedPort, port)
		}
	}

	var lastRequestAt atomic.Int64
	lastRequestAt.Store(time.Now().Unix())

	mux := http.NewServeMux()

	// Serve the generated HTML at /<prefix>/
	mux.HandleFunc("/"+prefix+"/", func(w http.ResponseWriter, r *http.Request) {
		lastRequestAt.Store(time.Now().Unix())
		if r.URL.Path == "/"+prefix+"/" || r.URL.Path == "/"+prefix+"" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(htmlContent)
			return
		}
		http.NotFound(w, r)
	})

	// Serve working directory at /<prefix>/files/
	fileServer := http.StripPrefix("/"+prefix+"/files/", http.FileServer(http.Dir(dir)))
	mux.HandleFunc("/"+prefix+"/files/", func(w http.ResponseWriter, r *http.Request) {
		lastRequestAt.Store(time.Now().Unix())
		fileServer.ServeHTTP(w, r)
	})

	server := &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	url := fmt.Sprintf("http://127.0.0.1:%d/%s/", port, prefix)

	if !quietFlag {
		output.Successf("Preview server running at %s", url)
		output.Infof("  Press Ctrl+C to stop")
	}

	if !noOpen {
		if err := openBrowser(url); err != nil {
			if !quietFlag {
				fmt.Printf("  (could not open browser: %v)\n", err)
				fmt.Printf("  Open manually: %s\n", url)
			}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Idle shutdown goroutine: exit 5 minutes after last request.
	idleDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				last := time.Unix(lastRequestAt.Load(), 0)
				if time.Since(last) > 5*time.Minute {
					if !quietFlag {
						fmt.Println("\n  Idle timeout reached, shutting down preview server.")
					}
					_ = server.Shutdown(context.Background())
					return
				}
			case <-idleDone:
				return
			}
		}
	}()

	// Start server in a goroutine.
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Serve(listener)
	}()

	// Wait for shutdown signal or server error.
	select {
	case <-ctx.Done():
		if !quietFlag {
			fmt.Println("\n  Shutting down preview server...")
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	case err := <-serverErr:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("server error: %w", err)
		}
	}

	close(idleDone)
	return nil
}

func bindListener(requestedPort int) (net.Listener, int, error) {
	addr := fmt.Sprintf("127.0.0.1:%d", requestedPort)
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		return ln, ln.Addr().(*net.TCPAddr).Port, nil
	}
	if requestedPort != 0 {
		// Fallback to ephemeral port.
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, 0, err
		}
		return ln, ln.Addr().(*net.TCPAddr).Port, nil
	}
	return nil, 0, err
}

// openBrowser opens url in the default browser without blocking. Local
// replacement for the archived github.com/pkg/browser.
func openBrowser(url string) error {
	ctx := context.Background()
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "open", url)
	case "windows":
		// `start` is a cmd.exe builtin; the empty first argument is the
		// window title so the URL is not mistaken for it.
		cmd = exec.CommandContext(ctx, "cmd", "/c", "start", "", url)
	default: // linux and the BSDs
		cmd = exec.CommandContext(ctx, "xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	// Reap the launcher in the background so it neither blocks the preview
	// server nor lingers as a zombie.
	go func() { _ = cmd.Wait() }()
	return nil
}

func isCI() bool {
	return os.Getenv("CI") == "true"
}
