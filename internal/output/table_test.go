package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTableBasic(t *testing.T) {
	tbl := NewTable([]string{"Name", "Status"})
	tbl.AddRow("alpha", "ok")
	tbl.AddRow("beta", "fail")

	out := tbl.Render()
	if !strings.Contains(out, "Name") {
		t.Fatal("missing header Name")
	}
	if !strings.Contains(out, "alpha") {
		t.Fatal("missing row alpha")
	}
	if !strings.Contains(out, "-----") {
		t.Fatal("missing separator")
	}
}

func TestTableEmpty(t *testing.T) {
	tbl := NewTable([]string{})
	if tbl.Render() != "" {
		t.Fatalf("expected empty render for empty headers, got: %q", tbl.Render())
	}
}

func TestTableTruncate(t *testing.T) {
	// Force a very narrow terminal by temporarily replacing term.GetSize.
	// Since we can't easily mock term.GetSize, we test truncate directly.
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"hello", 10, "hello"},
		{"hello world", 8, "hello..."},
		{"hi", 2, "hi"},
		{"hello", 3, "..."},
		{"", 5, ""},
	}
	for _, c := range cases {
		got := truncate(c.in, c.max)
		if got != c.want {
			t.Fatalf("truncate(%q, %d) = %q, want %q", c.in, c.max, got, c.want)
		}
	}
}

func TestTableGolden(t *testing.T) {
	tbl := NewTable([]string{"Check", "Result", "Detail"})
	tbl.AddRow("Go version", Symbol("check"), "go1.24.2")
	tbl.AddRow("OS/Arch", Symbol("check"), "linux/amd64")
	tbl.AddRow("API", Symbol("cross"), "unreachable")

	got := tbl.Render()

	goldenPath := filepath.Join("testdata", "table_basic.golden")
	if os.Getenv("UPDATE_GOLDEN") != "" {
		os.MkdirAll("testdata", 0o755)
		os.WriteFile(goldenPath, []byte(got), 0o644)
	}

	wantBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("reading golden file %s: %v", goldenPath, err)
	}
	if got != string(wantBytes) {
		t.Fatalf("table golden mismatch.\nGOT:\n%s\n\nWANT:\n%s", got, string(wantBytes))
	}
}
