package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestHelpTemplate(t *testing.T) {
	root := &cobra.Command{
		Use:   "cbx",
		Short: "CloudBooster CLI",
		Long:  "cbx is the CloudBooster CLI for planning cloud infrastructure.",
	}
	root.AddCommand(&cobra.Command{
		Use:   "plan",
		Short: "Generate a plan",
	})
	InstallHelpTemplate(root)

	buf := new(strings.Builder)
	root.SetOut(buf)
	root.SetErr(buf)
	if err := root.Help(); err != nil {
		t.Fatalf("Help() error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Usage:") {
		t.Fatal("missing Usage section")
	}
	if !strings.Contains(out, "https://docs.cloudbooster.io") {
		t.Fatal("missing docs URL footer")
	}
}

func TestHelpGolden(t *testing.T) {
	root := &cobra.Command{
		Use:   "cbx",
		Short: "CloudBooster CLI",
		Long:  "cbx is the CloudBooster CLI for planning cloud infrastructure.",
	}
	root.AddCommand(&cobra.Command{
		Use:   "plan",
		Short: "Generate a plan",
	})
	InstallHelpTemplate(root)

	buf := new(strings.Builder)
	root.SetOut(buf)
	root.SetErr(buf)
	_ = root.Help()
	got := buf.String()

	goldenPath := filepath.Join("testdata", "help_basic.golden")
	if os.Getenv("UPDATE_GOLDEN") != "" {
		os.MkdirAll("testdata", 0o755)
		os.WriteFile(goldenPath, []byte(got), 0o644)
	}

	wantBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("reading golden file %s: %v", goldenPath, err)
	}
	if got != string(wantBytes) {
		t.Fatalf("help golden mismatch.\nGOT:\n%s\n\nWANT:\n%s", got, string(wantBytes))
	}
}
