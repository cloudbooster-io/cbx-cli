package output

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRenderPlanMD(t *testing.T) {
	// Override timeNow for deterministic golden-file output.
	oldTimeNow := timeNow
	timeNow = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	defer func() { timeNow = oldTimeNow }()

	adr := "# ADR: Static Site\n\n## Status\nProposed\n\n## Context\nThe user requested: \"static site\"\n"
	mmd := "flowchart LR\n    s3[S3]\n    users[Users]\n    users --> s3\n    click s3 href \"#s3\"\n"

	got := RenderPlanMD("static site", 1, adr, mmd)

	goldenPath := filepath.Join("testdata", "plan_md.golden")
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("creating testdata: %v", err)
		}
		if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
			t.Fatalf("writing golden file: %v", err)
		}
	}

	wantBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("reading golden file %s: %v", goldenPath, err)
	}
	want := string(wantBytes)

	if got != want {
		t.Fatalf("RenderPlanMD() mismatch.\nGOT:\n%s\n\nWANT:\n%s", got, want)
	}
}
