package audit

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReadCapped_UnderCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "main.tf")
	content := []byte("resource \"aws_s3_bucket\" \"b\" {}\n")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	f, err := readCapped(path, 1024)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(f.Content, content) {
		t.Fatalf("content mismatch: got %q, want %q", f.Content, content)
	}
	if f.Bytes != len(content) {
		t.Fatalf("Bytes = %d, want %d", f.Bytes, len(content))
	}
	if f.Truncated {
		t.Fatal("expected Truncated=false for a file under the cap")
	}
}

func TestReadCapped_OverCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "main.tf")
	content := bytes.Repeat([]byte("x"), 100)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	const capBytes = 64
	f, err := readCapped(path, capBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Bytes != capBytes {
		t.Fatalf("Bytes = %d, want %d", f.Bytes, capBytes)
	}
	if !bytes.Equal(f.Content, content[:capBytes]) {
		t.Fatal("content was not capped to the first maxBytes bytes")
	}
	if !f.Truncated {
		t.Fatal("expected Truncated=true for a file over the cap")
	}
}

func TestReadCapped_EmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.tf")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	f, err := readCapped(path, 1024)
	if err != nil {
		t.Fatalf("unexpected error for empty file: %v", err)
	}
	if f.Bytes != 0 || len(f.Content) != 0 {
		t.Fatalf("expected empty content, got %d bytes", f.Bytes)
	}
	if f.Truncated {
		t.Fatal("expected Truncated=false for an empty file")
	}
}

func TestReadCapped_MissingFile(t *testing.T) {
	if _, err := readCapped(filepath.Join(t.TempDir(), "absent.tf"), 1024); err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestCollectSourceFiles_SkipsUnreadableFile(t *testing.T) {
	// collectSourceFiles skips files it cannot read instead of failing
	// the whole collection — one bad file must not void the LLM context.
	if runtime.GOOS == "windows" {
		t.Skip("file-mode based unreadability is not portable to windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores file modes")
	}

	dir := t.TempDir()
	good := filepath.Join(dir, "good.tf")
	if err := os.WriteFile(good, []byte("resource \"aws_s3_bucket\" \"b\" {}\n"), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	bad := filepath.Join(dir, "bad.tf")
	if err := os.WriteFile(bad, []byte("unreadable"), 0o000); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(bad, 0o644) }) // let TempDir cleanup remove it

	files, err := collectSourceFiles(dir, IaCTypeTerraform, 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected exactly the readable file, got %d files", len(files))
	}
	if files[0].Path != "good.tf" {
		t.Fatalf("unexpected file collected: %s", files[0].Path)
	}
}
