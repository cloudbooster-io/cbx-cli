package output

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteJSONData(t *testing.T) {
	var buf bytes.Buffer
	err := WriteJSON(&buf, map[string]string{"key": "value"}, nil)
	if err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, `"data"`) {
		t.Fatalf("expected data envelope, got: %s", got)
	}
	if !strings.Contains(got, `"key": "value"`) {
		t.Fatalf("expected nested key, got: %s", got)
	}
}

func TestWriteJSONError(t *testing.T) {
	var buf bytes.Buffer
	err := WriteJSON(&buf, nil, &ErrDetail{Code: "E123", Message: "something broke"})
	if err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, `"error"`) {
		t.Fatalf("expected error envelope, got: %s", got)
	}
	if strings.Contains(got, `"data"`) {
		t.Fatalf("expected no data field when error is present, got: %s", got)
	}
}

func TestWriteJSONDataAndError(t *testing.T) {
	var buf bytes.Buffer
	err := WriteJSON(&buf, map[string]any{"checks": []string{"a", "b"}}, &ErrDetail{Code: "PARTIAL", Message: "some checks failed"})
	if err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, `"data"`) {
		t.Fatalf("expected data field present when data is non-nil, got: %s", got)
	}
	if !strings.Contains(got, `"error"`) {
		t.Fatalf("expected error field present when err is non-nil, got: %s", got)
	}
	if !strings.Contains(got, `"some checks failed"`) {
		t.Fatalf("expected error message in output, got: %s", got)
	}
	if !strings.Contains(got, `"checks"`) {
		t.Fatalf("expected nested data preserved, got: %s", got)
	}
}

func TestJSONErrorHelpers(t *testing.T) {
	if JSONError(nil) != nil {
		t.Fatal("JSONError(nil) should return nil")
	}
	e := JSONErrorf("code %d failed", 42)
	if e.Message != "code 42 failed" {
		t.Fatalf("unexpected message: %s", e.Message)
	}
}

func TestJSONGolden(t *testing.T) {
	var buf bytes.Buffer
	_ = WriteJSON(&buf, map[string]string{"markdown": "# Hello"}, nil)
	got := buf.String()

	goldenPath := filepath.Join("testdata", "json_data.golden")
	if os.Getenv("UPDATE_GOLDEN") != "" {
		os.MkdirAll("testdata", 0o755)
		os.WriteFile(goldenPath, []byte(got), 0o644)
	}

	wantBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("reading golden file %s: %v", goldenPath, err)
	}
	if got != string(wantBytes) {
		t.Fatalf("json golden mismatch.\nGOT:\n%s\n\nWANT:\n%s", got, string(wantBytes))
	}
}
