package output

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderErrorFull(t *testing.T) {
	oldFn := isTerminalFn
	isTerminalFn = func() bool { return false }
	defer func() { isTerminalFn = oldFn }()
	Configure(false, false)

	e := ErrorDetail{
		What:   "cannot connect to API",
		Why:    "network timeout after 5s",
		Fix:    "check your internet connection and retry",
		Code:   "E_CONN",
		DocURL: "https://docs.cloudbooster.io/errors/E_CONN",
	}
	out := RenderError(e)
	if !strings.Contains(out, "cannot connect to API") {
		t.Fatal("missing What")
	}
	if !strings.Contains(out, "network timeout") {
		t.Fatal("missing Why")
	}
	if !strings.Contains(out, "check your internet") {
		t.Fatal("missing Fix")
	}
	if !strings.Contains(out, "E_CONN") {
		t.Fatal("missing Code")
	}
	if !strings.Contains(out, "https://docs.cloudbooster.io/errors/E_CONN") {
		t.Fatal("missing DocURL")
	}
}

func TestRenderErrorMinimal(t *testing.T) {
	oldFn := isTerminalFn
	isTerminalFn = func() bool { return false }
	defer func() { isTerminalFn = oldFn }()
	Configure(false, false)

	e := ErrorDetail{
		What: "something went wrong",
		Why:  "unknown cause",
		Fix:  "contact support",
	}
	out := RenderError(e)
	if strings.Contains(out, "Learn more") {
		t.Fatal("unexpected DocURL section")
	}
	if strings.Contains(out, "(") {
		t.Fatal("unexpected Code section")
	}
}

func TestRenderErrorCompact(t *testing.T) {
	e := ErrorDetail{What: "boom", Code: "E1"}
	out := RenderErrorCompact(e)
	if out != "[E1] boom" {
		t.Fatalf("unexpected compact: %q", out)
	}
}

func TestErrorGolden(t *testing.T) {
	oldFn := isTerminalFn
	isTerminalFn = func() bool { return false }
	defer func() { isTerminalFn = oldFn }()
	Configure(false, false)

	e := ErrorDetail{
		What:   "config file not found",
		Why:    "expected ~/.cbx/config.json",
		Fix:    "run 'cbx login' to create one",
		Code:   "E_CONFIG",
		DocURL: "https://docs.cloudbooster.io/errors/E_CONFIG",
	}
	got := RenderError(e)

	goldenPath := filepath.Join("testdata", "error_full.golden")
	if os.Getenv("UPDATE_GOLDEN") != "" {
		os.MkdirAll("testdata", 0o755)
		os.WriteFile(goldenPath, []byte(got), 0o644)
	}

	wantBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("reading golden file %s: %v", goldenPath, err)
	}
	if got != string(wantBytes) {
		t.Fatalf("error golden mismatch.\nGOT:\n%s\n\nWANT:\n%s", got, string(wantBytes))
	}
}

func TestDetailError_CarriesStructure(t *testing.T) {
	err := NewError(ErrorDetail{What: "boom", Why: "because", Fix: "do X", Code: "E_BOOM"})
	var detailErr *DetailError
	if !errors.As(err, &detailErr) {
		t.Fatal("NewError must be extractable via errors.As")
	}
	if detailErr.Detail.Code != "E_BOOM" || detailErr.Detail.Fix != "do X" {
		t.Fatalf("detail lost: %+v", detailErr.Detail)
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("Error() must render the human card, got %q", err.Error())
	}
}
