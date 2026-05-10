package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCollectSourceMode_HappyPath(t *testing.T) {
	dir := t.TempDir()

	opts := Options{
		SourceDir:    dir,
		MockScanners: true,
	}

	findings, err := Collect(opts)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding from the source-mode mock scanner")
	}
	for _, f := range findings {
		if !strings.HasPrefix(f.RuleID, "MOCK-SRC-") {
			t.Errorf("expected MOCK-SRC- finding, got %q", f.RuleID)
		}
	}
}

func TestCollectSourceMode_DeterministicByDirName(t *testing.T) {
	parent := t.TempDir()
	dirA := filepath.Join(parent, "alpha")
	dirB := filepath.Join(parent, "alpha-clone")
	for _, d := range []string{dirA, dirB} {
		if err := mkdir(d); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	first, err := Collect(Options{SourceDir: dirA, MockScanners: true})
	if err != nil {
		t.Fatalf("first Collect: %v", err)
	}

	// Same input -> same output. Re-running on the same directory must
	// yield byte-equal RuleID/Severity sequences (dedupe could mask drift).
	second, err := Collect(Options{SourceDir: dirA, MockScanners: true})
	if err != nil {
		t.Fatalf("second Collect: %v", err)
	}
	if !findingsEqualByKey(first, second) {
		t.Fatalf("source-mode findings not deterministic across runs: %v vs %v", findingKeys(first), findingKeys(second))
	}

	// A different dir base name should be allowed to differ (the mock keys
	// off basename); we don't assert inequality strictly, only that the
	// call succeeds and produces some findings.
	if _, err := Collect(Options{SourceDir: dirB, MockScanners: true}); err != nil {
		t.Fatalf("Collect on %s: %v", dirB, err)
	}
}

func TestCollectSourceMode_MissingDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	_, err := Collect(Options{SourceDir: missing, MockScanners: true})
	if err == nil {
		t.Fatal("expected error for missing source directory")
	}
	if !strings.Contains(err.Error(), "failed to read source directory") {
		t.Errorf("expected three-line error mentioning the source directory, got: %v", err)
	}
}

func TestCollectSourceMode_PathIsFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "main.tf")
	if err := writeFile(file, "resource \"null_resource\" \"x\" {}"); err != nil {
		t.Fatalf("writeFile: %v", err)
	}

	_, err := Collect(Options{SourceDir: file, MockScanners: true})
	if err == nil {
		t.Fatal("expected error when --source points at a regular file")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("expected 'not a directory' error, got: %v", err)
	}
}

func TestCollectSourceMode_FiltersUnsupportedProviders(t *testing.T) {
	// With explicit --scanners=checkov,static the runner must filter checkov
	// out (SupportsSource() == false until MR 3) and run only the static
	// mock. If the filter regressed, checkov's checkVersion would surface a
	// missing-binary error and fail the test.
	dir := t.TempDir()

	opts := Options{
		SourceDir: dir,
		Scanners:  []string{"static", "checkov"},
	}

	findings, err := Collect(opts)
	if err != nil {
		t.Fatalf("Collect returned error (checkov should have been filtered, not invoked): %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding from the static scanner")
	}
}

func TestCollectSourceMode_AllProvidersUnsupported(t *testing.T) {
	// If --scanners selects only providers that don't yet support source mode
	// the runner must surface a helpful error instead of silently returning 0
	// findings. checkov and trivy don't gain source mode until MR 3.
	dir := t.TempDir()

	opts := Options{
		SourceDir: dir,
		Scanners:  []string{"checkov", "trivy"},
	}

	_, err := Collect(opts)
	if err == nil {
		t.Fatal("expected error when no selected scanner supports source mode")
	}
	if !strings.Contains(err.Error(), "no source-mode scanners selected") {
		t.Errorf("expected helpful 'no source-mode scanners selected' error, got: %v", err)
	}
}

func TestProwlerScanSourceUnsupported(t *testing.T) {
	p := &prowlerAdapter{}
	if p.SupportsSource() {
		t.Fatal("prowler must never report SupportsSource() == true")
	}
	_, err := p.ScanSource(context.Background(), t.TempDir())
	if !errors.Is(err, ErrSourceModeUnsupported) {
		t.Fatalf("expected ErrSourceModeUnsupported, got %v", err)
	}
}

func TestSourceModeUnsupportedAdapters(t *testing.T) {
	// checkov and trivy ScanSource implementations land in MR 3.
	cases := []struct {
		name string
		p    FindingProvider
	}{
		{"checkov", &checkovAdapter{}},
		{"trivy", &trivyAdapter{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.p.SupportsSource() {
				t.Fatalf("%s should not report SupportsSource yet (MR 3)", tc.name)
			}
			if _, err := tc.p.ScanSource(context.Background(), t.TempDir()); !errors.Is(err, ErrSourceModeUnsupported) {
				t.Fatalf("%s.ScanSource: expected ErrSourceModeUnsupported, got %v", tc.name, err)
			}
		})
	}
}

func TestStaticScannerScanSourceEmptyDir(t *testing.T) {
	s := &staticScanner{}
	if !s.SupportsSource() {
		t.Fatal("static scanner should support source mode (it is the mock)")
	}
	findings, err := s.ScanSource(context.Background(), "")
	if err != nil {
		t.Fatalf("ScanSource(\"\"): %v", err)
	}
	if findings != nil {
		t.Fatalf("expected nil findings for empty dir, got %v", findings)
	}
}

// ---- helpers ----

func mkdir(p string) error {
	return os.MkdirAll(p, 0o755)
}

func writeFile(p, content string) error {
	return os.WriteFile(p, []byte(content), 0o644)
}

func findingsEqualByKey(a, b []Finding) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].RuleID != b[i].RuleID || a[i].Severity != b[i].Severity || a[i].Resource != b[i].Resource {
			return false
		}
	}
	return true
}

func findingKeys(fs []Finding) []string {
	keys := make([]string, 0, len(fs))
	for _, f := range fs {
		keys = append(keys, f.RuleID+"|"+f.Resource)
	}
	return keys
}
