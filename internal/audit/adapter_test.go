package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestScrubEnvStripsSensitive(t *testing.T) {
	t.Setenv("CB_API_KEY", "secret")
	t.Setenv("ANTHROPIC_API_KEY", "secret")
	t.Setenv("OPENAI_API_KEY", "secret")
	t.Setenv("AWS_ACCESS_KEY_ID", "akid")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "sak")
	t.Setenv("PATH", "/usr/bin")

	// Without AWS allowance.
	clean := scrubEnv(false)
	for _, e := range clean {
		if strings.HasPrefix(e, "CB_API_KEY=") ||
			strings.HasPrefix(e, "ANTHROPIC_API_KEY=") ||
			strings.HasPrefix(e, "OPENAI_API_KEY=") ||
			strings.HasPrefix(e, "AWS_") {
			t.Errorf("scrubEnv(false) leaked sensitive var: %s", e)
		}
	}

	var hasPath bool
	for _, e := range clean {
		if strings.HasPrefix(e, "PATH=") {
			hasPath = true
			break
		}
	}
	if !hasPath {
		t.Error("scrubEnv(false) removed non-sensitive PATH")
	}

	// With AWS allowance.
	cleanAWS := scrubEnv(true)
	var hasAWS bool
	for _, e := range cleanAWS {
		if strings.HasPrefix(e, "AWS_ACCESS_KEY_ID=") {
			hasAWS = true
			break
		}
	}
	if !hasAWS {
		t.Error("scrubEnv(true) should allow AWS vars")
	}
}

func TestMissingBinaryErrorFormat(t *testing.T) {
	meta := scannerMeta{
		Name:       "tfsec",
		InstallCmd: map[string]string{runtime.GOOS: "brew install tfsec"},
	}
	err := missingBinaryError(meta)
	msg := err.Error()
	lines := strings.Split(msg, "\n")
	if len(lines) < 3 {
		t.Fatalf("expected at least 3 lines, got %d: %s", len(lines), msg)
	}
	if !strings.Contains(lines[0], "tfsec is not installed") {
		t.Errorf("first line should mention missing binary, got: %s", lines[0])
	}
	if !strings.Contains(msg, "brew install tfsec") {
		t.Errorf("error should contain install command, got: %s", msg)
	}
}

func TestMissingBinaryErrorFallback(t *testing.T) {
	meta := scannerMeta{Name: "tfsec", InstallCmd: map[string]string{}}
	err := missingBinaryError(meta)
	if !strings.Contains(err.Error(), "documentation") {
		t.Errorf("expected fallback documentation message, got: %s", err.Error())
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.0.1", "1.0.0", 1},
		{"1.1.0", "1.0.9", 1},
		{"2.0.0", "1.99.99", 1},
		{"1.28.0", "1.28.0", 0},
		{"1.27.9", "1.28.0", -1},
	}
	for _, tc := range cases {
		got := compareVersions(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestVersionLessAndGreaterOrEqual(t *testing.T) {
	if !versionLess("1.27.0", "1.28.0") {
		t.Error("expected 1.27.0 < 1.28.0")
	}
	if versionLess("1.28.0", "1.28.0") {
		t.Error("expected 1.28.0 not < 1.28.0")
	}
	if !versionGreaterOrEqual("1.28.0", "1.28.0") {
		t.Error("expected 1.28.0 >= 1.28.0")
	}
	if !versionGreaterOrEqual("1.29.0", "1.28.0") {
		t.Error("expected 1.29.0 >= 1.28.0")
	}
	if versionGreaterOrEqual("1.27.0", "1.28.0") {
		t.Error("expected 1.27.0 not >= 1.28.0")
	}
}

func TestExtractVersion(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"v1.28.0", "1.28.0"},
		{"1.28.0", "1.28.0"},
		{"Version: 0.48.1", "0.48.1"},
		{"Prowler 3.11.0", "3.11.0"},
		{"2.4.25", "2.4.25"},
		{"no version here", ""},
	}
	for _, tc := range cases {
		got := extractVersion(tc.input)
		if got != tc.want {
			t.Errorf("extractVersion(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestPulumiTypeToTerraformType(t *testing.T) {
	cases := []struct {
		pulumi string
		want   string
	}{
		{"aws:s3/bucket:Bucket", "aws_s3_bucket"},
		{"aws:ec2/securityGroup:SecurityGroup", "aws_security_group"},
		{"aws:iam/role:Role", "aws_iam_role"},
		{"aws:rds/instance:Instance", "aws_db_instance"},
		{"aws:lambda/function:Function", "aws_lambda_function"},
		{"aws_s3_bucket", "aws_s3_bucket"},
		{"unknown:type", ""},
	}
	for _, tc := range cases {
		got := pulumiTypeToTerraformType(tc.pulumi)
		if got != tc.want {
			t.Errorf("pulumiTypeToTerraformType(%q) = %q, want %q", tc.pulumi, got, tc.want)
		}
	}
}

func TestWriteResourcesToTempDir(t *testing.T) {
	resources := []Resource{
		{
			Type: "aws:s3/bucket:Bucket",
			URN:  "urn:pulumi:dev::stack::aws:s3/bucket:Bucket::my-bucket",
			ID:   "my-bucket-id",
			Inputs: map[string]interface{}{
				"bucket": "my-bucket",
			},
		},
		{
			Type: "aws_security_group",
			URN:  "sg-123",
			Inputs: map[string]interface{}{
				"name": "web-sg",
			},
		},
	}

	dir, err := writeResourcesToTempDir(resources)
	if err != nil {
		t.Fatalf("writeResourcesToTempDir: %v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading temp dir: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 files, got %d", len(entries))
	}

	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".tf.json") {
			t.Errorf("expected .tf.json file, got %s", e.Name())
		}
	}
}

func TestWriteTerraformStateFile(t *testing.T) {
	resources := []Resource{
		{
			Type: "aws_s3_bucket",
			URN:  "my_bucket",
			Inputs: map[string]interface{}{
				"bucket": "my-bucket",
			},
		},
	}

	path, err := writeTerraformStateFile(resources)
	if err != nil {
		t.Fatalf("writeTerraformStateFile: %v", err)
	}
	defer func() { _ = os.RemoveAll(filepath.Dir(path)) }()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading state file: %v", err)
	}
	if !strings.Contains(string(data), `"version": 4`) {
		t.Error("expected state file to contain version 4")
	}
	if !strings.Contains(string(data), `"type": "aws_s3_bucket"`) {
		t.Error("expected state file to contain aws_s3_bucket type")
	}
}

func TestRunScannersContinuesOnError(t *testing.T) {
	scanners := []Scanner{
		&staticScanner{},
		&failingScanner{},
	}
	resources := []Resource{
		{Type: "aws:s3/bucket:Bucket", URN: "my-bucket"},
	}
	findings, err := RunScanners(scanners, resources)
	if err == nil {
		t.Fatal("expected error from failing scanner")
	}
	if !strings.Contains(err.Error(), "failing-scanner") {
		t.Errorf("expected error to mention scanner name, got: %v", err)
	}
	// staticScanner should still have produced findings.
	if len(findings) == 0 {
		t.Fatal("expected findings from static scanner despite failing scanner")
	}
}

type failingScanner struct{}

func (s *failingScanner) Name() string { return "failing-scanner" }

func (s *failingScanner) Scan(_ context.Context, _ []Resource) ([]Finding, error) {
	return nil, errors.New("intentional failure")
}

func (s *failingScanner) SupportsSource() bool { return false }
func (s *failingScanner) ScanSource(_ context.Context, _ string) ([]Finding, error) {
	return nil, ErrSourceModeUnsupported
}
