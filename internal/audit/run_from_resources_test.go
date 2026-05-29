package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudbooster-io/cbx-cli/internal/audit/parsers"
)

func TestRunFromResources_PopulatesResultAndWritesReport(t *testing.T) {
	// Run from a temp directory so the default report path lands
	// somewhere disposable. The function uses opts.ReportFile when set;
	// we override that path explicitly for the assertion.
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.md")

	resources := []DiscoveredResource{
		{
			Type:   "AWS::S3::Bucket",
			URN:    "aws://us-east-1/AWS::S3::Bucket/web",
			ID:     "web",
			Region: "us-east-1",
			Tags:   map[string]string{"Application": "frontend"},
		},
		{
			Type: "AWS::RDS::DBInstance",
			URN:  "aws://us-east-1/AWS::RDS::DBInstance/prod-db",
			ID:   "prod-db",
			Inputs: map[string]any{
				parsers.CBDescriberPrimitiveResolved: "aws:db/postgres@v1",
			},
		},
	}

	opts := Options{
		AWS:          true,
		AWSAccountID: "123456789012",
		MockScanners: true,
		ReportFile:   reportPath,
	}

	result, err := RunFromResources(opts, resources, nil)
	if err != nil {
		t.Fatalf("RunFromResources: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil Result")
	}
	if result.ReportPath != reportPath {
		t.Errorf("ReportPath = %q, want %q", result.ReportPath, reportPath)
	}
	if _, err := os.Stat(reportPath); err != nil {
		t.Errorf("report file not created: %v", err)
	}

	// Components must be present — both lenses ran. We expect at least
	// one tag-based component (frontend) and one cb-primitive
	// component (the engine-resolved postgres primitive for the RDS
	// instance).
	var sawTag, sawPrimitive bool
	for _, c := range result.Components {
		switch c.Kind {
		case "tag":
			if c.Name == "frontend" {
				sawTag = true
			}
		case "cb-primitive":
			if c.Source["primitive"] == "aws:db/postgres@v1" {
				sawPrimitive = true
			}
		}
	}
	if !sawTag {
		t.Errorf("expected a frontend tag-based component; got %+v", result.Components)
	}
	if !sawPrimitive {
		t.Errorf("expected the engine-resolved postgres cb-primitive component; got %+v", result.Components)
	}
}

func TestRunFromResources_EmptyResourceSetReturnsEmptyResult(t *testing.T) {
	dir := t.TempDir()
	opts := Options{
		AWS:          true,
		AWSAccountID: "123",
		MockScanners: true,
		ReportFile:   filepath.Join(dir, "empty.md"),
	}
	result, err := RunFromResources(opts, nil, nil)
	if err != nil {
		t.Fatalf("RunFromResources: %v", err)
	}
	if result == nil || len(result.Findings) != 0 || len(result.Components) != 0 {
		t.Errorf("expected empty result, got %+v", result)
	}
}
