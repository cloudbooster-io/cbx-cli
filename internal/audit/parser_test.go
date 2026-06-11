package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseStatePulumi(t *testing.T) {
	state := map[string]interface{}{
		"version": 3,
		"deployment": map[string]interface{}{
			"resources": []interface{}{
				map[string]interface{}{
					"urn":  "urn:pulumi:dev::stack::aws:s3/bucket:Bucket::my-bucket",
					"type": "aws:s3/bucket:Bucket",
					"inputs": map[string]interface{}{
						"bucket": "my-bucket",
						"tags": map[string]interface{}{
							"Env": "prod",
						},
						"region": "us-east-1",
					},
				},
			},
		},
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "pulumi.json")
	writeJSON(t, path, state)

	resources, err := ParseState(Options{StateFile: path})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	if resources[0].Type != "aws:s3/bucket:Bucket" {
		t.Fatalf("unexpected type: %s", resources[0].Type)
	}
	if resources[0].URN != "urn:pulumi:dev::stack::aws:s3/bucket:Bucket::my-bucket" {
		t.Fatalf("unexpected URN: %s", resources[0].URN)
	}
	if resources[0].Region != "us-east-1" {
		t.Fatalf("unexpected region: %s", resources[0].Region)
	}
	if len(resources[0].Tags) != 1 || resources[0].Tags["Env"] != "prod" {
		t.Fatalf("unexpected tags: %v", resources[0].Tags)
	}
}

func TestParseStateTerraform(t *testing.T) {
	state := map[string]interface{}{
		"terraform_version": "1.5.0",
		"serial":            1,
		"resources": []interface{}{
			map[string]interface{}{
				"mode":     "managed",
				"type":     "aws_s3_bucket",
				"name":     "my_bucket",
				"provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
				"instances": []interface{}{
					map[string]interface{}{
						"attributes": map[string]interface{}{
							"bucket": "my-bucket",
							"tags": map[string]interface{}{
								"Env": "staging",
							},
							"arn": "arn:aws:s3:::my-bucket",
						},
					},
				},
			},
		},
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "terraform.tfstate")
	writeJSON(t, path, state)

	resources, err := ParseState(Options{StateFile: path})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	if resources[0].Type != "aws_s3_bucket" {
		t.Fatalf("unexpected type: %s", resources[0].Type)
	}
	if len(resources[0].Tags) != 1 || resources[0].Tags["Env"] != "staging" {
		t.Fatalf("unexpected tags: %v", resources[0].Tags)
	}
	// ARN region extraction: S3 bucket ARNs don't have a region segment
	// (arn:aws:s3:::bucket), so region should be empty.
	if resources[0].Region != "" {
		t.Fatalf("unexpected region for S3 ARN: %s", resources[0].Region)
	}
}

func TestParseStateTerraformRegionFromARN(t *testing.T) {
	state := map[string]interface{}{
		"terraform_version": "1.5.0",
		"serial":            1,
		"resources": []interface{}{
			map[string]interface{}{
				"mode": "managed",
				"type": "aws_ec2_instance",
				"name": "my_instance",
				"instances": []interface{}{
					map[string]interface{}{
						"attributes": map[string]interface{}{
							"arn": "arn:aws:ec2:us-west-2:123456789012:instance/i-123",
						},
					},
				},
			},
		},
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "terraform.tfstate")
	writeJSON(t, path, state)

	resources, err := ParseState(Options{StateFile: path})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	if resources[0].Region != "us-west-2" {
		t.Fatalf("unexpected region: %s", resources[0].Region)
	}
}

func TestParseStateUnrecognized(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "unknown.json")
	writeJSON(t, path, map[string]interface{}{"foo": "bar"})

	_, err := ParseState(Options{StateFile: path})
	if err == nil {
		t.Fatal("expected error for unrecognized state format")
	}
	lines := strings.Count(err.Error(), "\n")
	if lines != 2 {
		t.Fatalf("expected three-line error (2 newlines), got %d: %v", lines, err)
	}
}

func TestParseStateMalformedJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad.json")
	if err := os.WriteFile(path, []byte(`{"invalid`), 0o644); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	_, err := ParseState(Options{StateFile: path})
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	lines := strings.Count(err.Error(), "\n")
	if lines != 2 {
		t.Fatalf("expected three-line error (2 newlines), got %d: %v", lines, err)
	}
}

func TestParseStateLargeFileWithYes(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "large.json")

	// Create a file just over 100 MB.
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating file: %v", err)
	}
	if _, err := f.WriteString(`{"terraform_version":"1.0.0","resources":[]}`); err != nil {
		t.Fatalf("writing header: %v", err)
	}
	target := int64(100*1024*1024 + 1)
	if err := f.Truncate(target); err != nil {
		t.Fatalf("truncating file: %v", err)
	}
	f.Close()

	_, err = ParseState(Options{StateFile: path, Yes: true})
	if err == nil {
		t.Fatal("expected error for empty resources")
	}
	// The size guard should have allowed it because Yes=true.
	// We expect the parser itself to error (no resources) rather than size error.
	if strings.Contains(err.Error(), "size limit") {
		t.Fatalf("expected parser error, got size error: %v", err)
	}
}

func TestParseStateLargeFileNoTUI(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "large.json")

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating file: %v", err)
	}
	if _, err := f.WriteString(`{}`); err != nil {
		t.Fatalf("writing header: %v", err)
	}
	target := int64(100*1024*1024 + 1)
	if err := f.Truncate(target); err != nil {
		t.Fatalf("truncating file: %v", err)
	}
	f.Close()

	_, err = ParseState(Options{StateFile: path, NoTUI: true})
	if err == nil {
		t.Fatal("expected error for large file with NoTUI")
	}
	if !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("expected size limit error, got: %v", err)
	}
}

func TestParseStateProvisionerRemoteExecDenylist(t *testing.T) {
	state := map[string]interface{}{
		"terraform_version": "1.5.0",
		"serial":            1,
		"resources": []interface{}{
			map[string]interface{}{
				"mode": "managed",
				"type": "aws_instance",
				"name": "web",
				"provisioner": []interface{}{
					map[string]interface{}{
						"type":   "remote-exec",
						"inline": []interface{}{"echo hello"},
					},
				},
				"instances": []interface{}{
					map[string]interface{}{
						"attributes": map[string]interface{}{
							"ami": "ami-123",
						},
					},
				},
			},
		},
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "terraform.tfstate")
	writeJSON(t, path, state)

	_, err := ParseState(Options{StateFile: path})
	if err == nil {
		t.Fatal("expected error for remote-exec provisioner")
	}
	if !strings.Contains(err.Error(), "blocked provisioner") {
		t.Fatalf("expected blocked provisioner error, got: %v", err)
	}
	lines := strings.Count(err.Error(), "\n")
	if lines != 2 {
		t.Fatalf("expected three-line error (2 newlines), got %d: %v", lines, err)
	}
}

func writeJSON(t *testing.T, path string, v interface{}) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshaling JSON: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("writing file: %v", err)
	}
}
