package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
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
					},
				},
			},
		},
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "pulumi.json")
	writeJSON(t, path, state)

	resources, err := ParseState(path)
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
						},
					},
				},
			},
		},
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "terraform.tfstate")
	writeJSON(t, path, state)

	resources, err := ParseState(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	if resources[0].Type != "aws_s3_bucket" {
		t.Fatalf("unexpected type: %s", resources[0].Type)
	}
}

func TestParseStateUnrecognized(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "unknown.json")
	writeJSON(t, path, map[string]interface{}{"foo": "bar"})

	_, err := ParseState(path)
	if err == nil {
		t.Fatal("expected error for unrecognized state format")
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
