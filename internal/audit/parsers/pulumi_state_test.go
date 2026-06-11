package parsers

import (
	"testing"
)

func TestParsePulumiStateBasic(t *testing.T) {
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
							"Env":   "prod",
							"Owner": "platform",
						},
						"region": "us-east-1",
					},
				},
			},
		},
	}

	resources, err := ParsePulumiState(state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}

	r := resources[0]
	if r.Type != "aws:s3/bucket:Bucket" {
		t.Fatalf("unexpected type: %s", r.Type)
	}
	if r.URN != "urn:pulumi:dev::stack::aws:s3/bucket:Bucket::my-bucket" {
		t.Fatalf("unexpected URN: %s", r.URN)
	}
	if r.Region != "us-east-1" {
		t.Fatalf("unexpected region: %s", r.Region)
	}
	if len(r.Tags) != 2 || r.Tags["Env"] != "prod" || r.Tags["Owner"] != "platform" {
		t.Fatalf("unexpected tags: %v", r.Tags)
	}
}

func TestParsePulumiStateTopLevelResources(t *testing.T) {
	state := map[string]interface{}{
		"version": 3,
		"resources": []interface{}{
			map[string]interface{}{
				"urn":  "urn:pulumi:dev::stack::aws:ec2/instance:Instance::web",
				"type": "aws:ec2/instance:Instance",
				"inputs": map[string]interface{}{
					"instanceType": "t3.micro",
				},
			},
		},
	}

	resources, err := ParsePulumiState(state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	if resources[0].Type != "aws:ec2/instance:Instance" {
		t.Fatalf("unexpected type: %s", resources[0].Type)
	}
}

func TestParsePulumiStateBothArraysNoDuplicates(t *testing.T) {
	state := map[string]interface{}{
		"version": 3,
		"deployment": map[string]interface{}{
			"resources": []interface{}{
				map[string]interface{}{
					"urn":  "urn:pulumi:dev::stack::aws:s3/bucket:Bucket::my-bucket",
					"type": "aws:s3/bucket:Bucket",
				},
			},
		},
		"resources": []interface{}{
			map[string]interface{}{
				"urn":  "urn:pulumi:dev::stack::aws:s3/bucket:Bucket::my-bucket",
				"type": "aws:s3/bucket:Bucket",
			},
		},
	}

	resources, err := ParsePulumiState(state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource (no double-count), got %d", len(resources))
	}
	if resources[0].URN != "urn:pulumi:dev::stack::aws:s3/bucket:Bucket::my-bucket" {
		t.Fatalf("unexpected URN: %s", resources[0].URN)
	}
}

func TestParsePulumiStateEmptyResources(t *testing.T) {
	state := map[string]interface{}{
		"version": 3,
		"deployment": map[string]interface{}{
			"resources": []interface{}{},
		},
	}

	_, err := ParsePulumiState(state)
	if err == nil {
		t.Fatal("expected error for empty resources")
	}
}

func TestParsePulumiStateNoResourcesKey(t *testing.T) {
	state := map[string]interface{}{
		"version": 3,
	}

	_, err := ParsePulumiState(state)
	if err == nil {
		t.Fatal("expected error for missing resources")
	}
}

func TestParsePulumiStateUnknownURNFallback(t *testing.T) {
	state := map[string]interface{}{
		"version": 3,
		"deployment": map[string]interface{}{
			"resources": []interface{}{
				map[string]interface{}{
					"type": "aws:s3/bucket:Bucket",
				},
			},
		},
	}

	resources, err := ParsePulumiState(state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resources[0].URN != "unknown" {
		t.Fatalf("expected URN 'unknown', got %s", resources[0].URN)
	}
}
