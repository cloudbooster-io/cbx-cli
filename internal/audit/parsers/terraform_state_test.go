package parsers

import (
	"strings"
	"testing"
)

func TestParseTerraformStateBasic(t *testing.T) {
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
							"region": "eu-west-1",
						},
					},
				},
			},
		},
	}

	resources, err := ParseTerraformState(state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}

	r := resources[0]
	if r.Type != "aws_s3_bucket" {
		t.Fatalf("unexpected type: %s", r.Type)
	}
	if r.URN != "my_bucket" {
		t.Fatalf("unexpected URN: %s", r.URN)
	}
	if r.Region != "eu-west-1" {
		t.Fatalf("unexpected region: %s", r.Region)
	}
	if len(r.Tags) != 1 || r.Tags["Env"] != "staging" {
		t.Fatalf("unexpected tags: %v", r.Tags)
	}
}

func TestParseTerraformStateRegionFromARN(t *testing.T) {
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

	resources, err := ParseTerraformState(state)
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

func TestParseTerraformStateValuesNesting(t *testing.T) {
	state := map[string]interface{}{
		"terraform_version": "1.5.0",
		"serial":            1,
		"values": map[string]interface{}{
			"root_module": map[string]interface{}{
				"resources": []interface{}{
					map[string]interface{}{
						"type": "aws_iam_role",
						"name": "lambda_role",
						"values": map[string]interface{}{
							"name": "lambda-role",
						},
					},
				},
			},
		},
	}

	resources, err := ParseTerraformState(state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	if resources[0].Type != "aws_iam_role" {
		t.Fatalf("unexpected type: %s", resources[0].Type)
	}
}

func TestParseTerraformStateChildModules(t *testing.T) {
	state := map[string]interface{}{
		"terraform_version": "1.5.0",
		"serial":            1,
		"values": map[string]interface{}{
			"root_module": map[string]interface{}{
				"resources": []interface{}{
					map[string]interface{}{
						"type": "aws_iam_role",
						"name": "root_role",
						"values": map[string]interface{}{
							"name": "root-role",
						},
					},
				},
				"child_modules": []interface{}{
					map[string]interface{}{
						"address": "module.network",
						"resources": []interface{}{
							map[string]interface{}{
								"type": "aws_vpc",
								"name": "main",
								"values": map[string]interface{}{
									"cidr_block": "10.0.0.0/16",
								},
							},
						},
						"child_modules": []interface{}{
							map[string]interface{}{
								"address": "module.network.module.subnets",
								"resources": []interface{}{
									map[string]interface{}{
										"type": "aws_subnet",
										"name": "private",
										"values": map[string]interface{}{
											"cidr_block": "10.0.1.0/24",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	resources, err := ParseTerraformState(state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resources) != 3 {
		t.Fatalf("expected 3 resources, got %d", len(resources))
	}

	types := map[string]bool{}
	for _, r := range resources {
		types[r.Type] = true
	}
	for _, want := range []string{"aws_iam_role", "aws_vpc", "aws_subnet"} {
		if !types[want] {
			t.Fatalf("expected resource type %q to be discovered, got %v", want, types)
		}
	}
}

func TestParseTerraformStateChildModuleProvisionerDenylist(t *testing.T) {
	state := map[string]interface{}{
		"terraform_version": "1.5.0",
		"serial":            1,
		"values": map[string]interface{}{
			"root_module": map[string]interface{}{
				"child_modules": []interface{}{
					map[string]interface{}{
						"address": "module.compute",
						"resources": []interface{}{
							map[string]interface{}{
								"type": "aws_instance",
								"name": "web",
								"provisioner": []interface{}{
									map[string]interface{}{
										"type":   "remote-exec",
										"inline": []interface{}{"echo hello"},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	_, err := ParseTerraformState(state)
	if err == nil {
		t.Fatal("expected error for remote-exec provisioner in child module")
	}
	if !strings.Contains(err.Error(), "blocked provisioner") {
		t.Fatalf("expected blocked provisioner error, got: %v", err)
	}
}

func TestParseTerraformStateEmptyResources(t *testing.T) {
	state := map[string]interface{}{
		"terraform_version": "1.5.0",
		"serial":            1,
		"resources":         []interface{}{},
	}

	_, err := ParseTerraformState(state)
	if err == nil {
		t.Fatal("expected error for empty resources")
	}
}

func TestParseTerraformStateProvisionerDenylistResourceLevel(t *testing.T) {
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

	_, err := ParseTerraformState(state)
	if err == nil {
		t.Fatal("expected error for remote-exec provisioner")
	}
	if !strings.Contains(err.Error(), "blocked provisioner") {
		t.Fatalf("expected blocked provisioner error, got: %v", err)
	}
}

func TestParseTerraformStateProvisionerDenylistInstanceLevel(t *testing.T) {
	state := map[string]interface{}{
		"terraform_version": "1.5.0",
		"serial":            1,
		"resources": []interface{}{
			map[string]interface{}{
				"mode": "managed",
				"type": "aws_instance",
				"name": "web",
				"instances": []interface{}{
					map[string]interface{}{
						"provisioner": []interface{}{
							map[string]interface{}{
								"type":   "remote-exec",
								"inline": []interface{}{"echo hello"},
							},
						},
						"attributes": map[string]interface{}{
							"ami": "ami-123",
						},
					},
				},
			},
		},
	}

	_, err := ParseTerraformState(state)
	if err == nil {
		t.Fatal("expected error for remote-exec provisioner in instance")
	}
	if !strings.Contains(err.Error(), "blocked provisioner") {
		t.Fatalf("expected blocked provisioner error, got: %v", err)
	}
}

func TestParseTerraformStateLocalExecAllowed(t *testing.T) {
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
						"type":   "local-exec",
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

	resources, err := ParseTerraformState(state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
}

func TestRegionFromARN(t *testing.T) {
	cases := []struct {
		arn      string
		expected string
	}{
		{"arn:aws:ec2:us-west-2:123456789012:instance/i-123", "us-west-2"},
		{"arn:aws:s3:::bucket-name", ""},
		{"", ""},
		{"not-an-arn", ""},
	}

	for _, tc := range cases {
		got := regionFromARN(tc.arn)
		if got != tc.expected {
			t.Fatalf("regionFromARN(%q) = %q, want %q", tc.arn, got, tc.expected)
		}
	}
}
