package parsers

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTF(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("seed %s: %v", name, err)
	}
}

func TestParseTerraformSource_LiteralResource(t *testing.T) {
	dir := t.TempDir()
	writeTF(t, dir, "main.tf", `
resource "aws_s3_bucket" "demo" {
  bucket = "cbx-demo"
  acl    = "private"
  tags = {
    Owner = "team-platform"
    Env   = "dev"
  }
}
`)

	resources, err := ParseTerraformSource(dir)
	if err != nil {
		t.Fatalf("ParseTerraformSource: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	got := resources[0]
	if got.Type != "aws_s3_bucket" {
		t.Errorf("Type = %q, want aws_s3_bucket", got.Type)
	}
	if got.URN != "aws_s3_bucket.demo" {
		t.Errorf("URN = %q, want aws_s3_bucket.demo", got.URN)
	}
	if got.Inputs["bucket"] != "cbx-demo" {
		t.Errorf("bucket input = %v, want cbx-demo", got.Inputs["bucket"])
	}
	if got.Tags["Owner"] != "team-platform" {
		t.Errorf("Tags[Owner] = %q, want team-platform", got.Tags["Owner"])
	}
}

func TestParseTerraformSource_ProviderRegionAttached(t *testing.T) {
	dir := t.TempDir()
	writeTF(t, dir, "main.tf", `
provider "aws" {
  region = "eu-west-1"
}

resource "aws_s3_bucket" "x" {
  bucket = "name"
}
`)

	resources, err := ParseTerraformSource(dir)
	if err != nil {
		t.Fatalf("ParseTerraformSource: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	if resources[0].Region != "eu-west-1" {
		t.Errorf("Region = %q, want eu-west-1", resources[0].Region)
	}
}

func TestParseTerraformSource_NonLiteralAttrSkipped(t *testing.T) {
	// `var.x` references are T1-out-of-scope: the resource is still emitted
	// but the unresolved attribute drops out of Inputs (not an error).
	dir := t.TempDir()
	writeTF(t, dir, "main.tf", `
variable "name" {
  default = "anything"
}

resource "aws_s3_bucket" "demo" {
  bucket = var.name
  acl    = "private"
}
`)

	resources, err := ParseTerraformSource(dir)
	if err != nil {
		t.Fatalf("ParseTerraformSource: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	if _, has := resources[0].Inputs["bucket"]; has {
		t.Errorf("var-ref bucket attr leaked into Inputs (T1 should skip): %v", resources[0].Inputs)
	}
	if resources[0].Inputs["acl"] != "private" {
		t.Errorf("acl literal should still be present: %v", resources[0].Inputs)
	}
}

func TestParseTerraformSource_CountResourceEmittedOnce(t *testing.T) {
	// Plan §6.1: count not expanded in T1; one resource, count attr preserved.
	dir := t.TempDir()
	writeTF(t, dir, "main.tf", `
resource "aws_s3_bucket" "many" {
  count  = 3
  bucket = "fixed"
}
`)

	resources, err := ParseTerraformSource(dir)
	if err != nil {
		t.Fatalf("ParseTerraformSource: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("count should not expand in T1; expected 1, got %d", len(resources))
	}
	if v, ok := resources[0].Inputs["count"].(float64); !ok || v != 3 {
		t.Errorf("count attr should be preserved; got %v", resources[0].Inputs["count"])
	}
}

func TestParseTerraformSource_MultiFileSorted(t *testing.T) {
	// Multiple files should be parsed and resources returned in URN order.
	dir := t.TempDir()
	writeTF(t, dir, "b.tf", `resource "aws_s3_bucket" "bbb" { bucket = "b" }`)
	writeTF(t, dir, "a.tf", `resource "aws_s3_bucket" "aaa" { bucket = "a" }`)

	resources, err := ParseTerraformSource(dir)
	if err != nil {
		t.Fatalf("ParseTerraformSource: %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(resources))
	}
	if resources[0].URN != "aws_s3_bucket.aaa" || resources[1].URN != "aws_s3_bucket.bbb" {
		t.Errorf("resources should be URN-sorted; got %q, %q", resources[0].URN, resources[1].URN)
	}
}

func TestParseTerraformSource_SkipsNoiseDirs(t *testing.T) {
	dir := t.TempDir()
	writeTF(t, dir, "root.tf", `resource "aws_s3_bucket" "root" { bucket = "r" }`)
	if err := os.MkdirAll(filepath.Join(dir, ".terraform", "modules", "x"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeTF(t, filepath.Join(dir, ".terraform", "modules", "x"), "leaked.tf",
		`resource "aws_s3_bucket" "leaked" { bucket = "ghost" }`)

	resources, err := ParseTerraformSource(dir)
	if err != nil {
		t.Fatalf("ParseTerraformSource: %v", err)
	}
	if len(resources) != 1 || resources[0].URN != "aws_s3_bucket.root" {
		t.Errorf(".terraform-cached resources leaked into output: %+v", resources)
	}
}

func TestParseTerraformSource_CrossModeInvariant(t *testing.T) {
	// Source-mode and state-mode parsers should produce the same Type and
	// URN-like address shape for the same resource definition. State mode
	// uses `aws_s3_bucket` for both Pulumi-style and TF-style; source mode
	// should match.
	dir := t.TempDir()
	writeTF(t, dir, "main.tf", `
resource "aws_s3_bucket" "demo" {
  bucket = "cbx-demo"
}
`)
	srcRes, err := ParseTerraformSource(dir)
	if err != nil {
		t.Fatalf("ParseTerraformSource: %v", err)
	}
	if len(srcRes) != 1 {
		t.Fatalf("expected 1 source-mode resource, got %d", len(srcRes))
	}
	if srcRes[0].Type != "aws_s3_bucket" {
		t.Errorf("source-mode Type %q diverges from state-mode 'aws_s3_bucket'", srcRes[0].Type)
	}
	// State-mode produces URN values like "aws_s3_bucket.demo" via Terraform
	// addressing; the source parser must do the same.
	if srcRes[0].URN != "aws_s3_bucket.demo" {
		t.Errorf("URN format %q diverges from state-mode <type>.<name>", srcRes[0].URN)
	}
}
