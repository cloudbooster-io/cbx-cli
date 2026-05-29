package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectIaCType(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			name: "terraform",
			files: map[string]string{
				"main.tf": `resource "aws_s3_bucket" "b" { bucket = "demo" }`,
			},
			want: IaCTypeTerraform,
		},
		{
			name: "terraform_json",
			files: map[string]string{
				"main.tf.json": `{"resource":{}}`,
			},
			want: IaCTypeTerraform,
		},
		{
			name: "cloudformation_yaml_with_marker",
			files: map[string]string{
				"template.yaml": "AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n",
			},
			want: IaCTypeCloudFormation,
		},
		{
			name: "cloudformation_yaml_no_marker_but_aws_type",
			files: map[string]string{
				"template.yml": "Resources:\n  B:\n    Type: AWS::S3::Bucket\n",
			},
			want: IaCTypeCloudFormation,
		},
		{
			name: "cloudformation_json",
			files: map[string]string{
				"template.json": `{"Resources":{"B":{"Type":"AWS::S3::Bucket"}}}`,
			},
			want: IaCTypeCloudFormation,
		},
		{
			name: "k8s",
			files: map[string]string{
				"deploy.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: demo\n",
			},
			want: IaCTypeK8s,
		},
		{
			name: "helm",
			files: map[string]string{
				"Chart.yaml":            "apiVersion: v2\nname: demo\nversion: 0.1.0\n",
				"templates/deploy.yaml": "apiVersion: apps/v1\nkind: Deployment\n",
			},
			want: IaCTypeHelm,
		},
		{
			// Chart.yaml itself has apiVersion + kind:-shaped fields, so we
			// must make sure detection doesn't accidentally classify the
			// chart root as plain k8s when no other YAML is present.
			name: "helm_chart_only",
			files: map[string]string{
				"Chart.yaml": "apiVersion: v2\nname: demo\nversion: 0.1.0\n",
			},
			want: IaCTypeHelm,
		},
		{
			name: "first_match_wins_terraform_over_cfn",
			files: map[string]string{
				"main.tf":       `resource "x" "y" {}`,
				"template.yaml": "AWSTemplateFormatVersion: '2010-09-09'\n",
			},
			want: IaCTypeTerraform,
		},
		{
			name: "empty_dir",
			files: map[string]string{
				"README.md": "nothing here",
			},
			want: "",
		},
		{
			name:  "completely_empty",
			files: map[string]string{},
			want:  "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for relPath, content := range tc.files {
				full := filepath.Join(dir, relPath)
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
					t.Fatalf("write %s: %v", relPath, err)
				}
			}
			got := detectIaCType(dir)
			if got != tc.want {
				t.Fatalf("detectIaCType(%s) = %q, want %q", tc.name, got, tc.want)
			}
		})
	}
}

func TestProviderSupportsIaCType(t *testing.T) {
	cases := []struct {
		provider FindingProvider
		iacType  string
		want     bool
	}{
		{&tfsecAdapter{}, IaCTypeTerraform, true},
		{&tfsecAdapter{}, IaCTypeCloudFormation, false},
		{&tfsecAdapter{}, IaCTypeK8s, false},
		{&tfsecAdapter{}, IaCTypeHelm, false},
		{&tfsecAdapter{}, "", true}, // unknown / empty type is permissive
		{&checkovAdapter{}, IaCTypeTerraform, true},
		{&checkovAdapter{}, IaCTypeCloudFormation, true},
		{&checkovAdapter{}, IaCTypeK8s, true},
		{&checkovAdapter{}, IaCTypeHelm, true},
		{&trivyAdapter{}, IaCTypeCloudFormation, true},
		{&trivyAdapter{}, IaCTypeK8s, true},
		{&staticScanner{}, IaCTypeCloudFormation, true},
	}
	for _, tc := range cases {
		got := providerSupportsIaCType(tc.provider, tc.iacType)
		if got != tc.want {
			t.Errorf("providerSupportsIaCType(%s, %q) = %v, want %v", tc.provider.Name(), tc.iacType, got, tc.want)
		}
	}
}
