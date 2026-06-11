package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// scannerMeta holds metadata for an external scanner binary.
type scannerMeta struct {
	Name       string
	MinVersion string
	MaxVersion string
	AllowAWS   bool
	InstallCmd map[string]string // OS → install command
}

var scannerRegistry = map[string]scannerMeta{
	"tfsec": {
		Name:       "tfsec",
		MinVersion: "1.28.0",
		MaxVersion: "2.0.0",
		AllowAWS:   false,
		InstallCmd: map[string]string{
			"darwin": "brew install tfsec",
			"linux":  "go install github.com/aquasecurity/tfsec/cmd/tfsec@latest",
		},
	},
	"checkov": {
		Name:       "checkov",
		MinVersion: "2.4.0",
		// Bumped to 4.0.0 — checkov 3.2.x is the current stable; the
		// previous 3.0.0 cap rejected every real install.
		MaxVersion: "4.0.0",
		AllowAWS:   false,
		InstallCmd: map[string]string{
			"darwin": "brew install checkov",
			"linux":  "pip install checkov",
		},
	},
	"prowler": {
		Name:       "prowler",
		MinVersion: "3.0.0",
		MaxVersion: "5.0.0",
		AllowAWS:   true,
		InstallCmd: map[string]string{
			"darwin": "brew install prowler",
			"linux":  "pip install prowler",
		},
	},
	"trivy": {
		Name:       "trivy",
		MinVersion: "0.48.0",
		MaxVersion: "1.0.0",
		AllowAWS:   false,
		InstallCmd: map[string]string{
			"darwin": "brew install aquasecurity/trivy/trivy",
			"linux":  "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin",
		},
	},
}

// scrubEnv returns a sanitized copy of the current environment.
// It strips CB_API_KEY, ANTHROPIC_API_KEY, and OPENAI_API_KEY.
// AWS_ variables are only retained when allowAWS is true.
func scrubEnv(allowAWS bool) []string {
	var out []string
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "CB_API_KEY=") ||
			strings.HasPrefix(e, "ANTHROPIC_API_KEY=") ||
			strings.HasPrefix(e, "OPENAI_API_KEY=") {
			continue
		}
		if !allowAWS && strings.HasPrefix(e, "AWS_") {
			continue
		}
		out = append(out, e)
	}
	return out
}

// runScanner executes a scanner binary with the given arguments and returns
// its stdout. The context bounds the subprocess lifetime: cancellation or a
// deadline kills the binary, so a hung scanner cannot wedge the CLI. Stderr
// is intentionally segregated: scanners (notably tfsec) write deprecation
// banners and progress chatter to stderr that would otherwise corrupt the
// JSON parsers downstream. On error stderr is folded into the returned
// error message so the user still sees it.
func runScanner(ctx context.Context, name string, args []string, allowAWS bool) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = scrubEnv(allowAWS)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return stdout, fmt.Errorf("%w: %s", err, msg)
		}
		return stdout, err
	}
	return stdout, nil
}

// missingBinaryError returns a formatted multi-line error for a missing
// scanner binary including an OS-specific install command.
func missingBinaryError(meta scannerMeta) error {
	cmd, ok := meta.InstallCmd[runtime.GOOS]
	if !ok {
		cmd = fmt.Sprintf("See %s documentation for installation instructions", meta.Name)
	}
	return fmt.Errorf("%s is not installed\n\nTo install %s:\n  %s", meta.Name, meta.Name, cmd)
}

// versionRe matches semantic versions like v1.2.3 or 1.2.3.
var versionRe = regexp.MustCompile(`v?(\d+\.\d+(?:\.\d+)?)`)

// checkVersion verifies the scanner binary version is within the
// supported range. If the binary is not found it returns a
// missing-binary error.
func checkVersion(ctx context.Context, meta scannerMeta) error {
	out, err := runScanner(ctx, meta.Name, []string{"--version"}, meta.AllowAWS)
	if err != nil {
		// Distinguish "not found" from other exec errors without
		// re-executing the binary.
		if _, lookErr := exec.LookPath(meta.Name); lookErr != nil {
			return missingBinaryError(meta)
		}
		return fmt.Errorf("checking %s version: %w", meta.Name, err)
	}

	versionStr := strings.TrimSpace(string(out))
	version := extractVersion(versionStr)
	if version == "" {
		return fmt.Errorf("could not parse %s version from: %s", meta.Name, versionStr)
	}
	if meta.MinVersion != "" && versionLess(version, meta.MinVersion) {
		return fmt.Errorf("%s version %s is below minimum %s", meta.Name, version, meta.MinVersion)
	}
	if meta.MaxVersion != "" && versionGreaterOrEqual(version, meta.MaxVersion) {
		return fmt.Errorf("%s version %s is at or above maximum %s", meta.Name, version, meta.MaxVersion)
	}
	return nil
}

func extractVersion(s string) string {
	m := versionRe.FindStringSubmatch(s)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

func versionLess(a, b string) bool {
	return compareVersions(a, b) < 0
}

func versionGreaterOrEqual(a, b string) bool {
	return compareVersions(a, b) >= 0
}

func compareVersions(a, b string) int {
	pa := parseVersion(a)
	pb := parseVersion(b)
	for i := 0; i < 3; i++ {
		if i < len(pa) && i < len(pb) {
			if pa[i] < pb[i] {
				return -1
			}
			if pa[i] > pb[i] {
				return 1
			}
		} else if i < len(pa) {
			return 1
		} else if i < len(pb) {
			return -1
		}
	}
	return 0
}

func parseVersion(s string) []int {
	parts := strings.Split(s, ".")
	var out []int
	for _, p := range parts {
		var n int
		_, _ = fmt.Sscanf(p, "%d", &n)
		out = append(out, n)
	}
	return out
}

// writeResourcesToTempDir creates a temporary directory containing
// Terraform JSON (.tf.json) representations of the given resources.
// The caller is responsible for removing the directory.
func writeResourcesToTempDir(resources []Resource) (string, error) {
	dir, err := os.MkdirTemp("", "cbx-audit-*")
	if err != nil {
		return "", fmt.Errorf("creating temp dir: %w", err)
	}

	for i, res := range resources {
		tfType := pulumiTypeToTerraformType(res.Type)
		if tfType == "" {
			continue
		}
		name := fmt.Sprintf("resource_%d", i)
		if res.URN != "" && res.URN != "unknown" {
			name = sanitizeName(res.URN)
		}

		inputs := res.Inputs
		if inputs == nil {
			inputs = map[string]interface{}{}
		}

		doc := map[string]interface{}{
			"resource": map[string]interface{}{
				tfType: map[string]interface{}{
					name: inputs,
				},
			},
		}

		filename := filepath.Join(dir, fmt.Sprintf("%s_%d.tf.json", tfType, i))
		data, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			_ = os.RemoveAll(dir)
			return "", fmt.Errorf("marshaling resource: %w", err)
		}
		if err := os.WriteFile(filename, data, 0o644); err != nil {
			_ = os.RemoveAll(dir)
			return "", fmt.Errorf("writing resource file: %w", err)
		}
	}

	return dir, nil
}

// writeTerraformStateFile creates a temporary Terraform state file from
// resources and returns its path. The caller is responsible for removing
// the parent directory.
func writeTerraformStateFile(resources []Resource) (string, error) {
	dir, err := os.MkdirTemp("", "cbx-audit-*")
	if err != nil {
		return "", fmt.Errorf("creating temp dir: %w", err)
	}

	var tfResources []interface{}
	for i, res := range resources {
		tfType := pulumiTypeToTerraformType(res.Type)
		if tfType == "" {
			continue
		}
		name := fmt.Sprintf("resource_%d", i)
		if res.URN != "" && res.URN != "unknown" {
			name = sanitizeName(res.URN)
		}
		attrs := res.Inputs
		if attrs == nil {
			attrs = map[string]interface{}{}
		}
		tfResources = append(tfResources, map[string]interface{}{
			"mode":     "managed",
			"type":     tfType,
			"name":     name,
			"provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
			"instances": []interface{}{
				map[string]interface{}{
					"attributes": attrs,
				},
			},
		})
	}

	state := map[string]interface{}{
		"version":           4,
		"terraform_version": "1.5.0",
		"serial":            1,
		"resources":         tfResources,
	}

	path := filepath.Join(dir, "terraform.tfstate")
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("marshaling state: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("writing state file: %w", err)
	}
	return path, nil
}

// pulumiTypeToTerraformType maps Pulumi type tokens to their Terraform
// provider equivalents. If the type already looks like a Terraform type
// it is returned unchanged.
func pulumiTypeToTerraformType(pt string) string {
	mappings := map[string]string{
		"aws:s3/bucket:Bucket":                "aws_s3_bucket",
		"aws:ec2/securityGroup:SecurityGroup": "aws_security_group",
		"aws:iam/role:Role":                   "aws_iam_role",
		"aws:rds/instance:Instance":           "aws_db_instance",
		"aws:lambda/function:Function":        "aws_lambda_function",
	}
	if tf, ok := mappings[pt]; ok {
		return tf
	}
	if strings.Contains(pt, "_") {
		return pt
	}
	return ""
}

// sanitizeName turns an arbitrary URN/ID into a valid Terraform resource
// local name.
func sanitizeName(s string) string {
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, ".", "_")
	parts := strings.Split(s, "_")
	if len(parts) > 0 {
		last := parts[len(parts)-1]
		if last != "" {
			return last
		}
	}
	return s
}

// severity mapping helpers.

func mapTfsecSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityWarning
	case "low":
		return SeverityInfo
	default:
		return SeverityInfo
	}
}

func mapCheckovSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityWarning
	case "low", "info":
		return SeverityInfo
	default:
		return SeverityWarning
	}
}

func mapTrivySeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityWarning
	case "low":
		return SeverityInfo
	default:
		return SeverityInfo
	}
}

func mapProwlerSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityWarning
	case "low", "info":
		return SeverityInfo
	default:
		return SeverityWarning
	}
}
