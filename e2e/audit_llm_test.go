//go:build e2e_llm

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAuditSource_LLM exercises the --llm <provider> path against a real
// LLM. Build-tagged off the default suite — only meaningful when a provider
// has been logged in via `cbx llm api login <provider>`. Skips cleanly when
// CBX_LLM_PROVIDER is unset or the per-CI keyring is empty.
func TestAuditSource_LLM(t *testing.T) {
	provider := os.Getenv("CBX_LLM_PROVIDER")
	if provider == "" {
		t.Skip("CBX_LLM_PROVIDER not set; skipping real-LLM e2e")
	}

	fixture, err := filepath.Abs("fixtures/terraform-sample-source")
	if err != nil {
		t.Fatalf("resolving fixture path: %v", err)
	}
	tmpDir := t.TempDir()

	stdout, stderr, code := runCBXInDir(t, tmpDir, nil,
		"audit", "--source", fixture, "--llm", provider, "--output", "json")

	// Exit code is severity-driven; zero or non-zero are both acceptable
	// outcomes — we only care about the JSON shape.
	_ = code
	_ = stderr

	requireJSONValid(t, stdout)

	var envelope struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
		t.Fatalf("parsing JSON envelope: %v", err)
	}
	if len(envelope.Data) == 0 {
		t.Fatalf("expected at least one finding from LLM analyzer, got none\nstdout: %s\nstderr: %s", stdout, stderr)
	}

	sawLLMRule := false
	for _, f := range envelope.Data {
		for _, field := range []string{"rule_id", "title", "severity"} {
			if _, ok := f[field]; !ok {
				t.Fatalf("finding missing field %q: %+v", field, f)
			}
		}
		if rid, ok := f["rule_id"].(string); ok && strings.HasPrefix(rid, "LLM-") {
			sawLLMRule = true
		}
	}
	if !sawLLMRule {
		t.Fatalf("expected at least one LLM- prefixed rule_id, got: %+v", envelope.Data)
	}
}
