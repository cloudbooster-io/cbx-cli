package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// TestAuditBareErrorsRedirectsToAWS covers the new behavior after the IaC
// source / state-file inputs were removed from the CLI surface: bare
// `cbx audit` no longer has any input flags and must error with a clear
// pointer to `cbx audit aws`.
func TestAuditBareErrorsRedirectsToAWS(t *testing.T) {
	cmd := NewRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"audit"})

	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected error from bare 'audit', got nil; output=%s", out.String())
	}
	if !strings.Contains(err.Error(), "cbx audit aws") {
		t.Fatalf("expected error to mention 'cbx audit aws', got %v", err)
	}
}

// TestAuditRemovedFlagsRejected confirms cobra rejects the old IaC flags
// rather than silently accepting them. Guards against accidental re-add.
func TestAuditRemovedFlagsRejected(t *testing.T) {
	removed := []string{
		"--pulumi-state",
		"--terraform-state",
		"--source",
		"--iac-type",
		"--scanners",
		"--llm",
		"--llm-max-files",
		"--llm-max-bytes-per-file",
		"--cb-knowledge",
		"--llm-max-cost",
	}
	for _, flag := range removed {
		t.Run(flag, func(t *testing.T) {
			cmd := NewRootCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs([]string{"audit", flag, "x"})

			err := cmd.Execute()
			if err == nil {
				t.Fatalf("expected cobra to reject %s, got nil; output=%s", flag, out.String())
			}
			if !strings.Contains(err.Error(), "unknown flag") {
				t.Fatalf("expected 'unknown flag' error for %s, got %v", flag, err)
			}
		})
	}
}
