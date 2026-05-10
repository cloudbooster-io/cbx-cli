package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAuditFlagMutex covers the input-flag exclusion logic added in MR 1.
// Exactly one of --pulumi-state, --terraform-state, --source must be set.
func TestAuditFlagMutex(t *testing.T) {
	cases := []struct {
		name        string
		args        []string
		wantErrSub  string
		wantSuccess bool
	}{
		{
			name:       "no input flag",
			args:       []string{"audit"},
			wantErrSub: "exactly one of --pulumi-state, --terraform-state, or --source",
		},
		{
			name:       "source and terraform together",
			args:       []string{"audit", "--source", ".", "--terraform-state", "x.tfstate"},
			wantErrSub: "mutually exclusive",
		},
		{
			name:       "source and pulumi together",
			args:       []string{"audit", "--source", ".", "--pulumi-state", "x.json"},
			wantErrSub: "mutually exclusive",
		},
		{
			name:       "all three together",
			args:       []string{"audit", "--source", ".", "--pulumi-state", "x.json", "--terraform-state", "y.tfstate"},
			wantErrSub: "mutually exclusive",
		},
		{
			name:       "invalid iac-type",
			args:       []string{"audit", "--source", ".", "--iac-type", "bogus"},
			wantErrSub: "invalid --iac-type",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := NewRootCmd()
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&out)
			cmd.SetArgs(tc.args)

			err := cmd.Execute()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil; output=%s", tc.wantErrSub, out.String())
			}
			if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Fatalf("expected error to contain %q, got %v", tc.wantErrSub, err)
			}
		})
	}
}

// TestAuditMockBanner verifies the source-mode mock banner fires on a plain
// `audit --source` invocation and stays suppressed when the user asks for
// machine-readable output (--json or --output=...) or --quiet.
func TestAuditMockBanner(t *testing.T) {
	cases := []struct {
		name       string
		extraArgs  []string
		wantBanner bool
	}{
		{
			name:       "plain run prints banner",
			extraArgs:  nil,
			wantBanner: true,
		},
		{
			name:       "--quiet suppresses banner",
			extraArgs:  []string{"--quiet"},
			wantBanner: false,
		},
		{
			name:       "--json suppresses banner",
			extraArgs:  []string{"--json"},
			wantBanner: false,
		},
		{
			name:       "--output markdown suppresses banner",
			extraArgs:  []string{"--output", "markdown"},
			wantBanner: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Run() writes a report file to CWD; redirect to a tempdir so
			// the test doesn't pollute the repo or fight other tests.
			t.Chdir(t.TempDir())
			source := t.TempDir()
			if err := os.WriteFile(filepath.Join(source, "main.tf"), []byte("resource \"null_resource\" \"x\" {}"), 0o644); err != nil {
				t.Fatalf("seed fixture: %v", err)
			}

			// stderr can't be captured through cmd.SetErr because audit.go
			// writes the banner directly to os.Stderr (matching how the
			// update-banner / report-written line already work). Redirect
			// the real fd for the duration of the call.
			origStderr := os.Stderr
			r, w, pipeErr := os.Pipe()
			if pipeErr != nil {
				t.Fatalf("pipe: %v", pipeErr)
			}
			os.Stderr = w

			cmd := NewRootCmd()
			args := append([]string{"audit", "--source", source}, tc.extraArgs...)
			cmd.SetArgs(args)
			var out bytes.Buffer
			cmd.SetOut(&out)

			runErr := cmd.Execute()

			// Severity-driven exit code propagates through cobra as an error.
			// We don't care about exit code here, only the banner.
			_ = runErr

			_ = w.Close()
			os.Stderr = origStderr

			var stderr bytes.Buffer
			_, _ = stderr.ReadFrom(r)

			hasBanner := strings.Contains(stderr.String(), "built-in mock scanner used")
			if hasBanner != tc.wantBanner {
				t.Fatalf("banner present = %v, want %v\nstderr:\n%s", hasBanner, tc.wantBanner, stderr.String())
			}
		})
	}
}
