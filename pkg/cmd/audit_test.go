package cmd

import (
	"bytes"
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
		{
			name:       "--llm and --scanners together",
			args:       []string{"audit", "--source", ".", "--llm", "claude", "--scanners", "tfsec"},
			wantErrSub: "--llm and --scanners are mutually exclusive",
		},
		{
			name:       "--llm without --source",
			args:       []string{"audit", "--terraform-state", "x.tfstate", "--llm", "claude"},
			wantErrSub: "--llm requires --source",
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
