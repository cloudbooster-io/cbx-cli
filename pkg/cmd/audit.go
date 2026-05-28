package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newAuditCmd is now a thin dispatcher whose only real job is to host the
// `aws` subcommand. The earlier IaC source / state-file inputs
// (--pulumi-state, --terraform-state, --source, --iac-type, --llm,
// --scanners, ...) are no longer exposed at the CLI surface. The
// underlying parsers/scanners/analyzers in internal/audit and the
// pkg/audit facade are unchanged, so library callers (including cb-cli)
// can still drive them programmatically; only the user-facing flag
// surface is closed.
func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit live cloud infrastructure",
		Long:  `Audit live cloud infrastructure. The only target shipped today is AWS (see 'cbx audit aws').`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("no audit target selected — run 'cbx audit aws' to audit a live AWS account")
		},
	}

	cmd.AddCommand(newAuditAWSCmd())

	return cmd
}
