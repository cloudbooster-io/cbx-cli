package cmd

import (
	"github.com/cloudbooster-io/cbx-cli/internal/output"

	"github.com/spf13/cobra"
)

// newAuditCmd is now a thin dispatcher whose only real job is to host the
// `aws` subcommand. The earlier IaC source / state-file inputs
// (--pulumi-state, --terraform-state, --source, --iac-type, --llm,
// --scanners, ...) are no longer exposed at the CLI surface. The
// underlying parsers/scanners/analyzers in internal/audit and the
// pkg/audit facade are unchanged, so library callers (including downstream consumers)
// can still drive them programmatically; only the user-facing flag
// surface is closed.
func newAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit live cloud infrastructure",
		Long:  `Audit live cloud infrastructure. The only target shipped today is AWS (see 'cbx audit aws').`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return output.NewError(output.ErrorDetail{
				What: "no audit target selected",
				Why:  "`cbx audit` is a dispatcher; the audit itself runs against a target",
				Fix:  "run `cbx audit aws` to audit a live AWS account",
				Code: "E_NO_AUDIT_TARGET",
			})
		},
	}

	cmd.AddCommand(newAuditAWSCmd())

	return cmd
}
