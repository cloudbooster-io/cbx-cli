package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// RequireExactlyOneArg returns a positional-args validator that swaps
// cobra's default "accepts 1 arg(s), received 0" for an actionable
// error including a one-line usage hint. label names the argument
// (e.g. "provider", "executor"); usage is a short copy-paste-ready
// example.
//
// Exported because downstream consumers (downstream consumers) reuse it when wiring
// the same cobra commands.
func RequireExactlyOneArg(label, usage string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("missing %s argument\n\nUsage: %s", label, usage)
		}
		if len(args) > 1 {
			return fmt.Errorf("too many arguments; expected exactly one %s\n\nUsage: %s", label, usage)
		}
		return nil
	}
}
