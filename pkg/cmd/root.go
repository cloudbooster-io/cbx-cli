package cmd

import (
	"fmt"
	"os"

	"github.com/cloudbooster-io/cbx-cli/internal/output"
	"github.com/cloudbooster-io/cbx-cli/internal/telemetry"

	"github.com/spf13/cobra"
)

// Version, Commit, and Date identify the cbx build. The defaults below are
// what a plain `go build` produces; release binaries get the real values
// injected at link time via -ldflags -X (see the Makefile's LDFLAGS and
// .goreleaser.yml), which is why they are vars rather than consts.
var (
	// Version is the cbx semantic version (e.g. "v1.2.3"), "dev" for
	// local builds.
	Version = "dev"
	// Commit is the git commit the binary was built from.
	Commit = "unknown"
	// Date is the build timestamp.
	Date = "unknown"
)

var (
	jsonFlag     bool
	quietFlag    bool
	noColorFlag  bool
	outputFormat string
)

// executedCommand tracks which subcommand was run (used by background update check).
var executedCommand string

// NewRootCmd builds the root cobra command with every cbx subcommand,
// persistent flag, and the telemetry/output PersistentPreRunE wiring
// attached. The cbx binary reaches it through Execute; it is exported so
// downstream consumers embedding the CLI can mount the command tree (or
// individual subcommands) inside their own cobra root.
// Help-group IDs for the root command (see AddGroup in NewRootCmd).
const (
	groupCore    = "core"
	groupAccount = "account"
	groupSetup   = "setup"
	groupMaint   = "maintenance"
)

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "cbx <command>",
		Short: "CloudBooster CLI — audit and manage cloud infrastructure",
		Long: `cbx is the CloudBooster CLI for auditing existing cloud deployments
and interacting with the CloudBooster platform.

Run cbx --help for the command list, cbx <cmd> --help for any subcommand, or cbx doctor to check your setup.`,
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			output.Configure(noColorFlag, quietFlag)

			// --json is a hidden back-compat alias for `-o json`. If the
			// user passed both, the explicit --output value wins.
			if jsonFlag && outputFormat == "" {
				outputFormat = "json"
			}
			// Validate format value. "" (human-readable default) and
			// "json" are supported today; yaml/table are reserved and
			// return a structured error so the flag surface signals
			// intent without lying about coverage.
			switch outputFormat {
			case "", "json":
				// ok
			case "yaml", "table":
				return output.NewError(output.ErrorDetail{
					What: fmt.Sprintf("output format %q is not yet supported", outputFormat),
					Why:  "only json (and the human-readable default) are implemented today",
					Fix:  "pass --output json or omit the flag for human-readable output",
					Code: "E_UNSUPPORTED_FORMAT",
				})
			default:
				return output.NewError(output.ErrorDetail{
					What: fmt.Sprintf("output format %q is not recognized", outputFormat),
					Why:  "supported formats: json (and the human-readable default)",
					Fix:  "pass --output json or omit the flag for human-readable output",
					Code: "E_UNSUPPORTED_FORMAT",
				})
			}
			output.SetFormat(outputFormat)

			executedCommand = cmd.Name()

			// First-run telemetry prompt, then Sentry init. Skip for
			// commands that manage telemetry themselves (no recursive
			// prompting), the help/version exits (low-cost, low-signal),
			// and machine-output modes (JSON/quiet — prompt would
			// corrupt the stream).
			if !skipTelemetryPrompt(cmd) {
				telemetry.MaybePromptFirstRun(os.Stdin, os.Stderr, output.JSON() || quietFlag)
			}
			telemetry.Init(Version, Commit)
			telemetry.SetTag("command", cmd.CommandPath())
			return nil
		},
	}

	root.PersistentFlags().StringVarP(&outputFormat, "output", "o", "", "Output format: json (default: human)")
	root.PersistentFlags().BoolVar(&jsonFlag, "json", false, "Output in JSON format (alias for --output json)")
	_ = root.PersistentFlags().MarkHidden("json")
	root.PersistentFlags().BoolVarP(&quietFlag, "quiet", "q", false, "Suppress non-error output")
	root.PersistentFlags().BoolVar(&noColorFlag, "no-color", false, "Disable colored output")

	// Unify `cbx --version` / `cbx -v` with the longer `cbx version`
	// output. Without this, cobra's default emits just `cbx version <ver>`.
	root.SetVersionTemplate(fmt.Sprintf("cbx version %s (commit: %s, built: %s)\n", Version, Commit, Date))

	output.InstallHelpTemplate(root)

	// Grouped help: the product verbs first, then account, then setup,
	// then maintenance plumbing. Hidden commands and anything without a
	// GroupID fall under "Additional commands".
	root.AddGroup(
		&cobra.Group{ID: groupCore, Title: "Core commands"},
		&cobra.Group{ID: groupAccount, Title: "Account"},
		&cobra.Group{ID: groupSetup, Title: "Setup & configuration"},
		&cobra.Group{ID: groupMaint, Title: "Maintenance"},
	)

	withGroup := func(g string, cmds ...*cobra.Command) {
		for _, c := range cmds {
			c.GroupID = g
			root.AddCommand(c)
		}
	}
	withGroup(groupCore, newAuditCmd())
	withGroup(groupAccount, newLoginCmd(), newLogoutCmd(), newStatusCmd(), newAuthCmd())
	withGroup(groupSetup, newLLMCmd(), newConfigCmd(), newTelemetryCmd())
	withGroup(groupMaint, newDoctorCmd(), newUpgradeCmd(), newVersionCmd())
	root.AddCommand(newKnowledgeCmd(), newEnvCmd())
	root.SetHelpCommandGroupID(groupMaint)
	root.SetCompletionCommandGroupID(groupMaint)

	return root
}

// skipTelemetryPrompt is true for commands where showing the first-run
// prompt would be disruptive or recursive (telemetry subcommands manage
// the prompt themselves; version/help are zero-friction quick exits).
func skipTelemetryPrompt(cmd *cobra.Command) bool {
	for c := cmd; c != nil; c = c.Parent() {
		switch c.Name() {
		case "telemetry", "version", "help", "completion":
			return true
		}
	}
	return false
}
