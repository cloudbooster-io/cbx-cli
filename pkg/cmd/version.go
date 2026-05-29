package cmd

import (
	"fmt"
	"runtime"

	"github.com/charmbracelet/lipgloss"
	"github.com/cloudbooster-io/cbx-cli/internal/output"

	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version of cbx",
		Example: `  # Print version info
  cbx version

  # Machine-readable
  cbx version --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if output.JSON() {
				return output.PrintJSON(map[string]string{
					"version": Version,
					"commit":  Commit,
					"date":    Date,
				}, nil)
			}
			fmt.Print(renderVersionCard())
			return nil
		},
	}
}

// renderVersionCard prints the wordmark + version + dim build metadata
// inside the shared card so `cbx version` matches every other surface.
func renderVersionCard() string {
	wordmark := lipgloss.NewStyle().Bold(true).Render("cbx")
	if !output.Enabled() {
		wordmark = "cbx"
	}
	version := output.RawChip(Version, lipgloss.Color("231"), lipgloss.Color("22"))

	card := output.Card{
		Label: output.Chip("CBX", lipgloss.Color("231"), lipgloss.Color("236")),
		Title: "version",
		Rows: []output.CardRow{
			{Key: "build", Value: wordmark + "  " + version},
			{Key: "commit", Value: output.Dim.Render(Commit)},
			{Key: "date", Value: output.Dim.Render(Date)},
			{Key: "runtime", Value: output.Dim.Render(fmt.Sprintf("%s/%s · go %s", runtime.GOOS, runtime.GOARCH, runtime.Version()))},
		},
		Footer: output.Dim.Render("Apache-2.0 · cbx is the open-core CLI for CloudBooster"),
	}
	return card.Render()
}
