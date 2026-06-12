package output

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

// helpTemplate is the styled Cobra help template. Section headers are
// rendered as small dim rules so they read as visual chapters; command
// names in the Commands block are bold so they stand out from their
// dim short descriptions. Learn-more URL is OSC-8 linked.
const helpTemplate = `{{with .Long}}{{ . | trim }}

{{end}}{{section "Usage"}}
  {{.UseLine}}

{{if .HasExample}}{{section "Examples"}}
{{.Example}}

{{end}}{{if .HasAvailableSubCommands}}{{if .Groups}}{{range $g := .Groups}}{{section $g.Title}}{{range $.Commands}}{{if (and (eq .GroupID $g.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{cmdName (rpad .Name .NamePadding)}} {{dim .Short}}{{end}}{{end}}

{{end}}{{if not .AllChildCommandsHaveGroup}}{{section "Additional commands"}}{{range .Commands}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{cmdName (rpad .Name .NamePadding)}} {{dim .Short}}{{end}}{{end}}

{{end}}{{else}}{{section "Commands"}}{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{cmdName (rpad .Name .NamePadding)}} {{dim .Short}}{{end}}{{end}}

{{end}}{{end}}{{if .HasAvailableLocalFlags}}{{section "Flags"}}
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}

{{end}}{{if .HasAvailableInheritedFlags}}{{section "Global flags"}}
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}

{{end}}{{dim "learn more · "}}{{linkURL (docURL .)}}
`

// docURL converts cmd.CommandPath() into a docs site URL.
//
//	"cbx"           -> https://docs.cloudbooster.io/cli/
//	"cbx audit aws" -> https://docs.cloudbooster.io/cli/cbx/audit/aws/
//
// The mapping mirrors the docs site's URL scheme so each subcommand
// deep-links into its own reference page.
func docURL(cmd *cobra.Command) string {
	path := strings.TrimSpace(cmd.CommandPath())
	if path == "" || path == cmd.Root().Name() {
		return "https://docs.cloudbooster.io/cli/"
	}
	slug := strings.ReplaceAll(strings.ToLower(path), " ", "/")
	return "https://docs.cloudbooster.io/cli/" + slug + "/"
}

// section renders a styled section heading. In styled mode it's bold +
// dim rule below; in plain mode it's the bare label + ":" — close to
// the original template so muscle-memory greps still hit.
func section(name string) string {
	if !Enabled() {
		return name + ":"
	}
	return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).Render(name)
}

// cmdName styles the command name column inside the Commands block.
// Bold + bright in styled mode, identity in plain mode.
func cmdName(name string) string {
	if !Enabled() {
		return name
	}
	return lipgloss.NewStyle().Bold(true).Render(name)
}

// dim applies the standard low-emphasis style. Used for command short
// descriptions and the "learn more" prefix.
func dim(s string) string {
	return Dim.Render(s)
}

// linkURL wraps a URL as an OSC-8 hyperlink in styled mode, otherwise
// returns the raw URL.
func linkURL(url string) string {
	return Hyperlink(url, url)
}

// InstallHelpTemplate applies the custom help and usage templates to root
// and propagates them to all subcommands. Also registers the template
// funcs the template references.
func InstallHelpTemplate(root *cobra.Command) {
	cobra.AddTemplateFunc("docURL", docURL)
	cobra.AddTemplateFunc("section", section)
	cobra.AddTemplateFunc("cmdName", cmdName)
	cobra.AddTemplateFunc("dim", dim)
	cobra.AddTemplateFunc("linkURL", linkURL)
	root.SetHelpTemplate(helpTemplate)
	root.SetUsageTemplate(helpTemplate)
}
