package output

import (
	"strings"

	"github.com/spf13/cobra"
)

// helpTemplate is the upgraded Cobra help template. The Learn more URL
// is derived from cmd.CommandPath() via the docURL template func so each
// subcommand deep-links into the docs site.
const helpTemplate = `{{with .Long}}{{ . | trim }}

{{end}}Usage:
  {{.UseLine}}

{{if .HasExample}}Examples:
{{.Example}}

{{end}}{{if .HasAvailableSubCommands}}Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}

{{end}}{{if .HasAvailableLocalFlags}}Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}

{{end}}{{if .HasAvailableInheritedFlags}}Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}

{{end}}Learn more: {{docURL .}}
`

// docURL converts cmd.CommandPath() into a docs site URL.
//
//   "cbx"           -> https://docs.cloudbooster.io/cli/
//   "cbx audit aws" -> https://docs.cloudbooster.io/cli/cbx/audit/aws/
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

// InstallHelpTemplate applies the custom help and usage templates to root
// and propagates them to all subcommands. Also registers the docURL
// template func so {{docURL .}} resolves.
func InstallHelpTemplate(root *cobra.Command) {
	cobra.AddTemplateFunc("docURL", docURL)
	root.SetHelpTemplate(helpTemplate)
	root.SetUsageTemplate(helpTemplate)
}
