package output

import "github.com/spf13/cobra"

// helpTemplate is the upgraded Cobra help template.
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

{{end}}Learn more: https://docs.cloudbooster.io
`

// InstallHelpTemplate applies the custom help and usage templates to root
// and propagates them to all subcommands.
func InstallHelpTemplate(root *cobra.Command) {
	root.SetHelpTemplate(helpTemplate)
	root.SetUsageTemplate(helpTemplate)
}
