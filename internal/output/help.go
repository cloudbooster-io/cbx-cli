package output

// HelpTemplate returns the Cobra-compatible help template for cbx.
// It renders a gh-style help surface: one-line description, usage,
// available commands, flags, examples, and a "Learn more" link.
func HelpTemplate() string {
	return `{{.Short}}

USAGE
  {{.UseLine}}

{{if .HasAvailableSubCommands}}AVAILABLE COMMANDS{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}

{{end}}{{if .HasAvailableLocalFlags}}FLAGS
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}

{{end}}EXAMPLES
  # Log in to CloudBooster
  $ cbx login

  # Generate an architecture plan
  $ cbx plan "deploy a static site to AWS"

LEARN MORE
  http://docs.cloudbooster.io
`
}

// UsageTemplate returns the Cobra-compatible usage template for cbx.
func UsageTemplate() string {
	return HelpTemplate()
}
