package cmd

import (
	_ "embed"
)

//go:embed assets/plan.tmpl.html
var planTemplate string

//go:embed assets/mermaid.min.js.gz
var mermaidJSGz []byte
