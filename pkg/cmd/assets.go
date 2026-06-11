package cmd

import (
	_ "embed"
)

//go:embed assets/plan.tmpl.html
var planTemplate string
