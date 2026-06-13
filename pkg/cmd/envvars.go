package cmd

import (
	"fmt"
	"os"

	"github.com/cloudbooster-io/cbx-cli/internal/config"
	"github.com/cloudbooster-io/cbx-cli/internal/output"
)

// init wires the config-package notices through the shared output writer.
// The deprecation warning still streams to stderr (it's environment-level
// and useful to see early). The legacy-config-dir nudge moves into the
// advisory buffer so the run finishes with a clean advisories card
// instead of a leading "notice: ..." line above everything else.
func init() {
	config.DeprecatedEnvWarn = func(oldName, newName string) {
		if output.IsQuiet() || output.JSON() {
			return
		}
		fmt.Fprintf(os.Stderr,
			"warning: %s is deprecated, use %s instead (will be removed in a future release)\n",
			oldName, newName)
	}
	config.LegacyConfigNudge = func(legacy, modern string) {
		if output.IsQuiet() || output.JSON() {
			return
		}
		output.Advise(output.Advisory{
			Code:  "legacy-config-dir",
			Title: fmt.Sprintf("using legacy config dir %s", legacy),
			Hint:  fmt.Sprintf("mv %s %s", legacy, modern),
		})
	}
}
