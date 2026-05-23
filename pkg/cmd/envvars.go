package cmd

import (
	"fmt"
	"os"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/output"
)

// init wires the config-package deprecation warnings to go through the
// shared output writer, so they respect --quiet and don't get tangled
// up with JSON output. The default sink in internal/config writes to
// stderr directly; here we replace it with one that does the same but
// is silent in --quiet and JSON modes.
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
		fmt.Fprintf(os.Stderr,
			"notice: using legacy config dir %s; consider moving it to %s (XDG-compliant)\n",
			legacy, modern)
	}
}
