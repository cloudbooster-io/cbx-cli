package cmd

import (
	"fmt"

	"github.com/cloudbooster-io/cbx-cli/internal/config"
	"github.com/cloudbooster-io/cbx-cli/internal/output"
)

// init wires the config-package notices through the shared output writer.
// The legacy-config-dir nudge goes into the advisory buffer so the run
// finishes with a clean advisories card instead of a leading
// "notice: ..." line above everything else.
func init() {
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
