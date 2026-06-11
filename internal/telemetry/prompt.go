package telemetry

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/mattn/go-isatty"

	"github.com/cloudbooster-io/cbx-cli/internal/config"
)

// MaybePromptFirstRun shows the opt-in prompt to the user if and only if:
//   - they haven't been prompted before (config.Telemetry.Prompted == false)
//   - they haven't already pinned the choice via env var
//   - both stdin and stdout are real TTYs
//   - the caller hasn't set --json / --quiet (passed in via showOK)
//
// On answer the config is updated and saved. Returns true iff the user
// opted in (so the caller can immediately Init telemetry without waiting
// for the next invocation).
func MaybePromptFirstRun(in io.Reader, out io.Writer, machineOutput bool) bool {
	// Env vars short-circuit the prompt entirely — the user has already
	// made their choice in a more durable place.
	if v := os.Getenv("CBX_TELEMETRY"); v != "" {
		return false
	}
	if os.Getenv("DO_NOT_TRACK") == "1" {
		return false
	}
	if os.Getenv("CI") == "true" {
		return false
	}
	// Suppress in machine-readable / scripted contexts — a prompt landing
	// on stdout would corrupt JSON parsing downstream.
	if machineOutput {
		return false
	}

	cfg, err := config.Load()
	if err != nil {
		return false
	}
	if cfg.Telemetry.Prompted {
		return false
	}

	if !isTerminal(in) || !isTerminal(out) {
		return false
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, "─────────────────────────────────────────────────────────────")
	fmt.Fprintln(out, " Help improve cbx?")
	fmt.Fprintln(out, "─────────────────────────────────────────────────────────────")
	fmt.Fprintln(out)
	fmt.Fprintln(out, " cbx can send anonymous error reports and usage metrics to")
	fmt.Fprintln(out, " CloudBooster's Sentry instance.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "   • Error reports — crash traces and error messages.")
	fmt.Fprintln(out, "     Scrubbed for API keys, file paths, AWS account IDs.")
	fmt.Fprintln(out, "   • Usage metrics — command name, duration, success/failure.")
	fmt.Fprintln(out, "     No flag values, no arguments, no environment data.")
	fmt.Fprintln(out)
	fmt.Fprintln(out, " You can change this anytime:")
	fmt.Fprintln(out, "   cbx telemetry enable    cbx telemetry disable")
	fmt.Fprintln(out)
	fmt.Fprint(out, " Enable telemetry? [y/N] ")

	reader := bufio.NewReader(in)
	line, _ := reader.ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	enabled := answer == "y" || answer == "yes"

	cfg.Telemetry.Enabled = enabled
	cfg.Telemetry.Prompted = true
	cfg.Telemetry.PromptedAt = time.Now().UTC().Format(time.RFC3339)
	_ = config.Save(cfg)

	fmt.Fprintln(out)
	if enabled {
		fmt.Fprintln(out, " ✓ Telemetry enabled. Thanks!")
	} else {
		fmt.Fprintln(out, " ✓ Telemetry disabled.")
	}
	fmt.Fprintln(out, "─────────────────────────────────────────────────────────────")
	fmt.Fprintln(out)

	return enabled
}

// isTerminal returns true only for *os.File handles that are real TTYs.
// io.Reader/io.Writer wrappers always fail this check so tests that pass
// bytes.Buffer never trigger the prompt accidentally.
func isTerminal(rw any) bool {
	f, ok := rw.(*os.File)
	if !ok {
		return false
	}
	return isatty.IsTerminal(f.Fd())
}
