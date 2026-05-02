package chat

import (
	"io"
	"os"
)

// IsTUIAvailable reports whether a Bubble Tea TUI can be started for the
// given input reader. It returns false when the --no-tui flag is set, the
// terminal type is "dumb", or the input is not a character device (TTY).
func IsTUIAvailable(in io.Reader, noTUIFlag bool) bool {
	if noTUIFlag {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := in.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice == os.ModeCharDevice
}
