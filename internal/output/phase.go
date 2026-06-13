package output

import (
	"fmt"
	"io"
	"os"
)

// PrintPhase writes a numbered phase marker to w (default: stderr).
// It is a no-op when quiet mode is active.
func PrintPhase(w io.Writer, phase, total int, label string) {
	if IsQuiet() {
		return
	}
	if w == nil {
		w = os.Stderr
	}
	_, _ = fmt.Fprintf(w, "%s Phase %d/%d: %s\n", Symbol("phase"), phase, total, label)
}
