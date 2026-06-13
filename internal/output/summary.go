package output

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// HumanSize converts a byte count into a human-readable string.
func HumanSize(bytes int) string {
	if bytes < 1024 {
		return fmt.Sprintf("%dB", bytes)
	}
	if bytes < 1024*1024 {
		return fmt.Sprintf("%.1fKB", float64(bytes)/1024)
	}
	return fmt.Sprintf("%.1fMB", float64(bytes)/(1024*1024))
}

// PrintPlanSummary writes the final plan summary line to w (default: stdout).
// It is a no-op when quiet mode is active.
func PrintPlanSummary(w io.Writer, files []string, totalBytes, componentCount int) {
	if IsQuiet() {
		return
	}
	if w == nil {
		w = os.Stdout
	}
	fileList := strings.Join(files, ", ")
	fmt.Fprintf(w, "Wrote %s (%s, %d components)\n", fileList, HumanSize(totalBytes), componentCount)
}
