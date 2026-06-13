package output

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Progress renders a bounded progress bar.
type Progress struct {
	width     int
	writer    io.Writer
	start     time.Time
	fillRune  rune
	emptyRune rune
	nowFn     func() time.Time
}

// NewProgress creates a Progress that writes to stderr.
func NewProgress() *Progress {
	return &Progress{
		width:     40,
		writer:    os.Stderr,
		fillRune:  '█',
		emptyRune: '░',
		start:     time.Now(),
		nowFn:     time.Now,
	}
}

// SetWriter changes the output writer (useful for tests).
func (p *Progress) SetWriter(w io.Writer) {
	p.writer = w
}

// SetWidth changes the bar width in characters.
func (p *Progress) SetWidth(w int) {
	p.width = w
}

// SetStartTime sets the baseline for ETA calculation (useful for tests).
func (p *Progress) SetStartTime(t time.Time) {
	p.start = t
}

// Render returns the progress bar string for the given current/total.
func (p *Progress) Render(current, total int64) string {
	if total <= 0 {
		total = 1
	}
	pct := float64(current) / float64(total)
	if pct > 1 {
		pct = 1
	}
	percent := pct * 100

	if !Enabled() {
		return fmt.Sprintf("%.0f%%", percent)
	}

	filled := int(pct * float64(p.width))
	if filled > p.width {
		filled = p.width
	}
	empty := p.width - filled

	bar := strings.Repeat(string(p.fillRune), filled) + strings.Repeat(string(p.emptyRune), empty)

	// ETA calculation.
	etaStr := "--:--"
	if current > 0 && current < total {
		now := p.nowFn()
		elapsed := now.Sub(p.start)
		totalDur := time.Duration(float64(elapsed) / pct)
		remaining := totalDur - elapsed
		etaStr = fmt.Sprintf("%02d:%02d", int(remaining.Minutes()), int(remaining.Seconds())%60)
	} else if current >= total {
		etaStr = "00:00"
	}

	return fmt.Sprintf("%s %5.1f%% [%s]", bar, percent, etaStr)
}

// Print writes the rendered bar to the configured writer followed by a carriage
// return so the next call overwrites it.
func (p *Progress) Print(current, total int64) {
	if !Enabled() {
		_, _ = fmt.Fprintf(p.writer, "\r%s", p.Render(current, total))
		return
	}
	_, _ = fmt.Fprintf(p.writer, "\r%s", p.Render(current, total))
}

// Finish writes a final line and moves to the next line.
func (p *Progress) Finish(current, total int64) {
	_, _ = fmt.Fprintln(p.writer, p.Render(current, total))
}
