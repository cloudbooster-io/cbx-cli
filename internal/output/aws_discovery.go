package output

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// AWSDiscoveryUI renders a live multi-line progress display for the
// `cbx audit aws` discovery phase. It animates a spinner, a progress
// bar, the most-recently-completed (region, type) hit, and a running
// resource counter, all on stderr.
//
// Modes:
//   - When styled output is disabled (non-TTY, --no-color, NO_COLOR,
//     --quiet), no animation is emitted — each Update call prints a
//     plain single-line status the first time per-second and on Done,
//     so non-interactive runs still get *something*.
//   - When styled output is enabled, four lines are redrawn in place
//     using ANSI cursor controls. Done() clears the display so the
//     caller can print the final summary.
//
// Concurrency: Update is safe to call from any goroutine; the renderer
// goroutine owns the writer. Start before the first Update, Done at
// the very end.
type AWSDiscoveryUI struct {
	writer io.Writer

	mu sync.Mutex

	// state read by the renderer
	phase      string
	identity   string
	regions    []string
	lastRegion string
	lastType   string
	lastFound  int
	jobsDone   int
	jobsTotal  int
	resources  int
	dirty      bool

	// scout-phase state. scoutTotal == 0 means no scout is running.
	scoutTotal   int
	scoutDone    int
	scoutResults map[string]int // region -> count, ordered separately
	scoutOrder   []string       // insertion-ordered region list
	scoutActive  []string       // narrowed list after scout
	scoutPhase   bool           // currently in scout phase

	// in-flight enrichment state — the most recent EnrichProgress
	// event. Cleared on the next JobDone for this (region,type).
	enrichRegion string
	enrichType   string
	enrichDone   int
	enrichTotal  int
	enrichSeen   time.Time

	// in-flight job tracking — keyed by "region|type", value is the
	// wall-clock start time. Updated by JobStart, removed by JobDone.
	// Lets the UI render which jobs are currently running so hung work
	// stops hiding behind a stalled progress bar.
	inFlight map[string]time.Time

	startTime time.Time
	spinIdx   int

	stop    chan struct{}
	stopped bool
	wg      sync.WaitGroup

	// number of lines we drew in the previous render; used to scroll the
	// cursor up before redrawing.
	prevLines int

	// timestamp of the last non-styled status line, used by
	// maybeNonStyledLine to throttle to ~1 line/sec. Guarded by mu.
	lastInlinePrint time.Time
}

// NewAWSDiscoveryUI constructs a display that writes to stderr.
func NewAWSDiscoveryUI() *AWSDiscoveryUI {
	return &AWSDiscoveryUI{
		writer:       os.Stderr,
		startTime:    time.Now(),
		phase:        "starting",
		stop:         make(chan struct{}),
		scoutResults: map[string]int{},
		inFlight:     map[string]time.Time{},
	}
}

// JobStart records the start of a discovery job so the UI can render
// the in-flight set with wall-clock durations.
func (u *AWSDiscoveryUI) JobStart(region, cfnType string) {
	key := region + "|" + cfnType
	u.mu.Lock()
	u.inFlight[key] = time.Now()
	u.dirty = true
	u.mu.Unlock()
}

// ScoutStart records the start of the scout phase. Causes the live
// render to switch into a per-region grid until ScoutDone is called.
func (u *AWSDiscoveryUI) ScoutStart(total int) {
	u.mu.Lock()
	u.scoutPhase = true
	u.scoutTotal = total
	u.scoutDone = 0
	u.dirty = true
	u.mu.Unlock()
	u.maybeNonStyledLine()
}

// ScoutRegionDone records a probed region's resource count.
func (u *AWSDiscoveryUI) ScoutRegionDone(region string, count, done, total int) {
	u.mu.Lock()
	if _, seen := u.scoutResults[region]; !seen {
		u.scoutOrder = append(u.scoutOrder, region)
	}
	u.scoutResults[region] = count
	u.scoutDone = done
	if total > u.scoutTotal {
		u.scoutTotal = total
	}
	u.dirty = true
	u.mu.Unlock()
	u.maybeNonStyledLine()
}

// ScoutDone records the narrowed active-region list and exits the
// scout phase.
func (u *AWSDiscoveryUI) ScoutDone(active []string) {
	u.mu.Lock()
	u.scoutActive = append([]string(nil), active...)
	u.scoutPhase = false
	u.dirty = true
	u.mu.Unlock()
}

// Start begins the animation loop. On non-styled output it's a no-op
// (Update prints inline updates instead). Safe to call once.
func (u *AWSDiscoveryUI) Start() {
	if !Enabled() {
		return
	}
	u.wg.Add(1)
	go u.loop()
}

// Done stops the animation, clears the in-place display (when styled),
// and returns. Safe to call multiple times.
func (u *AWSDiscoveryUI) Done() {
	u.mu.Lock()
	if u.stopped {
		u.mu.Unlock()
		return
	}
	u.stopped = true
	close(u.stop)
	u.mu.Unlock()
	u.wg.Wait()
	if Enabled() {
		u.mu.Lock()
		u.clearLines(u.prevLines)
		u.prevLines = 0
		u.mu.Unlock()
	}
}

// SetPhase updates the headline phase label (e.g. "preflight",
// "resolving regions", "discovering"). Triggers a redraw on the next
// tick.
func (u *AWSDiscoveryUI) SetPhase(label string) {
	u.mu.Lock()
	u.phase = label
	u.dirty = true
	u.mu.Unlock()
	u.maybeNonStyledLine()
}

// SetIdentity records the caller ARN for the header line.
func (u *AWSDiscoveryUI) SetIdentity(arn string) {
	u.mu.Lock()
	u.identity = arn
	u.dirty = true
	u.mu.Unlock()
}

// SetRegions records the resolved region list.
func (u *AWSDiscoveryUI) SetRegions(regs []string) {
	u.mu.Lock()
	u.regions = append([]string(nil), regs...)
	u.dirty = true
	u.mu.Unlock()
}

// SetTotalJobs records the total number of (region × type) jobs.
func (u *AWSDiscoveryUI) SetTotalJobs(total int) {
	u.mu.Lock()
	u.jobsTotal = total
	u.dirty = true
	u.mu.Unlock()
}

// JobDone is called as each discovery job completes.
func (u *AWSDiscoveryUI) JobDone(region, cfnType string, found, done, total int) {
	u.mu.Lock()
	u.lastRegion = region
	u.lastType = cfnType
	u.lastFound = found
	u.jobsDone = done
	if total > u.jobsTotal {
		u.jobsTotal = total
	}
	u.resources += found
	delete(u.inFlight, region+"|"+cfnType)
	// Clear the in-flight line if this JobDone closes out the
	// currently-enriching job. Otherwise leave it (another worker is
	// still mid-enrichment on a different job).
	if region == u.enrichRegion && cfnType == u.enrichType {
		u.enrichRegion = ""
		u.enrichType = ""
		u.enrichDone = 0
		u.enrichTotal = 0
	}
	u.dirty = true
	u.mu.Unlock()
	u.maybeNonStyledLine()
}

// EnrichProgress records the per-resource enrichment progress for an
// in-flight job. Used to display "enriching N/total" so the user
// doesn't think a slow describer (S3, IAM) has hung.
func (u *AWSDiscoveryUI) EnrichProgress(region, cfnType string, done, total int) {
	u.mu.Lock()
	u.enrichRegion = region
	u.enrichType = cfnType
	u.enrichDone = done
	u.enrichTotal = total
	u.enrichSeen = time.Now()
	u.dirty = true
	u.mu.Unlock()
}

// loop is the renderer goroutine: ticks ~10× per second and redraws
// when state has changed since the last tick.
func (u *AWSDiscoveryUI) loop() {
	defer u.wg.Done()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-u.stop:
			return
		case <-ticker.C:
			u.mu.Lock()
			u.spinIdx++
			u.render()
			u.mu.Unlock()
		}
	}
}

// render writes the live display. Must be called with mu held. The
// shape depends on the phase: scout shows a per-region grid; deep
// discovery shows the spinner + bar + last-hit layout.
func (u *AWSDiscoveryUI) render() {
	if u.scoutPhase {
		u.renderScout()
		return
	}
	u.renderDiscover()
}

// renderDiscover draws the deep-scan multi-line display.
func (u *AWSDiscoveryUI) renderDiscover() {
	frame := defaultFrames[u.spinIdx%len(defaultFrames)]

	bar := renderBar(u.jobsDone, u.jobsTotal, 28)
	eta := renderETA(u.startTime, u.jobsDone, u.jobsTotal)

	headline := fmt.Sprintf("%s %s %s", Info.Render(frame), phaseChip(u.phase), Dim.Render(u.phase))
	if u.identity != "" {
		headline += "  " + Dim.Render("· "+shortARN(u.identity))
	}

	lastLine := "  " + Dim.Render("waiting for first result...")
	if u.lastType != "" {
		region := u.lastRegion
		if region == "" {
			region = "global"
		}
		lastLine = fmt.Sprintf("  %s %s %s %s",
			Success.Render(Symbol("check")),
			Dim.Render(fmt.Sprintf("%-15s", region)),
			u.lastType,
			Dim.Render(fmt.Sprintf("(%d)", u.lastFound)),
		)
	}

	barLine := fmt.Sprintf("  %s  %s  %s  %s",
		bar,
		Info.Render(fmt.Sprintf("%d/%d jobs", u.jobsDone, max1(u.jobsTotal))),
		Success.Render(fmt.Sprintf("%d resources", u.resources)),
		Dim.Render("ETA "+eta),
	)

	regionsLine := ""
	if len(u.regions) > 0 {
		shown := u.regions
		if len(u.scoutActive) > 0 {
			shown = u.scoutActive
		}
		regionsLine = "  " + Dim.Render("regions: "+strings.Join(shown, ", "))
	}

	lines := []string{headline, lastLine, barLine}

	// In-flight jobs — one row per currently-running (region, type)
	// with its elapsed wall-clock. Anything running >30s gets a warn
	// colour so hung work jumps out. Sorted longest-running first so
	// the most-likely-hung row is on top.
	if len(u.inFlight) > 0 {
		now := time.Now()
		type kv struct {
			region, cfnType string
			elapsed         time.Duration
		}
		rows := make([]kv, 0, len(u.inFlight))
		for k, start := range u.inFlight {
			region, cfnType := splitInFlightKey(k)
			rows = append(rows, kv{region: region, cfnType: cfnType, elapsed: now.Sub(start)})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].elapsed > rows[j].elapsed })
		for i, row := range rows {
			// Cap to a handful of rows so the display doesn't explode.
			if i >= 4 {
				lines = append(lines, "  "+Dim.Render(fmt.Sprintf("… and %d more", len(rows)-i)))
				break
			}
			region := row.region
			if region == "" {
				region = "global"
			}
			elapsedStr := fmtElapsed(row.elapsed)
			elapsedStyled := Dim.Render(elapsedStr)
			if row.elapsed > 30*time.Second {
				elapsedStyled = Warning.Render(elapsedStr)
			}
			line := fmt.Sprintf("  %s %s %s %s",
				Info.Render(frame),
				Dim.Render(fmt.Sprintf("%-15s", region)),
				fmt.Sprintf("%-44s", row.cfnType),
				elapsedStyled,
			)
			// Append in-job enrichment progress when this row matches
			// the most-recent EnrichProgress event.
			if row.region == u.enrichRegion && row.cfnType == u.enrichType && u.enrichTotal > 0 && time.Since(u.enrichSeen) < 1500*time.Millisecond {
				line += "  " + Info.Render(fmt.Sprintf("enriching %d/%d", u.enrichDone, u.enrichTotal))
			}
			lines = append(lines, line)
		}
	}

	if regionsLine != "" {
		lines = append(lines, regionsLine)
	}

	u.clearLines(u.prevLines)
	for _, ln := range lines {
		_, _ = fmt.Fprintln(u.writer, ln)
	}
	u.prevLines = len(lines)
	u.dirty = false
}

// renderScout draws the per-region scout display: a heading line plus
// a grid of regions with each one's probe-resource count. Regions that
// haven't reported yet show a spinner; finished ones show ✓ + count or
// "—" for empty.
func (u *AWSDiscoveryUI) renderScout() {
	frame := defaultFrames[u.spinIdx%len(defaultFrames)]

	headline := fmt.Sprintf("%s %s  %s  %s",
		Info.Render(frame),
		phaseChip("scout"),
		Dim.Render(fmt.Sprintf("scouting %d regions for activity", u.scoutTotal)),
		Dim.Render(fmt.Sprintf("(%d/%d)", u.scoutDone, max1(u.scoutTotal))),
	)
	if u.identity != "" {
		headline += "  " + Dim.Render("· "+shortARN(u.identity))
	}

	// Build a fixed-width grid: 3 columns × N rows. Stable order based
	// on whichever regions have been observed so far (insertion).
	lines := []string{headline}
	const cols = 3
	cells := make([]string, 0, len(u.scoutOrder))
	for _, r := range u.scoutOrder {
		count := u.scoutResults[r]
		marker := Success.Render(Symbol("check"))
		label := fmt.Sprintf("%d", count)
		if count == 0 {
			marker = Dim.Render(Symbol("bullet"))
			label = Dim.Render("—")
		}
		cells = append(cells, fmt.Sprintf("%s %-15s %s", marker, r, label))
	}
	// Pending regions (in-flight) — show a spinner row at the tail of
	// what we've already drawn. Cap to keep the grid bounded.
	pending := u.scoutTotal - len(u.scoutOrder)
	for i := 0; i < pending && i < 6; i++ {
		cells = append(cells, fmt.Sprintf("%s %-15s %s", Dim.Render(frame), "…probing", ""))
	}
	for i := 0; i < len(cells); i += cols {
		end := i + cols
		if end > len(cells) {
			end = len(cells)
		}
		row := "  " + strings.Join(padCells(cells[i:end], 26), " ")
		lines = append(lines, row)
	}

	u.clearLines(u.prevLines)
	for _, ln := range lines {
		_, _ = fmt.Fprintln(u.writer, ln)
	}
	u.prevLines = len(lines)
	u.dirty = false
}

// padCells right-pads each visible cell to width chars so columns line
// up regardless of label length. Uses visible-width (ANSI stripped is
// fine for our short labels — the styled glyphs are 1-char wide).
func padCells(cells []string, width int) []string {
	out := make([]string, len(cells))
	for i, c := range cells {
		visible := stripANSI(c)
		if len(visible) >= width {
			out[i] = c
			continue
		}
		out[i] = c + strings.Repeat(" ", width-len(visible))
	}
	return out
}

// stripANSI removes ANSI escape sequences from s so length-based
// padding lines columns up correctly. Minimal regexp-free
// implementation — handles the CSI sequences lipgloss emits.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			// skip CSI ... letter
			i += 2
			for i < len(s) && (s[i] < 0x40 || s[i] > 0x7e) {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// clearLines moves the cursor up n lines and clears each one in place.
// No-op when n == 0.
func (u *AWSDiscoveryUI) clearLines(n int) {
	if n <= 0 {
		return
	}
	for i := 0; i < n; i++ {
		_, _ = fmt.Fprint(u.writer, "\033[1A\033[2K")
	}
	_, _ = fmt.Fprint(u.writer, "\r")
}

// maybeNonStyledLine emits a single-line status update to stderr in
// non-styled mode (no TTY / quiet / no-color). Keeps non-interactive
// users informed without ANSI escapes. Throttled to ~1 line/sec.
func (u *AWSDiscoveryUI) maybeNonStyledLine() {
	if Enabled() {
		return
	}
	u.mu.Lock()
	now := time.Now()
	if !u.lastInlinePrint.IsZero() && now.Sub(u.lastInlinePrint) < time.Second {
		u.mu.Unlock()
		return
	}
	u.lastInlinePrint = now
	line := fmt.Sprintf("[%s] %d/%d jobs · %d resources", u.phase, u.jobsDone, max1(u.jobsTotal), u.resources)
	u.mu.Unlock()
	_, _ = fmt.Fprintln(u.writer, line)
}

// renderBar builds a fixed-width filled/empty bar. Total ≤ 0 renders
// an indeterminate placeholder. Filled segments use the success colour
// so the bar reads as a positive accumulator instead of pure ASCII.
func renderBar(done, total, width int) string {
	if total <= 0 {
		return Dim.Render(strings.Repeat("·", width))
	}
	pct := float64(done) / float64(total)
	if pct > 1 {
		pct = 1
	}
	filled := int(pct * float64(width))
	if filled > width {
		filled = width
	}
	filledSeg := strings.Repeat("▰", filled)
	emptySeg := strings.Repeat("▱", width-filled)
	if Enabled() {
		filledSeg = Success.Render(filledSeg)
		emptySeg = Dim.Render(emptySeg)
	}
	return filledSeg + emptySeg
}

// phaseChip returns a small coloured tag for the named discovery phase.
// Distinct hues let scout / discover / done read at a glance even before
// the user parses the rest of the headline.
func phaseChip(phase string) string {
	switch {
	case strings.Contains(phase, "auth"):
		return Chip("AUTH", chipInfoFG, chipInfoBG)
	case strings.Contains(phase, "scout"):
		return Chip("SCOUT", chipInfoFG, lipgloss.Color("57")) // purple
	case strings.Contains(phase, "region"):
		return Chip("REGIONS", chipInfoFG, chipInfoBG)
	case strings.Contains(phase, "discover"):
		return Chip("DISCOVER", chipInfoFG, lipgloss.Color("25")) // deep blue
	case strings.Contains(phase, "done"):
		return Chip("DONE", chipInfoFG, lipgloss.Color("22")) // green
	default:
		return Chip(strings.ToUpper(phase), chipInfoFG, lipgloss.Color("240"))
	}
}

// renderETA returns a mm:ss string of estimated time remaining, or
// "--:--" when there's not enough signal yet.
func renderETA(start time.Time, done, total int) string {
	if done <= 0 || total <= 0 {
		return "--:--"
	}
	if done >= total {
		return "00:00"
	}
	elapsed := time.Since(start)
	pct := float64(done) / float64(total)
	totalDur := time.Duration(float64(elapsed) / pct)
	remaining := totalDur - elapsed
	if remaining < 0 {
		remaining = 0
	}
	return fmt.Sprintf("%02d:%02d", int(remaining.Minutes()), int(remaining.Seconds())%60)
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// shortARN trims the IAM ARN to the trailing user/role identifier so
// the headline line doesn't get blown out on long ARNs.
func shortARN(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 && i < len(arn)-1 {
		return arn[i+1:]
	}
	return arn
}

// splitInFlightKey reverses the "region|type" key encoding used by
// AWSDiscoveryUI.inFlight back into its parts.
func splitInFlightKey(k string) (region, cfnType string) {
	if i := strings.Index(k, "|"); i >= 0 {
		return k[:i], k[i+1:]
	}
	return "", k
}

// fmtElapsed renders a duration as a short human string suitable for
// the in-flight row: "1.2s" under 60s, "1m12s" otherwise.
func fmtElapsed(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	m := int(d.Minutes())
	s := int(d.Seconds()) - m*60
	return fmt.Sprintf("%dm%02ds", m, s)
}
