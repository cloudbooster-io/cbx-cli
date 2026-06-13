package output

import (
	"sort"
	"sync"
)

// Advisory is a single user-actionable notice captured during a run.
// Title is the headline (e.g. "using legacy config dir"); Hint is the
// one-command fix (e.g. "mv ~/.cbx ~/.config/cbx"). Code is an optional
// stable identifier so callers can deduplicate.
type Advisory struct {
	Code  string
	Title string
	Hint  string
}

var (
	advMu      sync.Mutex
	advisories []Advisory
	advSeen    = map[string]struct{}{}
)

// Advise records an advisory to be rendered in the end-of-run block.
// Repeated calls with the same Code are deduplicated. Safe to call from
// any goroutine and at any point in the startup/run lifecycle.
func Advise(a Advisory) {
	advMu.Lock()
	defer advMu.Unlock()
	if a.Code != "" {
		if _, ok := advSeen[a.Code]; ok {
			return
		}
		advSeen[a.Code] = struct{}{}
	}
	advisories = append(advisories, a)
}

// AdviseTitle is the no-hint shorthand for callers that only want to surface
// a one-line notice without a follow-up command.
func AdviseTitle(code, title string) {
	Advise(Advisory{Code: code, Title: title})
}

// Advisories returns a copy of the buffered notices, sorted by their order
// of arrival. Tests use this to assert without depending on render output.
func Advisories() []Advisory {
	advMu.Lock()
	defer advMu.Unlock()
	out := make([]Advisory, len(advisories))
	copy(out, advisories)
	return out
}

// ResetAdvisories clears the buffer. Tests call this between runs.
func ResetAdvisories() {
	advMu.Lock()
	defer advMu.Unlock()
	advisories = nil
	advSeen = map[string]struct{}{}
}

// FlushAdvisories renders the buffered advisories and clears the buffer.
// Use this from end-of-run hooks that want to ensure each notice is
// shown exactly once. Returns "" when nothing is buffered.
func FlushAdvisories() string {
	rendered := RenderAdvisories()
	ResetAdvisories()
	return rendered
}

// RenderAdvisories produces the end-of-run advisories block as a string.
// Returns "" when no advisories have been recorded. The block is a Card
// with a dim 'notice' label per row, plus a hint sub-line where present.
func RenderAdvisories() string {
	advMu.Lock()
	list := make([]Advisory, len(advisories))
	copy(list, advisories)
	advMu.Unlock()

	if len(list) == 0 {
		return ""
	}

	// Stable order: keep arrival order but coalesce equal Code+Title pairs.
	seen := map[string]struct{}{}
	uniq := list[:0]
	for _, a := range list {
		k := a.Code + "|" + a.Title
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		uniq = append(uniq, a)
	}
	sort.SliceStable(uniq, func(i, j int) bool {
		// keep input order — SliceStable preserves equal-cmp positions,
		// so a constant comparator is the easiest "no reorder".
		return false
	})

	c := Card{Title: "Advisories"}
	for _, a := range uniq {
		c.AddRow("notice", a.Title)
		if a.Hint != "" {
			c.Rows = append(c.Rows, CardRow{Key: "", Value: "  " + Dim.Render("→ "+a.Hint)})
		}
	}
	return c.Render()
}
