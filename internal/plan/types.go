package plan

import "time"

// Component represents a single infrastructure component.
type Component struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Service     string `json:"service"`
}

// Plan represents an architecture plan.
type Plan struct {
	Intent         string      `json:"intent"`
	Components     []Component `json:"components"`
	Version        int         `json:"version"`
	ADRContent     string      `json:"-"`
	D2Content      string      `json:"-"`
	MermaidContent string      `json:"-"`
	HTMLContent    string      `json:"-"`
}

// Turn represents a single interaction turn.
type Turn struct {
	Timestamp time.Time `json:"timestamp"`
	Input     string    `json:"input"`
	IsRefine  bool      `json:"is_refine"`
	Plan      *Plan     `json:"plan"`
}

// Session tracks the multi-turn planning session.
type Session struct {
	History        []Turn
	CurrentPlan    *Plan
	ActiveProvider string
	DiagramFormat  string // "d2" or "mermaid"
	Unsaved        bool
	PendingQuit    bool
	OutputDir      string
}

// NewSession creates a new planning session.
func NewSession(outputDir string) *Session {
	return &Session{
		History:       make([]Turn, 0),
		DiagramFormat: "mermaid",
		OutputDir:     outputDir,
	}
}

// SetPlan updates the current plan and marks the session as having unsaved changes.
func (s *Session) SetPlan(plan *Plan) {
	s.CurrentPlan = plan
	s.Unsaved = true
}

// AppendTurn adds a turn to the history.
func (s *Session) AppendTurn(input string, isRefine bool, plan *Plan) {
	s.History = append(s.History, Turn{
		Timestamp: time.Now(),
		Input:     input,
		IsRefine:  isRefine,
		Plan:      plan,
	})
}

// MarkSaved clears the unsaved flag.
func (s *Session) MarkSaved() {
	s.Unsaved = false
}
