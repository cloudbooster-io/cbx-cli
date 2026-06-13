package audit

import "github.com/charmbracelet/bubbles/key"

// KeyMap defines the key bindings for the audit TUI.
type KeyMap struct {
	Up       key.Binding
	Down     key.Binding
	Top      key.Binding
	Bottom   key.Binding
	PageUp   key.Binding
	PageDown key.Binding
	Tab      key.Binding
	Enter    key.Binding
	Back     key.Binding
	Filter   key.Binding
	CycleSev key.Binding
	CycleSvc key.Binding
	Reset    key.Binding
	Open     key.Binding
	Help     key.Binding
	Quit     key.Binding
}

// DefaultKeyMap returns the default key bindings.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Up:       key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
		Down:     key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
		Top:      key.NewBinding(key.WithKeys("g", "home"), key.WithHelp("g", "top")),
		Bottom:   key.NewBinding(key.WithKeys("G", "end"), key.WithHelp("G", "bottom")),
		PageUp:   key.NewBinding(key.WithKeys("pgup", "ctrl+u"), key.WithHelp("pgup", "page up")),
		PageDown: key.NewBinding(key.WithKeys("pgdown", "ctrl+d"), key.WithHelp("pgdn", "page down")),
		Tab:      key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "toggle pane")),
		Enter:    key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "open detail")),
		Back:     key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back")),
		Filter:   key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "search")),
		CycleSev: key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "severity")),
		CycleSvc: key.NewBinding(key.WithKeys("v"), key.WithHelp("v", "service")),
		Reset:    key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "reset")),
		Open:     key.NewBinding(key.WithKeys("o"), key.WithHelp("o", "open report")),
		Help:     key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
		Quit:     key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	}
}
