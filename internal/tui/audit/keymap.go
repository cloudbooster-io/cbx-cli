package audit

import "github.com/charmbracelet/bubbles/key"

// KeyMap defines the key bindings for the audit TUI.
type KeyMap struct {
	Up       key.Binding
	Down     key.Binding
	PageUp   key.Binding
	PageDown key.Binding
	Enter    key.Binding
	Back     key.Binding
	Quit     key.Binding
	Filter   key.Binding
	CycleSev key.Binding
	CycleSvc key.Binding
	Reset    key.Binding
}

// DefaultKeyMap returns the default key bindings.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Up:       key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
		Down:     key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
		PageUp:   key.NewBinding(key.WithKeys("pgup"), key.WithHelp("pgup", "page up")),
		PageDown: key.NewBinding(key.WithKeys("pgdown"), key.WithHelp("pgdn", "page down")),
		Enter:    key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "drill down")),
		Back:     key.NewBinding(key.WithKeys("esc", "q"), key.WithHelp("esc/q", "back/quit")),
		Quit:     key.NewBinding(key.WithKeys("ctrl+c"), key.WithHelp("ctrl+c", "quit")),
		Filter:   key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "search")),
		CycleSev: key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "severity")),
		CycleSvc: key.NewBinding(key.WithKeys("v"), key.WithHelp("v", "service")),
		Reset:    key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "reset")),
	}
}
