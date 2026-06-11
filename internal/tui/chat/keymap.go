package chat

import "github.com/charmbracelet/bubbles/key"

// KeyMap defines the key bindings for the chat TUI.
type KeyMap struct {
	Submit       key.Binding
	NewLine      key.Binding
	Cancel       key.Binding
	Quit         key.Binding
	HistoryPrev  key.Binding
	HistoryNext  key.Binding
	PageUp       key.Binding
	PageDown     key.Binding
	Palette      key.Binding
	PaletteClose key.Binding
}

// DefaultKeyMap returns the default key bindings.
func DefaultKeyMap() KeyMap {
	return KeyMap{
		Submit:       key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "submit")),
		NewLine:      key.NewBinding(key.WithKeys("shift+enter", "alt+enter"), key.WithHelp("shift+enter", "newline")),
		Cancel:       key.NewBinding(key.WithKeys("ctrl+c"), key.WithHelp("ctrl+c", "cancel")),
		Quit:         key.NewBinding(key.WithKeys("ctrl+d"), key.WithHelp("ctrl+d", "quit")),
		HistoryPrev:  key.NewBinding(key.WithKeys("up"), key.WithHelp("↑", "prev history")),
		HistoryNext:  key.NewBinding(key.WithKeys("down"), key.WithHelp("↓", "next history")),
		PageUp:       key.NewBinding(key.WithKeys("pgup"), key.WithHelp("pgup", "page up")),
		PageDown:     key.NewBinding(key.WithKeys("pgdown"), key.WithHelp("pgdown", "page down")),
		Palette:      key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "commands")),
		PaletteClose: key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "close")),
	}
}
