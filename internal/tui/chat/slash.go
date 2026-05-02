package chat

import (
	"fmt"
	"sort"
	"strings"
)

// ErrQuit signals that the REPL should exit.
var ErrQuit = fmt.Errorf("quit")

// Command represents a registered slash command.
type Command struct {
	Name    string
	Args    string // display args for help / palette (e.g. "[path]")
	Summary string
	Handler func(args []string) (string, error)
}

// ParsedCommand is the result of parsing a slash command from user input.
type ParsedCommand struct {
	Name string
	Args []string
}

// Registry holds a collection of slash commands.
type Registry struct {
	commands map[string]Command
}

// NewRegistry creates an empty slash-command registry.
func NewRegistry() *Registry {
	return &Registry{
		commands: make(map[string]Command),
	}
}

// Register adds a command to the registry. If a command with the same name
// already exists, it is overwritten.
func (r *Registry) Register(cmd Command) {
	r.commands[cmd.Name] = cmd
}

// Execute runs the handler for the named command.
func (r *Registry) Execute(name string, args []string) (string, error) {
	cmd, ok := r.commands[name]
	if !ok {
		var suggestions []string
		for _, c := range r.commands {
			if strings.Contains(c.Name, name) || strings.Contains(name, c.Name) {
				suggestions = append(suggestions, "/"+c.Name)
			}
		}
		if len(suggestions) > 0 {
			return "", fmt.Errorf("unknown command: /%s. Did you mean: %s?", name, strings.Join(suggestions, ", "))
		}
		return "", fmt.Errorf("unknown command: /%s (type /help for available commands)", name)
	}
	return cmd.Handler(args)
}

// Commands returns all registered commands in alphabetical order.
func (r *Registry) Commands() []Command {
	var names []string
	for name := range r.commands {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []Command
	for _, name := range names {
		out = append(out, r.commands[name])
	}
	return out
}

// Help formats the registered commands as a help string.
func (r *Registry) Help() string {
	var sb strings.Builder
	sb.WriteString("Available commands:\n")
	for _, c := range r.Commands() {
		if c.Args != "" {
			sb.WriteString(fmt.Sprintf("  /%-10s %-15s — %s\n", c.Name, c.Args, c.Summary))
		} else {
			sb.WriteString(fmt.Sprintf("  /%-10s %-15s — %s\n", c.Name, "", c.Summary))
		}
	}
	return sb.String()
}

// ParseSlashCommand parses a slash command from user input.
func ParseSlashCommand(input string) (*ParsedCommand, error) {
	input = strings.TrimSpace(input)
	if !strings.HasPrefix(input, "/") {
		return nil, fmt.Errorf("not a slash command")
	}
	parts := strings.Fields(input[1:])
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	return &ParsedCommand{
		Name: strings.ToLower(parts[0]),
		Args: parts[1:],
	}, nil
}

// fuzzyMatch reports whether pattern is a subsequence of text (case-insensitive).
func fuzzyMatch(pattern, text string) bool {
	pattern = strings.ToLower(pattern)
	text = strings.ToLower(text)
	pi := 0
	for ti := 0; ti < len(text) && pi < len(pattern); ti++ {
		if text[ti] == pattern[pi] {
			pi++
		}
	}
	return pi == len(pattern)
}
