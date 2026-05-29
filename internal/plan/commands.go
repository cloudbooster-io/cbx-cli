package plan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cloudbooster-io/cbx-cli/internal/config"
	"github.com/cloudbooster-io/cbx-cli/internal/output"
	"github.com/cloudbooster-io/cbx-cli/internal/tui/chat"
)

const maxFreeVariants = 2

// Command represents a parsed slash command.
type Command struct {
	Name string
	Args []string
}

// ParseSlashCommand parses a slash command from user input.
func ParseSlashCommand(input string) (*Command, error) {
	input = strings.TrimSpace(input)
	if !strings.HasPrefix(input, "/") {
		return nil, fmt.Errorf("not a slash command")
	}
	parts := strings.Fields(input[1:])
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	return &Command{
		Name: strings.ToLower(parts[0]),
		Args: parts[1:],
	}, nil
}

// AvailableCommands returns the list of available slash commands for help/palette.
func AvailableCommands() []struct {
	Name        string
	Args        string
	Description string
} {
	return []struct {
		Name        string
		Args        string
		Description string
	}{
		{"save", "[path]", "Save current plan to files"},
		{"regenerate", "", "Re-run LLM with same candidates"},
		{"refine", "<text>", "Add a follow-up refinement"},
		{"variants", "<N>", fmt.Sprintf("Request N variants (max %d on free tier)", maxFreeVariants)},
		{"llm", "<provider>", "Switch active LLM provider"},
		{"diagram", "mermaid|d2", "Toggle diagram output format"},
		{"export", "json [path]", "Export plan as JSON"},
		{"help", "", "Show this help message"},
		{"quit", "", "Exit the planner"},
	}
}

// ExecuteSlashCommand runs a slash command against the session.
func ExecuteSlashCommand(cmd *Command, session *Session, client Client, cfg *config.Config) (string, error) {
	if cmd.Name != "quit" {
		session.PendingQuit = false
	}
	switch cmd.Name {
	case "save":
		return cmdSave(cmd.Args, session)
	case "regenerate":
		return cmdRegenerate(session, client, cfg)
	case "refine":
		return cmdRefine(cmd.Args, session, client, cfg)
	case "variants":
		return cmdVariants(cmd.Args, session)
	case "llm":
		return cmdLLM(cmd.Args, session, cfg)
	case "diagram":
		return cmdDiagram(cmd.Args, session)
	case "export":
		return cmdExport(cmd.Args, session)
	case "help":
		return cmdHelp(), nil
	case "quit":
		return cmdQuit(session)
	default:
		var suggestions []string
		for _, c := range AvailableCommands() {
			if strings.Contains(c.Name, cmd.Name) || strings.Contains(cmd.Name, c.Name) {
				suggestions = append(suggestions, "/"+c.Name)
			}
		}
		if len(suggestions) > 0 {
			return "", fmt.Errorf("unknown command: /%s. Did you mean: %s?", cmd.Name, strings.Join(suggestions, ", "))
		}
		return "", fmt.Errorf("unknown command: /%s (type /help for available commands)", cmd.Name)
	}
}

func cmdSave(args []string, session *Session) (string, error) {
	if session.CurrentPlan == nil {
		return "", fmt.Errorf("no plan to save")
	}
	dir := session.OutputDir
	if len(args) > 0 {
		dir = args[0]
	}
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creating output dir: %w", err)
	}

	mdPath := filepath.Join(dir, "plan.md")
	md := output.RenderPlanMD(session.CurrentPlan.Intent, session.CurrentPlan.Version, session.CurrentPlan.ADRContent, session.CurrentPlan.MermaidContent)
	if err := os.WriteFile(mdPath, []byte(md), 0o644); err != nil {
		return "", fmt.Errorf("writing plan markdown: %w", err)
	}

	var parts []string
	parts = append(parts, fmt.Sprintf("%s (%d bytes)", mdPath, len(md)))
	if session.DiagramFormat == "d2" {
		d2Path := filepath.Join(dir, "plan.d2")
		if err := os.WriteFile(d2Path, []byte(session.CurrentPlan.D2Content), 0o644); err != nil {
			return "", fmt.Errorf("writing D2 diagram: %w", err)
		}
		parts = append(parts, fmt.Sprintf("%s (%d bytes)", d2Path, len(session.CurrentPlan.D2Content)))
	}

	session.MarkSaved()
	return fmt.Sprintf("Saved plan v%d to %s (%s)", session.CurrentPlan.Version, dir, strings.Join(parts, ", ")), nil
}

func cmdRegenerate(session *Session, client Client, cfg *config.Config) (string, error) {
	if len(session.History) == 0 {
		return "", fmt.Errorf("no previous intent to regenerate")
	}
	intent := session.History[0].Input
	provider := GetProvider(session, cfg)
	plan, err := client.GeneratePlan(context.Background(), intent, provider)
	if err != nil {
		return "", err
	}
	session.SetPlan(plan)
	session.AppendTurn(intent, false, plan)
	return fmt.Sprintf("Regenerated plan v%d", plan.Version), nil
}

func cmdRefine(args []string, session *Session, client Client, cfg *config.Config) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("usage: /refine <text>")
	}
	if session.CurrentPlan == nil {
		return "", fmt.Errorf("no plan to refine; start with an intent first")
	}
	refineText := strings.Join(args, " ")
	provider := GetProvider(session, cfg)
	plan, err := client.RefinePlan(context.Background(), session.CurrentPlan, refineText, provider)
	if err != nil {
		return "", err
	}
	session.SetPlan(plan)
	session.AppendTurn(refineText, true, plan)
	return fmt.Sprintf("Refined plan v%d: %s", plan.Version, refineText), nil
}

func cmdVariants(args []string, session *Session) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("usage: /variants <N>")
	}
	n, err := strconv.Atoi(args[0])
	if err != nil || n < 1 {
		return "", fmt.Errorf("invalid variant count: %s", args[0])
	}
	if n > maxFreeVariants {
		return "", fmt.Errorf("free tier capped at %d variants. Upgrade with: cbx plan --variants %d --explore", maxFreeVariants, n)
	}
	if session.CurrentPlan == nil {
		return "", fmt.Errorf("no plan to generate variants for")
	}
	return fmt.Sprintf("Generated %d variant(s) (v%d head)", n, session.CurrentPlan.Version), nil
}

func cmdLLM(args []string, session *Session, cfg *config.Config) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("usage: /llm <provider>")
	}
	provider := args[0]
	if _, ok := cfg.LLM.Providers[provider]; !ok {
		return "", fmt.Errorf("provider %s is not logged in; run 'cbx llm api login %s' first", provider, provider)
	}
	cfg.LLM.Default = provider
	if err := config.Save(cfg); err != nil {
		return "", fmt.Errorf("saving config: %w", err)
	}
	session.ActiveProvider = provider
	return fmt.Sprintf("Switched to %s", provider), nil
}

func cmdDiagram(args []string, session *Session) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("usage: /diagram mermaid|d2")
	}
	format := strings.ToLower(args[0])
	if format != "mermaid" && format != "d2" {
		return "", fmt.Errorf("unknown diagram format: %s (choose mermaid or d2)", format)
	}
	session.DiagramFormat = format
	return fmt.Sprintf("Diagram format set to %s", format), nil
}

func cmdExport(args []string, session *Session) (string, error) {
	if session.CurrentPlan == nil {
		return "", fmt.Errorf("no plan to export")
	}
	jsonStr, err := ExportJSON(session.CurrentPlan)
	if err != nil {
		return "", err
	}
	if len(args) > 1 {
		path := args[1]
		if err := os.WriteFile(path, []byte(jsonStr), 0o644); err != nil {
			return "", fmt.Errorf("writing export: %w", err)
		}
		return fmt.Sprintf("Exported plan to %s", path), nil
	}
	return jsonStr, nil
}

func cmdHelp() string {
	var sb strings.Builder
	sb.WriteString("Available commands:\n")
	for _, c := range AvailableCommands() {
		if c.Args != "" {
			sb.WriteString(fmt.Sprintf("  /%-10s %-15s — %s\n", c.Name, c.Args, c.Description))
		} else {
			sb.WriteString(fmt.Sprintf("  /%-10s %-15s — %s\n", c.Name, "", c.Description))
		}
	}
	return sb.String()
}

func cmdQuit(session *Session) (string, error) {
	if session.Unsaved && !session.PendingQuit {
		session.PendingQuit = true
		return "You have unsaved changes. Use /save first, or /quit again to discard.", nil
	}
	return "Goodbye!", chat.ErrQuit
}
