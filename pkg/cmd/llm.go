package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/cloudbooster-io/cbx-cli/internal/config"
	"github.com/cloudbooster-io/cbx-cli/internal/llm"
	"github.com/cloudbooster-io/cbx-cli/internal/output"

	"github.com/spf13/cobra"
)

// llmRow is the shared shape across the three `llm list` surfaces (api,
// cli, combined). We collect rows first, then hand them to the same card
// renderer so the visual treatment is identical regardless of which list
// the user asked for.
type llmRow struct {
	Kind    string // "api" | "cli"
	Name    string
	Detail  string
	Default bool
	OK      bool // for cli executors: detected on PATH; for api: implicit true
}

// renderLLMProvidersCard renders the providers/executors list using the
// shared Card layout — kind chip + name (bold) + status chip + dim
// detail. Empty list returns a "no providers" card with a one-command
// hint. Kind chips use distinct colors so api/cli rows are scannable.
func renderLLMProvidersCard(rows []llmRow, title string, emptyHint string) string {
	if len(rows) == 0 {
		card := output.Card{
			Label: output.Chip("LLM", lipgloss.Color("231"), lipgloss.Color("236")),
			Title: title,
			Rows: []output.CardRow{
				{Key: "", Value: output.Dim.Render("no providers configured")},
			},
			Footer: output.Dim.Render(output.Symbol("arrow")+" ") + emptyHint,
		}
		return card.Render()
	}

	// Compute the name column width so detail strings align.
	nameW := 0
	for _, r := range rows {
		if w := lipgloss.Width(r.Name); w > nameW {
			nameW = w
		}
	}

	card := output.Card{
		Label: output.Chip("LLM", lipgloss.Color("231"), lipgloss.Color("236")),
		Title: title,
	}
	for _, r := range rows {
		kindChip := llmKindChip(r.Kind)
		name := r.Name + strings.Repeat(" ", nameW-lipgloss.Width(r.Name))
		nameStyled := lipgloss.NewStyle().Bold(true).Render(name)
		if !output.Enabled() {
			nameStyled = name
		}
		status := ""
		switch {
		case r.Default:
			status = " " + output.Chip("DEFAULT", lipgloss.Color("231"), lipgloss.Color("22"))
		case r.Kind == "cli" && !r.OK:
			status = " " + output.Chip("NOT FOUND", lipgloss.Color("231"), lipgloss.Color("124"))
		}
		row := fmt.Sprintf("%s  %s%s  %s", kindChip, nameStyled, status, output.Dim.Render(r.Detail))
		card.Rows = append(card.Rows, output.CardRow{Key: "", Value: row})
	}
	return card.Render()
}

// llmKindChip returns the small "api" / "cli" tag with distinct hues so
// the two row types are immediately separable when scanning the list.
func llmKindChip(kind string) string {
	switch kind {
	case "api":
		return output.Chip("API", lipgloss.Color("231"), lipgloss.Color("25")) // blue
	case "cli":
		return output.Chip("CLI", lipgloss.Color("231"), lipgloss.Color("57")) // purple
	default:
		return output.Chip(strings.ToUpper(kind), lipgloss.Color("231"), lipgloss.Color("240"))
	}
}

// cliExecutor describes a known local LLM CLI that cbx can shell out to.
// Adding a new executor here makes it visible to 'cbx llm cli list/test' and
// usable as a target name in 'cbx llm default'. Detection is via PATH lookup.
type cliExecutor struct {
	Name        string // user-facing name, also the --llm value
	Binary      string // executable to find on PATH
	VersionArgs []string
	Vendor      string
}

var cliExecutors = []cliExecutor{
	{
		Name:        "claude-code",
		Binary:      "claude",
		VersionArgs: []string{"--version"},
		Vendor:      "Anthropic Claude Code",
	},
	{
		Name:        "codex",
		Binary:      "codex",
		VersionArgs: []string{"--version"},
		Vendor:      "OpenAI Codex CLI",
	},
}

func findExecutor(name string) (cliExecutor, bool) {
	for _, e := range cliExecutors {
		if e.Name == name {
			return e, true
		}
	}
	return cliExecutor{}, false
}

func newLLMCmd() *cobra.Command {
	llmCmd := &cobra.Command{
		Use:   "llm",
		Short: "Manage LLM providers (HTTP API keys) and local CLI executors",
		Long: `Manage how cbx talks to LLMs. ('cbx audit aws' always uses the local Claude Code CLI for grounded analysis; see 'cbx llm cli'.)

Two flavours of provider:

  api  — direct HTTP to an API endpoint (Anthropic / OpenAI / …) using
         your own API key. Token is stored in the OS keychain.

  cli  — shell out to a local CLI binary that already owns its own
         authentication (Claude Code, Codex CLI, …). No token is stored
         by cbx; the CLI handles auth.

Use 'cbx llm list' for a combined view, 'cbx llm default <name>' to
pick which provider is used by default, and 'cbx llm model' to
see or pin the model each provider/executor runs with.`,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
	llmCmd.AddCommand(
		newLLMAPICmd(),
		newLLMCLICmd(),
		newLLMListCmd(),
		newLLMDefaultCmd(),
		newLLMModelCmd(),
	)
	return llmCmd
}

// --- model subcommand --------------------------------------------------------

// modelSourceFor resolves the effective model for a provider/executor name and
// reports where it comes from: "configured" (user override in config),
// "default" (the api provider's registry default), or "cli default" (a CLI
// executor with no override — the local CLI picks its own model).
func modelSourceFor(cfg *config.Config, name string) (model, source string) {
	if p, ok := cfg.LLM.Providers[name]; ok && p.Model != "" {
		if p.ModelPinned {
			return p.Model, "configured"
		}
		// Unpinned entries carry login-seeded defaults. For api providers
		// that's still the effective model; for pure CLI executors the model
		// is not passed to the binary unless pinned, so fall through to the
		// executor's own default.
		if _, isAPI := llm.Providers[name]; isAPI {
			return p.Model, "default"
		}
	}
	if reg, ok := llm.Providers[name]; ok {
		return reg.Model, "default"
	}
	return "", "cli default"
}

// knownModelTarget reports whether name is something a model can be configured
// for: an api provider in the registry or a known CLI executor.
func knownModelTarget(name string) bool {
	if _, ok := llm.Providers[name]; ok {
		return true
	}
	_, ok := findExecutor(name)
	return ok
}

// modelTargetNames returns every name `cbx llm model` can address, sorted,
// de-duplicated (codex is both an api provider and a CLI executor — one slot).
func modelTargetNames() []string {
	seen := map[string]bool{}
	var names []string
	for name := range llm.Providers {
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	for _, e := range cliExecutors {
		if !seen[e.Name] {
			seen[e.Name] = true
			names = append(names, e.Name)
		}
	}
	sort.Strings(names)
	return names
}

func newLLMModelCmd() *cobra.Command {
	var clear bool
	cmd := &cobra.Command{
		Use:   "model [name] [model]",
		Short: "Show or set the model a provider/executor uses",
		Long: `Show or set the model used by an api provider or CLI executor.

With no arguments, lists the effective model for every provider and
executor. With a name, shows that one. With a name and a model, stores
the model as that provider's override.

For api providers (claude, codex) the model is sent with every HTTP
request; when unset, cbx uses a current default (claude-sonnet-4-6 for
claude). For CLI executors (claude-code, codex) cbx passes the model to
the binary via --model; when unset, no flag is passed and the CLI's own
configured default applies.

Model IDs are not validated by cbx — use the provider's current names
(e.g. claude-sonnet-4-6, claude-opus-4-8).`,
		Example: `  # Show effective models for everything
  cbx llm model

  # Pin the Claude Code executor (used by audit) to Opus
  cbx llm model claude-code claude-opus-4-8

  # Set the model for the claude api provider
  cbx llm model claude claude-sonnet-4-6

  # Revert to the default
  cbx llm model claude-code --clear`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 2 {
				return fmt.Errorf("too many arguments; expected [name] [model]")
			}
			if clear && len(args) != 1 {
				return fmt.Errorf("--clear takes exactly one argument: the provider/executor name")
			}
			if len(args) == 2 && args[1] == "" {
				return fmt.Errorf("model must not be empty; use --clear to revert to the default")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			// List mode: no args.
			if len(args) == 0 {
				type row struct {
					Name   string `json:"name"`
					Model  string `json:"model"`
					Source string `json:"source"`
				}
				var rows []row
				for _, name := range modelTargetNames() {
					m, src := modelSourceFor(cfg, name)
					rows = append(rows, row{Name: name, Model: m, Source: src})
				}
				if output.JSON() {
					return output.PrintJSON(map[string]any{"models": rows}, nil)
				}
				cardRows := make([]llmRow, 0, len(rows))
				for _, r := range rows {
					detail := r.Model
					if detail == "" {
						detail = "(CLI's own default)"
					}
					cardRows = append(cardRows, llmRow{
						Kind: "api", Name: r.Name, Detail: detail + " · " + r.Source, OK: true,
					})
					if _, isCLI := findExecutor(r.Name); isCLI {
						cardRows[len(cardRows)-1].Kind = "cli"
					}
				}
				fmt.Fprint(cmd.OutOrStdout(),
					renderLLMProvidersCard(cardRows, "models",
						"run `cbx llm model <name> <model>` to set one"))
				return nil
			}

			name := args[0]
			if !knownModelTarget(name) {
				return output.NewError(output.ErrorDetail{
					What: fmt.Sprintf("unknown provider or executor: %s", name),
					Why:  fmt.Sprintf("cbx knows about: %s", strings.Join(modelTargetNames(), ", ")),
					Fix:  "run `cbx llm model` to see every configurable name",
					Code: "E_UNKNOWN_PROVIDER",
				})
			}

			// Get mode: one arg, no --clear.
			if len(args) == 1 && !clear {
				m, src := modelSourceFor(cfg, name)
				if output.JSON() {
					return output.PrintJSON(map[string]any{"provider": name, "model": m, "source": src}, nil)
				}
				if m == "" {
					output.Infof("%s: no model pinned — the local CLI's own default applies", name)
					return nil
				}
				output.Infof("%s: %s (%s)", name, m, src)
				return nil
			}

			// Clear mode.
			if clear {
				if p, ok := cfg.LLM.Providers[name]; ok {
					if p.AuthMode == config.AuthModeCLIExecutor {
						// Entry existed only to carry the override.
						delete(cfg.LLM.Providers, name)
					} else {
						p.Model = llm.Providers[name].Model
						p.ModelPinned = false
						cfg.LLM.Providers[name] = p
					}
					if err := config.Save(cfg); err != nil {
						return err
					}
				}
				m, src := modelSourceFor(cfg, name)
				if output.JSON() {
					return output.PrintJSON(map[string]any{"provider": name, "model": m, "source": src}, nil)
				}
				output.Successf("Model for %s reset to %s", name, map[bool]string{true: m, false: "the CLI's own default"}[m != ""])
				return nil
			}

			// Set mode.
			model := args[1]
			p, ok := cfg.LLM.Providers[name]
			if !ok {
				p = config.LLMProvider{Name: name, AuthMode: config.AuthModeCLIExecutor}
			}
			p.Model = model
			p.ModelPinned = true
			cfg.LLM.Providers[name] = p
			if err := config.Save(cfg); err != nil {
				return err
			}
			if output.JSON() {
				return output.PrintJSON(map[string]any{"provider": name, "model": model, "source": "configured"}, nil)
			}
			output.Successf("Model for %s set to %s", name, model)
			return nil
		},
	}
	cmd.Flags().BoolVar(&clear, "clear", false, "Remove the override and revert to the default")
	return cmd
}

// --- api subgroup -----------------------------------------------------------

func newLLMAPICmd() *cobra.Command {
	api := &cobra.Command{
		Use:   "api",
		Short: "Manage HTTP API providers (bring your own API key)",
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
	api.AddCommand(
		newLLMAPILoginCmd(),
		newLLMAPILogoutCmd(),
		newLLMAPIListCmd(),
		newLLMAPITestCmd(),
	)
	return api
}

func newLLMAPILoginCmd() *cobra.Command {
	var tokenFlag string
	cmd := &cobra.Command{
		Use:   "login <provider>",
		Short: "Store an HTTP API key for a provider (claude, codex)",
		Long: `Store an HTTP API key for a provider in the OS keychain.

Providers:
  claude   Anthropic Claude  — key format: sk-ant-...
           get one at https://console.anthropic.com/settings/keys
  codex    OpenAI            — key format: sk-...
           get one at https://platform.openai.com/api-keys

The token can be passed via --token, the CBX_LLM_TOKEN env var, or an
interactive prompt. To use a local CLI binary (Claude Code, Codex CLI)
instead of an API key, see 'cbx llm cli'.`,
		Example: `  # Interactive prompt for the key
  cbx llm api login claude

  # Pass the key inline (non-interactive)
  cbx llm api login codex --token sk-...`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return output.NewError(output.ErrorDetail{
					What: "missing provider argument",
					Why:  "usage: cbx llm api login <provider> — providers: claude, codex",
					Fix:  "run `cbx llm api login claude`; to use a local CLI binary instead, see `cbx llm cli`",
					Code: "E_MISSING_ARG",
				})
			}
			if len(args) > 1 {
				return output.NewError(output.ErrorDetail{
					What: "too many arguments",
					Why:  "expected exactly one provider name",
					Fix:  "run `cbx llm api login <provider>` with a single provider (claude or codex)",
					Code: "E_TOO_MANY_ARGS",
				})
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			provider := args[0]
			p, ok := llm.Providers[provider]
			if !ok {
				return output.NewError(output.ErrorDetail{
					What: fmt.Sprintf("unknown api provider: %s", provider),
					Why:  "only `claude` and `codex` are supported as HTTP API providers",
					Fix:  "use `cbx llm api login claude` or `cbx llm api login codex`; for local CLI executors see `cbx llm cli list`",
					Code: "E_UNKNOWN_PROVIDER",
				})
			}

			token := tokenFlag
			if token == "" {
				token = os.Getenv("CBX_LLM_TOKEN")
			}
			if token == "" {
				// No interactive prompt in JSON mode — it would corrupt the
				// machine-readable stdout. Require an explicit token source.
				if output.JSON() {
					return output.NewError(output.ErrorDetail{
						What: "token required",
						Why:  "JSON mode cannot prompt interactively for the API key",
						Fix:  "pass --token or set CBX_LLM_TOKEN",
						Code: "E_NO_TOKEN",
					})
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Enter your %s API key: ", provider)
				var input string
				if _, err := fmt.Fscanln(cmd.InOrStdin(), &input); err != nil {
					return fmt.Errorf("reading token: %w", err)
				}
				token = input
			}

			if err := llm.ValidateTokenFormat(provider, token); err != nil {
				return err
			}
			if err := llm.ValidateToken(provider, token); err != nil {
				return fmt.Errorf("token validation failed: %w", err)
			}
			if err := llm.StoreToken(provider, token); err != nil {
				return fmt.Errorf("storing token: %w", err)
			}

			cfg, err := config.Load()
			if err != nil {
				return err
			}
			if cfg.LLM.Providers == nil {
				cfg.LLM.Providers = map[string]config.LLMProvider{}
			}
			cfg.LLM.Providers[provider] = config.LLMProvider{
				Name:     provider,
				BaseURL:  p.BaseURL,
				Model:    p.Model,
				LoggedIn: true,
				AuthMode: config.AuthModeAPIKey,
			}
			if cfg.LLM.Default == "" {
				cfg.LLM.Default = provider
			}
			if err := config.Save(cfg); err != nil {
				return err
			}

			if output.JSON() {
				return output.PrintJSON(map[string]any{
					"provider":  provider,
					"status":    "logged_in",
					"auth_mode": config.AuthModeAPIKey,
					"default":   cfg.LLM.Default == provider,
				}, nil)
			}
			output.Successf("Logged in to api/%s (key stored in OS keychain)", provider)
			return nil
		},
	}
	cmd.Flags().StringVar(&tokenFlag, "token", "", "API key (skips env var and prompt)")
	return cmd
}

func newLLMAPILogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout <provider>",
		Short: "Forget the stored API key for a provider",
		Args:  RequireExactlyOneArg("provider", "cbx llm api logout <provider>   (e.g. claude, codex)"),
		RunE: func(cmd *cobra.Command, args []string) error {
			provider := args[0]
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			_ = llm.DeleteToken(provider)
			delete(cfg.LLM.Providers, provider)
			if cfg.LLM.Default == provider {
				cfg.LLM.Default = ""
			}
			if err := config.Save(cfg); err != nil {
				return err
			}
			if output.JSON() {
				return output.PrintJSON(map[string]any{"provider": provider, "status": "logged_out"}, nil)
			}
			output.Successf("Logged out of api/%s", provider)
			return nil
		},
	}
}

func newLLMAPIListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List configured HTTP API providers",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			type row struct {
				Name    string `json:"name"`
				Model   string `json:"model"`
				BaseURL string `json:"base_url"`
				Default bool   `json:"default"`
			}
			var rows []row
			for name, p := range cfg.LLM.Providers {
				if p.AuthMode != "" && p.AuthMode != config.AuthModeAPIKey {
					continue
				}
				rows = append(rows, row{
					Name:    name,
					Model:   p.Model,
					BaseURL: p.BaseURL,
					Default: cfg.LLM.Default == name,
				})
			}
			sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })

			if output.JSON() {
				return output.PrintJSON(map[string]any{"providers": rows}, nil)
			}
			cardRows := make([]llmRow, 0, len(rows))
			for _, r := range rows {
				cardRows = append(cardRows, llmRow{
					Kind: "api", Name: r.Name, Detail: r.Model, Default: r.Default, OK: true,
				})
			}
			fmt.Fprint(cmd.OutOrStdout(),
				renderLLMProvidersCard(cardRows, "api providers",
					"run `cbx llm api login <provider>` (e.g. claude, openai) to configure one"))
			return nil
		},
	}
}

func newLLMAPITestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test <provider>",
		Short: "Verify a configured api provider's key is still valid (calls /models)",
		Args:  RequireExactlyOneArg("provider", "cbx llm api test <provider>   (e.g. claude, codex)"),
		RunE: func(cmd *cobra.Command, args []string) error {
			provider := args[0]
			token, err := llm.GetToken(provider)
			if err != nil || token == "" {
				return output.NewError(output.ErrorDetail{
					What: fmt.Sprintf("no stored key for api/%s", provider),
					Why:  "cbx has not seen an API key for this provider in the OS keychain",
					Fix:  fmt.Sprintf("run `cbx llm api login %s` to store one", provider),
					Code: "E_NO_TOKEN",
				})
			}
			if err := llm.ValidateToken(provider, token); err != nil {
				return output.NewError(output.ErrorDetail{
					What: fmt.Sprintf("api/%s test failed", provider),
					Why:  err.Error(),
					Fix:  fmt.Sprintf("re-run `cbx llm api login %s` if the key was rotated or revoked", provider),
					Code: "E_LLM_TEST_FAILED",
				})
			}
			if output.JSON() {
				return output.PrintJSON(map[string]any{"provider": provider, "ok": true}, nil)
			}
			output.Successf("api/%s OK", provider)
			return nil
		},
	}
}

// --- cli subgroup -----------------------------------------------------------

func newLLMCLICmd() *cobra.Command {
	cli := &cobra.Command{
		Use:   "cli",
		Short: "Manage local CLI executors (Claude Code, Codex CLI, …)",
		Long: `Local CLI executors are vendor-supplied command-line tools (Claude
Code, OpenAI Codex CLI, …) that already own their own authentication.
cbx shells out to them — no token is stored on the cbx side.

Use 'cbx llm cli list' to see which executors cbx knows about and
which are detected on PATH. Use 'cbx llm cli test <name>' to verify
the binary responds AND can serve a real prompt (auth, model, limits).`,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
	cli.AddCommand(
		newLLMCLIListCmd(),
		newLLMCLITestCmd(),
	)
	return cli
}

func newLLMCLIListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List known CLI executors and whether they're detected on PATH",
		RunE: func(cmd *cobra.Command, args []string) error {
			type row struct {
				Name     string `json:"name"`
				Binary   string `json:"binary"`
				Vendor   string `json:"vendor"`
				Detected bool   `json:"detected"`
				Path     string `json:"path,omitempty"`
			}
			rows := make([]row, 0, len(cliExecutors))
			for _, e := range cliExecutors {
				r := row{Name: e.Name, Binary: e.Binary, Vendor: e.Vendor}
				if p, err := exec.LookPath(e.Binary); err == nil {
					r.Detected = true
					r.Path = p
				}
				rows = append(rows, r)
			}

			if output.JSON() {
				return output.PrintJSON(map[string]any{"executors": rows}, nil)
			}
			cardRows := make([]llmRow, 0, len(rows))
			for _, r := range rows {
				detail := r.Vendor + " · " + r.Path
				if !r.Detected {
					detail = r.Vendor + " · not on PATH"
				}
				cardRows = append(cardRows, llmRow{
					Kind: "cli", Name: r.Name, Detail: detail, OK: r.Detected,
				})
			}
			fmt.Fprint(cmd.OutOrStdout(),
				renderLLMProvidersCard(cardRows, "cli executors",
					"install Claude Code or OpenAI Codex CLI and re-run `cbx llm cli list`"))
			return nil
		},
	}
}

func newLLMCLITestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test <name>",
		Short: "Verify the executor works: --version, then a one-shot prompt",
		Long: `Verify a local CLI executor end to end. Runs <binary> --version
(installed and callable), then sends a minimal one-shot prompt through
the same non-interactive invocation cbx uses for real work ('claude -p',
'codex exec'), honoring any 'cbx llm model' pin.

The prompt step is the part --version cannot cover: expired auth, a
revoked or inaccessible model, and exhausted usage limits only surface
on a real completion. 'cbx audit aws' runs this same probe before
spending time on AWS discovery.`,
		Example: `  # Verify Claude Code is installed, authenticated, and can serve a prompt
  cbx llm cli test claude-code`,
		Args: RequireExactlyOneArg("executor name", "cbx llm cli test <name>   (e.g. claude-code, codex; see: cbx llm cli list)"),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			e, ok := findExecutor(name)
			if !ok {
				known := make([]string, 0, len(cliExecutors))
				for _, x := range cliExecutors {
					known = append(known, x.Name)
				}
				return output.NewError(output.ErrorDetail{
					What: fmt.Sprintf("unknown executor: %s", name),
					Why:  fmt.Sprintf("cbx knows about: %s", strings.Join(known, ", ")),
					Fix:  "pick a known executor name, or run `cbx llm cli list` to see what's available",
					Code: "E_UNKNOWN_EXECUTOR",
				})
			}
			bin, err := exec.LookPath(e.Binary)
			if err != nil {
				return output.NewError(output.ErrorDetail{
					What: fmt.Sprintf("executor %s not found on PATH", name),
					Why:  fmt.Sprintf("looked for binary %q but it's not on PATH", e.Binary),
					Fix:  fmt.Sprintf("install the %s CLI and ensure %q is on PATH; check with `which %s`", e.Vendor, e.Binary, e.Binary),
					Code: "E_NOT_ON_PATH",
				})
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			out, runErr := exec.CommandContext(ctx, bin, e.VersionArgs...).CombinedOutput()
			versionLine := strings.TrimSpace(string(out))
			if runErr != nil {
				return output.NewError(output.ErrorDetail{
					What: fmt.Sprintf("executor %s at %s failed --version", name, bin),
					Why:  fmt.Sprintf("%v — %s", runErr, versionLine),
					Fix:  fmt.Sprintf("reinstall the %s CLI or check the binary runs by hand", e.Vendor),
					Code: "E_EXECUTOR_BROKEN",
				})
			}

			// Prompt probe — the part --version can't cover. Same
			// invocation shape, binary resolution, and model pin as a
			// real audit run (see llm.ProbeCLIExecutor).
			model := pinnedExecutorModel(name)
			if !output.JSON() && !output.IsQuiet() {
				modelNote := ""
				if model != "" {
					modelNote = " (model " + model + ")"
				}
				fmt.Fprintf(os.Stderr, "%s\n",
					output.Dim.Render(fmt.Sprintf("sending a one-shot probe prompt to %s%s — a few seconds…", name, modelNote)))
			}
			probeCtx, probeCancel := context.WithTimeout(context.Background(), llmProbeTimeout)
			defer probeCancel()
			started := time.Now()
			_, probeErr := llm.ProbeCLIExecutor(probeCtx, name, model)
			elapsed := time.Since(started)
			if probeErr != nil {
				if output.JSON() {
					_ = output.PrintJSON(map[string]any{
						"executor": name, "ok": false, "path": bin, "version": versionLine,
						"model": model, "probe_ok": false, "error": probeErr.Error(),
					}, nil)
				}
				return fmt.Errorf("%s", output.RenderError(output.ErrorDetail{
					What: fmt.Sprintf("executor %s answers --version but failed the prompt probe", name),
					Why:  probeErr.Error(),
					Fix:  fmt.Sprintf("the binary runs but can't serve a completion — check the %s CLI's auth, usage limits, and the pinned model (`cbx llm model`)", e.Vendor),
					Code: "E_EXECUTOR_PROBE_FAILED",
				}))
			}

			if output.JSON() {
				return output.PrintJSON(map[string]any{
					"executor": name, "ok": true, "path": bin, "version": versionLine,
					"model": model, "probe_ok": true, "probe_seconds": elapsed.Seconds(),
				}, nil)
			}
			probeLine := fmt.Sprintf("prompt probe OK in %.1fs", elapsed.Seconds())
			if model != "" {
				probeLine += " (model " + model + ")"
			}
			output.Successf("cli/%s OK (%s)\n  %s\n  %s", name, bin, versionLine, probeLine)
			return nil
		},
	}
}

// llmProbeTimeout bounds the one-shot prompt probe in `cbx llm cli test`
// and the `cbx audit aws` LLM preflight. Generous: a cold `claude -p`
// run on a tiny prompt is normally well under 30s, but slow first-token
// days shouldn't fail the check.
const llmProbeTimeout = 90 * time.Second

// pinnedExecutorModel returns the model the user pinned for a CLI
// executor via `cbx llm model <name> <model>`, or "" when unpinned /
// config is unreadable — matching how the plan pipeline resolves it
// (internal/plan/pipeline.go), so the probe tests the model a real run
// would use.
func pinnedExecutorModel(name string) string {
	cfg, err := config.Load()
	if err != nil {
		return ""
	}
	if p := cfg.LLM.Providers[name]; p.ModelPinned && p.Model != "" {
		return p.Model
	}
	return ""
}

// --- top-level list + default ----------------------------------------------

func newLLMListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "Unified view of all api providers and cli executors",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			type entry struct {
				Name    string `json:"name"`
				Kind    string `json:"kind"` // "api" or "cli"
				Detail  string `json:"detail"`
				Default bool   `json:"default"`
			}
			var entries []entry

			for name, p := range cfg.LLM.Providers {
				if p.AuthMode != "" && p.AuthMode != config.AuthModeAPIKey {
					continue
				}
				entries = append(entries, entry{
					Name: name, Kind: "api",
					Detail:  p.Model,
					Default: cfg.LLM.Default == name,
				})
			}
			for _, e := range cliExecutors {
				status := "not installed"
				if p, err := exec.LookPath(e.Binary); err == nil {
					status = p
				}
				entries = append(entries, entry{
					Name: e.Name, Kind: "cli",
					Detail:  status,
					Default: cfg.LLM.Default == e.Name,
				})
			}
			sort.Slice(entries, func(i, j int) bool {
				if entries[i].Kind != entries[j].Kind {
					return entries[i].Kind < entries[j].Kind
				}
				return entries[i].Name < entries[j].Name
			})

			if output.JSON() {
				return output.PrintJSON(map[string]any{"providers": entries, "default": cfg.LLM.Default}, nil)
			}
			cardRows := make([]llmRow, 0, len(entries))
			for _, e := range entries {
				ok := true
				if e.Kind == "cli" {
					// "not installed" detail signals PATH miss; flip the OK
					// bit so the row gets the red NOT FOUND chip.
					ok = e.Detail != "not installed"
				}
				cardRows = append(cardRows, llmRow{
					Kind: e.Kind, Name: e.Name, Detail: e.Detail, Default: e.Default, OK: ok,
				})
			}
			fmt.Fprint(cmd.OutOrStdout(),
				renderLLMProvidersCard(cardRows, "providers",
					"run `cbx llm api login <name>` for an API key or install a CLI executor (see `cbx llm cli list`)"))
			return nil
		},
	}
}

func newLLMDefaultCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "default <name>",
		Short: "Set the default LLM provider (api or cli)",
		Example: `  # Use the Anthropic API provider (after cbx llm api login claude)
  cbx llm default claude

  # Use the local Claude Code CLI executor
  cbx llm default claude-code`,
		Args: RequireExactlyOneArg("provider name", "cbx llm default <name>   (api provider or cli executor; see: cbx llm list)"),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			// Accept either: an api provider already configured via login,
			// or a cli executor whose binary is currently detectable.
			if _, ok := cfg.LLM.Providers[name]; !ok {
				e, known := findExecutor(name)
				if !known {
					return output.NewError(output.ErrorDetail{
						What: fmt.Sprintf("%s is not logged in", name),
						Why:  "no api provider with that name is configured and no cli executor with that name is known",
						Fix:  fmt.Sprintf("run `cbx llm api login %s` to add it as an api provider, or `cbx llm cli list` to see known cli executors", name),
						Code: "E_NO_LLM",
					})
				}
				if _, err := exec.LookPath(e.Binary); err != nil {
					return output.NewError(output.ErrorDetail{
						What: fmt.Sprintf("cli executor %s is known but not on PATH", name),
						Why:  fmt.Sprintf("looked for binary %q but it's not detectable on PATH", e.Binary),
						Fix:  fmt.Sprintf("install the %s CLI and ensure %q is on PATH; verify with `cbx llm cli test %s`", e.Vendor, e.Binary, name),
						Code: "E_NOT_ON_PATH",
					})
				}
			}

			cfg.LLM.Default = name
			if err := config.Save(cfg); err != nil {
				return err
			}
			if output.JSON() {
				return output.PrintJSON(map[string]any{"default": name}, nil)
			}
			output.Successf("Default LLM set to %s", name)
			return nil
		},
	}
}
