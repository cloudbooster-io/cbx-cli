package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/config"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/llm"
	"gitlab.com/cloudbooster.io/platform/cbx-cli/internal/output"

	"github.com/spf13/cobra"
)

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
		Long: `Manage how cbx talks to LLMs for 'cbx plan' and 'cbx audit aws --llm'.

Two flavours of provider:

  api  — direct HTTP to an API endpoint (Anthropic / OpenAI / …) using
         your own API key. Token is stored in the OS keychain.

  cli  — shell out to a local CLI binary that already owns its own
         authentication (Claude Code, Codex CLI, …). No token is stored
         by cbx; the CLI handles auth.

Use 'cbx llm list' for a combined view and 'cbx llm default <name>' to
pick which provider plan/audit use by default.`,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
	llmCmd.AddCommand(
		newLLMAPICmd(),
		newLLMCLICmd(),
		newLLMListCmd(),
		newLLMDefaultCmd(),
	)
	return llmCmd
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
				return fmt.Errorf("missing provider argument\n\nUsage: cbx llm api login <provider>\nProviders: claude, codex\n\nTo use a local CLI binary instead, see: cbx llm cli")
			}
			if len(args) > 1 {
				return fmt.Errorf("too many arguments; expected exactly one provider")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			provider := args[0]
			p, ok := llm.Providers[provider]
			if !ok {
				return fmt.Errorf("%s", output.RenderError(output.ErrorDetail{
					What: fmt.Sprintf("unknown api provider: %s", provider),
					Why:  "only `claude` and `codex` are supported as HTTP API providers",
					Fix:  "use `cbx llm api login claude` or `cbx llm api login codex`; for local CLI executors see `cbx llm cli list`",
					Code: "E_UNKNOWN_PROVIDER",
				}))
			}

			token := tokenFlag
			if token == "" {
				token = os.Getenv("CBX_LLM_TOKEN")
			}
			if token == "" {
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
			if len(rows) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No api providers configured. Use: cbx llm api login <provider>")
				return nil
			}
			for _, r := range rows {
				marker := ""
				if r.Default {
					marker = " (default)"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s%s — %s\n", r.Name, marker, r.Model)
			}
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
				return fmt.Errorf("%s", output.RenderError(output.ErrorDetail{
					What: fmt.Sprintf("no stored key for api/%s", provider),
					Why:  "cbx has not seen an API key for this provider in the OS keychain",
					Fix:  fmt.Sprintf("run `cbx llm api login %s` to store one", provider),
					Code: "E_NO_TOKEN",
				}))
			}
			if err := llm.ValidateToken(provider, token); err != nil {
				if output.JSON() {
					return output.PrintJSON(map[string]any{"provider": provider, "ok": false, "error": err.Error()}, nil)
				}
				return fmt.Errorf("api/%s test failed: %w", provider, err)
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
the binary responds.`,
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
			for _, r := range rows {
				status := "not installed"
				if r.Detected {
					status = r.Path
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%-12s — %s [%s]\n", r.Name, r.Vendor, status)
			}
			return nil
		},
	}
}

func newLLMCLITestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test <name>",
		Short: "Run <binary> --version to confirm the executor is callable",
		Example: `  # Verify Claude Code is installed and responding
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
				return fmt.Errorf("%s", output.RenderError(output.ErrorDetail{
					What: fmt.Sprintf("unknown executor: %s", name),
					Why:  fmt.Sprintf("cbx knows about: %s", strings.Join(known, ", ")),
					Fix:  "pick a known executor name, or run `cbx llm cli list` to see what's available",
					Code: "E_UNKNOWN_EXECUTOR",
				}))
			}
			bin, err := exec.LookPath(e.Binary)
			if err != nil {
				return fmt.Errorf("%s", output.RenderError(output.ErrorDetail{
					What: fmt.Sprintf("executor %s not found on PATH", name),
					Why:  fmt.Sprintf("looked for binary %q but it's not on PATH", e.Binary),
					Fix:  fmt.Sprintf("install the %s CLI and ensure %q is on PATH; check with `which %s`", e.Vendor, e.Binary, e.Binary),
					Code: "E_NOT_ON_PATH",
				}))
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			out, runErr := exec.CommandContext(ctx, bin, e.VersionArgs...).CombinedOutput()
			versionLine := strings.TrimSpace(string(out))
			if runErr != nil {
				if output.JSON() {
					return output.PrintJSON(map[string]any{"executor": name, "ok": false, "path": bin, "error": runErr.Error(), "output": versionLine}, nil)
				}
				return fmt.Errorf("executor %s at %s failed --version: %v\n%s", name, bin, runErr, versionLine)
			}
			if output.JSON() {
				return output.PrintJSON(map[string]any{"executor": name, "ok": true, "path": bin, "version": versionLine}, nil)
			}
			output.Successf("cli/%s OK (%s)\n  %s", name, bin, versionLine)
			return nil
		},
	}
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
			if len(entries) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No LLM providers configured.")
				return nil
			}
			for _, e := range entries {
				marker := ""
				if e.Default {
					marker = " (default)"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%-4s %s%s — %s\n", e.Kind, e.Name, marker, e.Detail)
			}
			return nil
		},
	}
}

func newLLMDefaultCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "default <name>",
		Short: "Set the default LLM provider (api or cli) for plan/audit",
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
					return fmt.Errorf("%s", output.RenderError(output.ErrorDetail{
						What: fmt.Sprintf("%s is not logged in", name),
						Why:  "no api provider with that name is configured and no cli executor with that name is known",
						Fix:  fmt.Sprintf("run `cbx llm api login %s` to add it as an api provider, or `cbx llm cli list` to see known cli executors", name),
						Code: "E_NO_LLM",
					}))
				}
				if _, err := exec.LookPath(e.Binary); err != nil {
					return fmt.Errorf("%s", output.RenderError(output.ErrorDetail{
						What: fmt.Sprintf("cli executor %s is known but not on PATH", name),
						Why:  fmt.Sprintf("looked for binary %q but it's not detectable on PATH", e.Binary),
						Fix:  fmt.Sprintf("install the %s CLI and ensure %q is on PATH; verify with `cbx llm cli test %s`", e.Vendor, e.Binary, name),
						Code: "E_NOT_ON_PATH",
					}))
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
