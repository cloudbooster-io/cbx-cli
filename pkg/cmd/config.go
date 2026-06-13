package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/cloudbooster-io/cbx-cli/internal/config"
	"github.com/cloudbooster-io/cbx-cli/internal/output"
)

// configKey describes a user-facing config key, its getter from the
// on-disk Config, and its setter. Adding a new key here is the only
// place a new field has to be wired — `cbx config list` introspects
// the map automatically.
type configKey struct {
	get func(*config.Config) string
	set func(*config.Config, string)
}

func configKeys() map[string]configKey {
	return map[string]configKey{
		"api_url": {
			get: func(c *config.Config) string { return c.APIURL },
			set: func(c *config.Config, v string) { c.APIURL = v },
		},
		"default_org": {
			get: func(c *config.Config) string { return c.DefaultOrg },
			set: func(c *config.Config, v string) { c.DefaultOrg = v },
		},
		"llm.default": {
			get: func(c *config.Config) string { return c.LLM.Default },
			set: func(c *config.Config, v string) { c.LLM.Default = v },
		},
		"aws.default_region": {
			get: func(c *config.Config) string { return c.AWS.DefaultRegion },
			set: func(c *config.Config, v string) { c.AWS.DefaultRegion = v },
		},
	}
}

func sortedKeyNames() []string {
	keys := configKeys()
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

func unknownKeyError(key string) error {
	return output.NewError(output.ErrorDetail{
		What: fmt.Sprintf("unknown config key: %q", key),
		Why:  "the requested key is not a recognized cbx configuration key",
		Fix:  fmt.Sprintf("pick one of: %s", strings.Join(sortedKeyNames(), ", ")),
		Code: "E_UNKNOWN_CONFIG_KEY",
	})
}

func newConfigCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "config",
		Short: "Read and write persistent cbx settings",
		Long: `Inspect and update persistent configuration stored in the cbx
config file (see ` + "`cbx doctor`" + ` for its path).

Supported keys:

  api_url               CloudBooster API base URL
  default_org           Default organization slug
  llm.default           Default LLM provider for plan/audit
  aws.default_region    Default AWS region for ` + "`cbx audit aws`" + ` when
                        --region is not passed`,
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}
	c.AddCommand(newConfigSetCmd(), newConfigGetCmd(), newConfigListCmd())
	return c
}

func newConfigSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a persistent config value",
		Example: `  # Pin the default AWS region used by ` + "`cbx audit aws`" + `
  cbx config set aws.default_region us-east-1

  # Set the default LLM provider
  cbx config set llm.default claude-code`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			key, value := args[0], args[1]
			keys := configKeys()
			entry, ok := keys[key]
			if !ok {
				return unknownKeyError(key)
			}
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			entry.set(cfg, value)
			if err := config.Save(cfg); err != nil {
				return err
			}
			if output.JSON() {
				return output.PrintJSON(map[string]string{
					"key":   key,
					"value": value,
				}, nil)
			}
			output.Successf("Set %s = %s", key, value)
			return nil
		},
	}
}

func newConfigGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <key>",
		Short: "Print a single config value to stdout",
		Example: `  cbx config get aws.default_region
  cbx config get llm.default --output json`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := args[0]
			keys := configKeys()
			entry, ok := keys[key]
			if !ok {
				return unknownKeyError(key)
			}
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			value := entry.get(cfg)
			if output.JSON() {
				return output.PrintJSON(map[string]string{
					"key":   key,
					"value": value,
				}, nil)
			}
			fmt.Fprintln(cmd.OutOrStdout(), value)
			return nil
		},
	}
}

func newConfigListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "Print all known config keys and their current values",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			keys := configKeys()
			names := sortedKeyNames()
			if output.JSON() {
				rows := make(map[string]string, len(names))
				for _, k := range names {
					rows[k] = keys[k].get(cfg)
				}
				return output.PrintJSON(rows, nil)
			}
			card := output.Card{
				Label: output.Chip("CONFIG", lipgloss.Color("231"), lipgloss.Color("236")),
				Title: "cbx settings",
			}
			for _, k := range names {
				v := keys[k].get(cfg)
				if v == "" {
					v = output.Dim.Render("—")
				} else if output.Enabled() {
					v = lipgloss.NewStyle().Bold(true).Render(v)
				}
				card.AddRow(k, v)
			}
			card.Footer = output.Dim.Render(output.Symbol("arrow")+" ") +
				"cbx config set <key> <value>" +
				output.Dim.Render(" to change a setting · `cbx config get <key>` for raw stdout")
			fmt.Fprint(cmd.OutOrStdout(), card.Render())
			return nil
		},
	}
}
