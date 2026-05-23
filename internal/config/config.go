package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

// Config holds the CLI configuration.
type Config struct {
	Auth       AuthConfig      `json:"auth,omitempty"`
	LLM        LLMConfig       `json:"llm,omitempty"`
	APIURL     string          `json:"api_url,omitempty"`
	DefaultOrg string          `json:"default_org,omitempty"`
	Telemetry  TelemetryConfig `json:"telemetry,omitempty"`
}

// TelemetryConfig holds the user's opt-in choice for anonymous error
// reports and usage metrics. Default is "not prompted yet, disabled" —
// nothing is sent until the user explicitly opts in.
type TelemetryConfig struct {
	Enabled     bool   `json:"enabled"`
	Prompted    bool   `json:"prompted"`
	PromptedAt  string `json:"prompted_at,omitempty"`
}

// AuthConfig holds CloudBooster authentication metadata.
// The actual tokens are stored in the OS keyring, never on disk.
type AuthConfig struct {
	Email     string `json:"email,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// LLMConfig holds LLM provider credentials.
type LLMConfig struct {
	Providers map[string]LLMProvider `json:"providers,omitempty"`
	Default   string                 `json:"default,omitempty"`
}

// LLMProvider holds metadata for a single LLM provider.
// Secrets are stored in the OS keychain, not in this struct.
type LLMProvider struct {
	Name     string `json:"name"`
	BaseURL  string `json:"base_url,omitempty"`
	Model    string `json:"model,omitempty"`
	LoggedIn bool   `json:"logged_in"`

	// AuthMode records how the provider authenticates. Default ("") and
	// "api-key" both mean a token stored in the OS keychain. "claude-code-cli"
	// means cbx shells out to the local `claude` CLI binary (Claude Code)
	// and reuses its own authentication — no token is stored.
	AuthMode string `json:"auth_mode,omitempty"`
}

const (
	AuthModeAPIKey        = "api-key"
	AuthModeClaudeCodeCLI = "claude-code-cli"
)

// legacyNudgeOnce ensures we only emit the "move ~/.cbx to ~/.config/cbx"
// nudge a single time per process.
var legacyNudgeOnce sync.Once

// LegacyConfigNudge is the sink for the one-time migration suggestion when
// only the legacy ~/.cbx directory exists. Override in tests or to route
// through output.*. Default writes to stderr.
var LegacyConfigNudge = func(legacy, modern string) {
	fmt.Fprintf(os.Stderr,
		"notice: using legacy config dir %s; consider moving it to %s (XDG-compliant)\n",
		legacy, modern)
}

func nudgeLegacyConfigOnce(legacy, modern string) {
	legacyNudgeOnce.Do(func() {
		if LegacyConfigNudge != nil {
			LegacyConfigNudge(legacy, modern)
		}
	})
}

// Dir returns the configuration directory for cbx.
//
// Resolution order:
//  1. $CBX_CONFIG_DIR (explicit override; used by tests + power users)
//  2. Windows: %APPDATA%\cbx (via os.UserConfigDir)
//  3. $XDG_CONFIG_HOME/cbx
//  4. Legacy ~/.cbx when it exists and ~/.config/cbx does not (with a
//     one-time stderr nudge to migrate)
//  5. ~/.config/cbx (default)
func Dir() string {
	if d := os.Getenv("CBX_CONFIG_DIR"); d != "" {
		return d
	}
	if runtime.GOOS == "windows" {
		if d, err := os.UserConfigDir(); err == nil {
			return filepath.Join(d, "cbx")
		}
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "cbx")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	newDir := filepath.Join(home, ".config", "cbx")
	legacyDir := filepath.Join(home, ".cbx")

	// Back-compat: prefer the legacy dir when it exists and the new one
	// doesn't, but emit a one-time nudge so the user migrates eventually.
	// We don't auto-copy to avoid partial-migration risk.
	if _, err := os.Stat(legacyDir); err == nil {
		if _, err2 := os.Stat(newDir); os.IsNotExist(err2) {
			nudgeLegacyConfigOnce(legacyDir, newDir)
			return legacyDir
		}
	}
	return newDir
}

// resetLegacyNudgeForTest clears the one-shot guard. Test-only.
func resetLegacyNudgeForTest() {
	legacyNudgeOnce = sync.Once{}
}

// CacheDir returns the cache directory for cbx.
func CacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".cache", "cb")
}

// Path returns the full path to the config file.
func Path() string {
	return filepath.Join(Dir(), "config.json")
}

// defaultAPIURL is the production CloudBooster API endpoint.
const defaultAPIURL = "https://api.cloudbooster.io"

// Load reads the configuration from disk and applies environment overrides.
func Load() (*Config, error) {
	path := Path()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg := &Config{
				LLM:    LLMConfig{Providers: make(map[string]LLMProvider)},
				APIURL: defaultAPIURL,
			}
			if envURL := Env("API_URL"); envURL != "" {
				cfg.APIURL = envURL
			}
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if cfg.LLM.Providers == nil {
		cfg.LLM.Providers = make(map[string]LLMProvider)
	}
	if cfg.APIURL == "" {
		cfg.APIURL = defaultAPIURL
	}
	if envURL := Env("API_URL"); envURL != "" {
		cfg.APIURL = envURL
	}
	return &cfg, nil
}

// Save persists the configuration to disk.
func Save(cfg *Config) error {
	path := Path()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	return nil
}
