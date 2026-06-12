package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// Config holds the CLI configuration.
type Config struct {
	Auth       AuthConfig      `json:"auth,omitempty"`
	LLM        LLMConfig       `json:"llm,omitempty"`
	APIURL     string          `json:"api_url,omitempty"`
	DefaultOrg string          `json:"default_org,omitempty"`
	AWS        AWSConfig       `json:"aws,omitempty"`
	Telemetry  TelemetryConfig `json:"telemetry,omitempty"`
}

// AWSConfig holds AWS-specific defaults shared by `cbx audit aws` and
// other AWS-touching subcommands. None are required; all fall back to
// either the AWS SDK profile or interactive prompting.
type AWSConfig struct {
	// DefaultRegion is used by `cbx audit aws` when --region is not
	// passed, the positional console-URL does not carry a region, and
	// the AWS profile itself has no region set.
	DefaultRegion string `json:"default_region,omitempty"`
}

// TelemetryConfig holds the user's opt-in choice for anonymous error
// reports and usage metrics. Default is "not prompted yet, disabled" —
// nothing is sent until the user explicitly opts in.
type TelemetryConfig struct {
	Enabled    bool   `json:"enabled"`
	Prompted   bool   `json:"prompted"`
	PromptedAt string `json:"prompted_at,omitempty"`
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
	// ModelPinned is true when Model was deliberately set via `cbx llm
	// model` (vs seeded by a login default). Load-bearing for names that
	// are both an api provider and a CLI executor (codex): only a pinned
	// model is passed to the local CLI as --model.
	ModelPinned bool `json:"model_pinned,omitempty"`
	LoggedIn    bool `json:"logged_in"`

	// AuthMode records how the provider authenticates. Default ("") and
	// "api-key" both mean a token stored in the OS keychain. "claude-code-cli"
	// means cbx shells out to the local `claude` CLI binary (Claude Code)
	// and reuses its own authentication — no token is stored.
	AuthMode string `json:"auth_mode,omitempty"`
}

const (
	AuthModeAPIKey        = "api-key"
	AuthModeClaudeCodeCLI = "claude-code-cli"
	// AuthModeCLIExecutor marks an entry that exists only to carry
	// per-executor settings (currently the model override set via
	// `cbx llm model`) for a local CLI executor. No token is stored;
	// the CLI owns its own auth.
	AuthModeCLIExecutor = "cli-executor"
)

// legacyNudgeOnce ensures we only emit the "move ~/.cbx to ~/.config/cbx"
// nudge a single time per process. Combined with the on-disk sentinel
// (see legacyNudgeSentinelName) this also keeps the nudge from firing
// across processes — without that, every cbx invocation would re-emit it
// because each process is fresh.
var legacyNudgeOnce sync.Once

// legacyNudgeSentinelName is the marker file written inside the legacy
// config dir after the first nudge. Subsequent processes that find the
// sentinel skip the nudge entirely. We park it inside the legacy dir
// (not the XDG newDir) on purpose: creating newDir as an empty directory
// would flip Dir()'s "prefer legacy" branch and silently orphan the
// user's existing config.json.
const legacyNudgeSentinelName = ".legacy-nudged"

// LegacyConfigNudge is the sink for the one-time migration suggestion when
// only the legacy ~/.cbx directory exists. Override in tests or to route
// through output.*. Default writes to stderr.
var LegacyConfigNudge = func(legacy, modern string) {
	fmt.Fprintf(os.Stderr,
		"notice: using legacy config dir %s; consider moving it to %s (XDG-compliant)\n",
		legacy, modern)
}

func nudgeLegacyConfigOnce(legacy, modern string) {
	sentinel := filepath.Join(legacy, legacyNudgeSentinelName)
	if _, err := os.Stat(sentinel); err == nil {
		// Already nudged in a prior process — stay silent.
		return
	}
	legacyNudgeOnce.Do(func() {
		if LegacyConfigNudge != nil {
			LegacyConfigNudge(legacy, modern)
		}
		// Best-effort sentinel write; failure to persist just means the
		// next process re-nudges (annoying but not broken).
		_ = os.WriteFile(sentinel, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
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
	migrateRetiredModels(&cfg)
	if cfg.APIURL == "" {
		cfg.APIURL = defaultAPIURL
	}
	if envURL := Env("API_URL"); envURL != "" {
		cfg.APIURL = envURL
	}
	return &cfg, nil
}

// retiredModelReplacements maps model IDs that the upstream provider has
// retired (requests 404) to their current replacement. Applied in-memory on
// every Load so a stale stored model never reaches an API call; the stored
// file is rewritten on the next Save. These entries were written by `cbx llm
// api login` defaults of earlier cbx versions, not chosen by the user.
var retiredModelReplacements = map[string]string{
	// Claude Sonnet 4 retires 2026-06-15.
	"claude-sonnet-4-20250514": "claude-sonnet-4-6",
}

// migrateRetiredModels swaps retired model IDs in the provider map for their
// current replacements.
func migrateRetiredModels(cfg *Config) {
	for name, p := range cfg.LLM.Providers {
		if repl, ok := retiredModelReplacements[p.Model]; ok {
			p.Model = repl
			cfg.LLM.Providers[name] = p
		}
	}
}

// Save persists the configuration to disk. The write is atomic
// (temp file + rename in the same directory): a truncate-in-place write
// would let a concurrent Load in another cbx process observe a partially
// written file and fail on invalid JSON.
func Save(cfg *Config) error {
	path := Path()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op once renamed
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing config: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	return nil
}
