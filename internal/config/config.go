package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config holds the CLI configuration.
type Config struct {
	Auth       AuthConfig            `json:"auth,omitempty"`
	LLM        LLMConfig             `json:"llm,omitempty"`
	APIURL     string                `json:"api_url,omitempty"`
	DefaultOrg string                `json:"default_org,omitempty"`
}

// AuthConfig holds CloudBooster authentication state.
type AuthConfig struct {
	Token     string `json:"token,omitempty"`
	Email     string `json:"email,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// LLMConfig holds LLM provider credentials.
type LLMConfig struct {
	Providers map[string]LLMProvider `json:"providers,omitempty"`
	Default   string                 `json:"default,omitempty"`
}

// LLMProvider holds credentials for a single LLM provider.
type LLMProvider struct {
	Name      string `json:"name"`
	APIKey    string `json:"api_key,omitempty"`
	BaseURL   string `json:"base_url,omitempty"`
	Model     string `json:"model,omitempty"`
	LoggedIn  bool   `json:"logged_in"`
}

// Dir returns the configuration directory for cbx.
func Dir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".cbx")
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
			if envURL := os.Getenv("CB_API_URL"); envURL != "" {
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
	if envURL := os.Getenv("CB_API_URL"); envURL != "" {
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
