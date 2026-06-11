// Package config re-exports the CLI configuration primitives so that
// downstream modules (e.g. downstream consumers) can load and save config without
// reaching into cbx-cli/internal.
package config

import (
	"github.com/cloudbooster-io/cbx-cli/internal/config"
)

// Config holds the CLI configuration.
type Config = config.Config

// AuthConfig holds CloudBooster authentication metadata.
type AuthConfig = config.AuthConfig

// LLMConfig holds LLM provider credentials.
type LLMConfig = config.LLMConfig

// LLMProvider holds metadata for a single LLM provider.
type LLMProvider = config.LLMProvider

// Dir returns the configuration directory for cbx.
var Dir = config.Dir

// CacheDir returns the cache directory for cbx.
var CacheDir = config.CacheDir

// Load reads the configuration file.
var Load = config.Load

// Save writes the configuration file.
var Save = config.Save
