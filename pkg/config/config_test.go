package config_test

// Smoke test for the pkg/config facade, modeled on pkg/audit/audit_test.go.
// downstream consumers depend on these type aliases and function vars
// resolving to the same symbols internal/config exposes; if a
// re-export is renamed or dropped this test fails at compile time
// rather than silently breaking downstream consumers at import.

import (
	"reflect"
	"testing"

	internalconfig "github.com/cloudbooster-io/cbx-cli/internal/config"
	pkgconfig "github.com/cloudbooster-io/cbx-cli/pkg/config"
)

func TestFacade_TypeAliasesIdentical(t *testing.T) {
	// Type aliases are compile-time equivalent — each conversion below
	// only compiles while the facade alias still resolves to its
	// internal counterpart.
	var (
		_ = pkgconfig.Config(internalconfig.Config{})
		_ = pkgconfig.AuthConfig(internalconfig.AuthConfig{})
		_ = pkgconfig.LLMConfig(internalconfig.LLMConfig{})
		_ = pkgconfig.LLMProvider(internalconfig.LLMProvider{})
	)
}

func TestFacade_FuncReexportsIdentical(t *testing.T) {
	// Function vars compare by underlying code pointer — a facade var
	// rewired away from its internal counterpart fails here.
	pairs := []struct {
		name             string
		facade, internal any
	}{
		{"Dir", pkgconfig.Dir, internalconfig.Dir},
		{"CacheDir", pkgconfig.CacheDir, internalconfig.CacheDir},
		{"Load", pkgconfig.Load, internalconfig.Load},
		{"Save", pkgconfig.Save, internalconfig.Save},
	}
	for _, p := range pairs {
		if reflect.ValueOf(p.facade).Pointer() != reflect.ValueOf(p.internal).Pointer() {
			t.Errorf("facade.%s does not resolve to internal/config.%s", p.name, p.name)
		}
	}
}
