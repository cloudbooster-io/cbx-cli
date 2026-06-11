package auth_test

// Smoke test for the pkg/auth facade, modeled on pkg/audit/audit_test.go.
// downstream consumers depend on these type aliases and function vars
// resolving to the same symbols internal/core/auth exposes; if a
// re-export is renamed or dropped this test fails at compile time
// rather than silently breaking downstream consumers at import.

import (
	"reflect"
	"testing"

	internalauth "github.com/cloudbooster-io/cbx-cli/internal/core/auth"
	pkgauth "github.com/cloudbooster-io/cbx-cli/pkg/auth"
)

func TestFacade_TypeAliasesIdentical(t *testing.T) {
	// Keyring is an interface — the inner-to-outer conversion only
	// compiles while the internal contract still satisfies the
	// facade's.
	_ = pkgauth.Keyring(internalauth.Keyring(nil))
}

func TestFacade_FuncReexportsIdentical(t *testing.T) {
	// Function vars compare by underlying code pointer — a facade var
	// rewired away from its internal counterpart fails here.
	pairs := []struct {
		name             string
		facade, internal any
	}{
		{"NewKeyring", pkgauth.NewKeyring, internalauth.NewKeyring},
		{"LoadToken", pkgauth.LoadToken, internalauth.LoadToken},
		{"AccessToken", pkgauth.AccessToken, internalauth.AccessToken},
		{"IsAuthenticated", pkgauth.IsAuthenticated, internalauth.IsAuthenticated},
	}
	for _, p := range pairs {
		if reflect.ValueOf(p.facade).Pointer() != reflect.ValueOf(p.internal).Pointer() {
			t.Errorf("facade.%s does not resolve to internal/core/auth.%s", p.name, p.name)
		}
	}
}
