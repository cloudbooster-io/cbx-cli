package output_test

// Smoke test for the pkg/output facade, modeled on pkg/audit/audit_test.go.
// downstream consumers depend on these type aliases and var re-exports
// resolving to the same symbols internal/output exposes; if a
// re-export is renamed or dropped this test fails at compile time
// rather than silently breaking downstream consumers at import.

import (
	"reflect"
	"testing"

	internaloutput "github.com/cloudbooster-io/cbx-cli/internal/output"
	pkgoutput "github.com/cloudbooster-io/cbx-cli/pkg/output"
)

func TestFacade_TypeAliasesIdentical(t *testing.T) {
	// Type aliases are compile-time equivalent — each conversion below
	// only compiles while the facade alias still resolves to its
	// internal counterpart. Spinner embeds a mutex, so its alias is
	// asserted via pointer conversion instead of a value copy
	// (go vet copylocks).
	var (
		_ = pkgoutput.Envelope(internaloutput.Envelope{})
		_ = pkgoutput.ErrDetail(internaloutput.ErrDetail{})
		_ = (*pkgoutput.Spinner)((*internaloutput.Spinner)(nil))
	)
}

func TestFacade_FuncReexportsIdentical(t *testing.T) {
	// Function vars compare by underlying code pointer — a facade var
	// rewired away from its internal counterpart fails here.
	pairs := []struct {
		name             string
		facade, internal any
	}{
		{"WriteJSON", pkgoutput.WriteJSON, internaloutput.WriteJSON},
		{"PrintJSON", pkgoutput.PrintJSON, internaloutput.PrintJSON},
		{"JSONError", pkgoutput.JSONError, internaloutput.JSONError},
		{"JSONErrorf", pkgoutput.JSONErrorf, internaloutput.JSONErrorf},
		{"NewSpinner", pkgoutput.NewSpinner, internaloutput.NewSpinner},
		{"Configure", pkgoutput.Configure, internaloutput.Configure},
		{"Enabled", pkgoutput.Enabled, internaloutput.Enabled},
		{"IsQuiet", pkgoutput.IsQuiet, internaloutput.IsQuiet},
	}
	for _, p := range pairs {
		if reflect.ValueOf(p.facade).Pointer() != reflect.ValueOf(p.internal).Pointer() {
			t.Errorf("facade.%s does not resolve to internal/output.%s", p.name, p.name)
		}
	}
}

func TestFacade_StyleReexportsIdentical(t *testing.T) {
	// Success / Warning / Error / Info / Dim are lipgloss.Style values
	// copied at facade init — DeepEqual catches a re-export wired to
	// the wrong style. (Configure reassigns the internal vars, so this
	// test must not call it before comparing.)
	pairs := []struct {
		name             string
		facade, internal any
	}{
		{"Success", pkgoutput.Success, internaloutput.Success},
		{"Warning", pkgoutput.Warning, internaloutput.Warning},
		{"Error", pkgoutput.Error, internaloutput.Error},
		{"Info", pkgoutput.Info, internaloutput.Info},
		{"Dim", pkgoutput.Dim, internaloutput.Dim},
	}
	for _, p := range pairs {
		if !reflect.DeepEqual(p.facade, p.internal) {
			t.Errorf("facade.%s does not match internal/output.%s", p.name, p.name)
		}
	}
}
