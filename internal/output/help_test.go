package output

import (
	"strings"
	"testing"
)

func TestHelpTemplate(t *testing.T) {
	tmpl := HelpTemplate()
	if tmpl == "" {
		t.Fatal("HelpTemplate() returned empty string")
	}
	if !strings.Contains(tmpl, "USAGE") {
		t.Fatal("HelpTemplate() missing USAGE section")
	}
	if !strings.Contains(tmpl, "LEARN MORE") {
		t.Fatal("HelpTemplate() missing LEARN MORE section")
	}
	if !strings.Contains(tmpl, "docs.cloudbooster.io") {
		t.Fatal("HelpTemplate() missing docs.cloudbooster.io link")
	}
}

func TestUsageTemplate(t *testing.T) {
	if UsageTemplate() != HelpTemplate() {
		t.Fatal("UsageTemplate() should match HelpTemplate()")
	}
}
