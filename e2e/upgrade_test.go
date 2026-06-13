package e2e

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestUpgrade(t *testing.T) {
	t.Parallel()

	t.Run("upgrade_dev_build", func(t *testing.T) {
		// The E2E binary is built without ldflags, so version == "dev".
		stdout, _, code := runCBX(t, nil, "upgrade")
		if code != 0 {
			t.Fatalf("upgrade exited %d", code)
		}
		if !strings.Contains(stdout, "cannot upgrade development build") {
			t.Fatalf("expected dev build message, got: %s", stdout)
		}
	})

	t.Run("upgrade_dev_build_json", func(t *testing.T) {
		stdout, _, code := runCBX(t, nil, "upgrade", "--json")
		if code != 0 {
			t.Fatalf("upgrade exited %d", code)
		}
		var envelope struct {
			Data map[string]interface{} `json:"data"`
		}
		if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
			t.Fatalf("expected valid JSON: %v\noutput: %s", err, stdout)
		}
		msg, ok := envelope.Data["message"].(string)
		if !ok || !strings.Contains(msg, "development build") {
			t.Fatalf("expected development build message in JSON, got: %v", envelope.Data)
		}
	})

	t.Run("upgrade_dry_run", func(t *testing.T) {
		stdout, _, code := runCBX(t, nil, "upgrade", "--dry-run")
		if code != 0 {
			t.Fatalf("upgrade exited %d", code)
		}
		if !strings.Contains(stdout, "cannot upgrade development build") {
			t.Fatalf("expected dev build message for dry-run, got: %s", stdout)
		}
	})
}
