package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	t.Parallel()

	t.Run("version_plain", func(t *testing.T) {
		stdout, _, code := runCBX(t, nil, "version")
		if code != 0 {
			t.Fatalf("version exited %d", code)
		}
		if !strings.Contains(stdout, "cbx version") {
			t.Fatalf("expected version string, got: %s", stdout)
		}
	})

	t.Run("version_json", func(t *testing.T) {
		stdout, _, code := runCBX(t, nil, "version", "--json")
		if code != 0 {
			t.Fatalf("version exited %d", code)
		}
		var out struct {
			Data map[string]string `json:"data"`
		}
		if err := json.Unmarshal([]byte(stdout), &out); err != nil {
			t.Fatalf("expected valid JSON: %v", err)
		}
		if _, ok := out.Data["version"]; !ok {
			t.Fatalf("expected 'version' field in JSON data")
		}
	})
}

func TestDoctor(t *testing.T) {
	t.Parallel()

	// Spin up a local mock API so the test doesn't depend on external connectivity.
	mockAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mockAPI.Close()

	stdout, _, code := runCBX(t, map[string]string{"CB_API_URL": mockAPI.URL}, "doctor")
	if code != 0 {
		t.Fatalf("doctor exited %d", code)
	}
	if !strings.Contains(stdout, "healthy") {
		t.Fatalf("expected healthy message, got: %s", stdout)
	}
	if !strings.Contains(stdout, mockAPI.URL) {
		t.Fatalf("expected doctor output to mention mock API URL %s, got: %s", mockAPI.URL, stdout)
	}
}
