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
		if !strings.Contains(stdout, "build:") {
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

	env := map[string]string{"CB_API_URL": mockAPI.URL}

	t.Run("doctor_plain", func(t *testing.T) {
		stdout, stderr, code := runCBX(t, env, "doctor")
		// Doctor may exit non-zero when some checks fail in the test environment.
		_ = code
		if !strings.Contains(stdout, "cbx version") {
			t.Fatalf("expected cbx version check, got: %s\nstderr:\n%s", stdout, stderr)
		}
		if !strings.Contains(stdout, "API connectivity") {
			t.Fatalf("expected API connectivity check, got: %s\nstderr:\n%s", stdout, stderr)
		}
		if !strings.Contains(stdout, mockAPI.URL) {
			t.Fatalf("expected doctor output to mention mock API URL %s, got: %s\nstderr:\n%s", mockAPI.URL, stdout, stderr)
		}
	})

	t.Run("doctor_json", func(t *testing.T) {
		stdout, stderr, code := runCBX(t, env, "doctor", "--json")
		_ = code
		var envelope struct {
			Data struct {
				Healthy bool `json:"healthy"`
				Checks  []struct {
					Name string `json:"name"`
					OK   bool   `json:"ok"`
					Info string `json:"info"`
				} `json:"checks"`
			} `json:"data"`
		}
		if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
			t.Fatalf("expected valid JSON: %v\noutput: %s\nstderr:\n%s", err, stdout, stderr)
		}
		report := envelope.Data
		if len(report.Checks) == 0 {
			t.Fatal("expected at least one check in JSON report")
		}
		foundAPI := false
		for _, c := range report.Checks {
			if c.Name == "API connectivity" {
				foundAPI = true
				if !strings.Contains(c.Info, mockAPI.URL) {
					t.Fatalf("expected API info to contain %s, got %s", mockAPI.URL, c.Info)
				}
			}
		}
		if !foundAPI {
			t.Fatal("expected API connectivity check in JSON")
		}
	})
}
