package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestPKCEExchange(t *testing.T) {
	var receivedVerifier string
	var receivedCode string

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	mux.HandleFunc("/v1/auth/cli/exchange", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		receivedVerifier = r.FormValue("code_verifier")
		receivedCode = r.FormValue("code")

		resp := map[string]interface{}{
			"access_token":  "test-access-token",
			"token_type":    "Bearer",
			"refresh_token": "test-refresh-token",
			"expires_in":    3600,
			"email":         "alice@example.com",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	result, err := exchangeCode(context.Background(), server.URL+"/v1/auth/cli/exchange", "auth-code-123", "verifier-xyz", "http://127.0.0.1:9999/callback")
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}

	if receivedCode != "auth-code-123" {
		t.Fatalf("expected code auth-code-123, got %q", receivedCode)
	}
	if receivedVerifier != "verifier-xyz" {
		t.Fatalf("expected verifier verifier-xyz, got %q", receivedVerifier)
	}
	if result.Token.AccessToken != "test-access-token" {
		t.Fatalf("expected access token test-access-token, got %q", result.Token.AccessToken)
	}
	if result.Email != "alice@example.com" {
		t.Fatalf("expected email alice@example.com, got %q", result.Email)
	}
}

func TestPKCEExchangeTamperedVerifier(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	mux.HandleFunc("/v1/auth/cli/exchange", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		verifier := r.FormValue("code_verifier")
		if verifier != "correct-verifier" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_grant",
				"error_description": "invalid code verifier",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "ok"})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Correct verifier should succeed.
	_, err := exchangeCode(ctx, server.URL+"/v1/auth/cli/exchange", "code", "correct-verifier", "http://127.0.0.1:9999/callback")
	if err != nil {
		t.Fatalf("correct verifier should succeed: %v", err)
	}

	// Tampered verifier should fail.
	_, err = exchangeCode(ctx, server.URL+"/v1/auth/cli/exchange", "code", "tampered-verifier", "http://127.0.0.1:9999/callback")
	if err == nil {
		t.Fatal("tampered verifier should be rejected")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Fatalf("expected HTTP 400 error, got: %v", err)
	}
}

func TestDeviceFlow(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	mux.HandleFunc("/v1/auth/cli/device", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"device_code":               "device-123",
			"user_code":                 "ABCD-EFGH",
			"verification_uri":          server.URL + "/verify",
			"verification_uri_complete": server.URL + "/verify?user_code=ABCD-EFGH",
			"expires_in":                600,
			"interval":                  1,
		})
	})

	mux.HandleFunc("/v1/auth/cli/exchange", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "device-access-token",
			"token_type":    "Bearer",
			"refresh_token": "device-refresh-token",
			"expires_in":    3600,
		})
	})

	cfg := &Config{APIURL: server.URL}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := RunDeviceFlow(ctx, cfg)
	if err != nil {
		t.Fatalf("device flow failed: %v", err)
	}
	if result.Token.AccessToken != "device-access-token" {
		t.Fatalf("expected access token device-access-token, got %q", result.Token.AccessToken)
	}
}

func TestCallbackServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	callbackURL, codeCh, errCh, err := startCallbackServer(ctx, "test-state")
	if err != nil {
		t.Fatalf("start callback server: %v", err)
	}

	// Verify it binds to 127.0.0.1
	u, err := url.Parse(callbackURL)
	if err != nil {
		t.Fatalf("parse callback URL: %v", err)
	}
	if u.Hostname() != "127.0.0.1" {
		t.Fatalf("expected hostname 127.0.0.1, got %q", u.Hostname())
	}

	// Simulate the authorization server redirecting back.
	go func() {
		q := url.Values{}
		q.Set("code", "my-code")
		q.Set("state", "test-state")
		resp, err := http.Get(callbackURL + "?" + q.Encode())
		if err != nil {
			t.Logf("callback GET error: %v", err)
			return
		}
		_ = resp.Body.Close()
	}()

	select {
	case code := <-codeCh:
		if code != "my-code" {
			t.Fatalf("expected code my-code, got %q", code)
		}
	case err := <-errCh:
		t.Fatalf("unexpected error: %v", err)
	case <-ctx.Done():
		t.Fatal("timeout waiting for callback")
	}
}

func TestCallbackServerInvalidState(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	callbackURL, codeCh, errCh, err := startCallbackServer(ctx, "real-state")
	if err != nil {
		t.Fatalf("start callback server: %v", err)
	}

	go func() {
		q := url.Values{}
		q.Set("code", "my-code")
		q.Set("state", "wrong-state")
		resp, err := http.Get(callbackURL + "?" + q.Encode())
		if err != nil {
			t.Logf("callback GET error: %v", err)
			return
		}
		_ = resp.Body.Close()
	}()

	select {
	case <-codeCh:
		t.Fatal("should not receive code with invalid state")
	case err := <-errCh:
		if !strings.Contains(err.Error(), "invalid state") {
			t.Fatalf("expected invalid state error, got: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("timeout waiting for error")
	}
}

func TestAuthenticatedClient(t *testing.T) {
	mockKeyring := &mockKeyring{data: make(map[string]string)}
	token := &oauth2.Token{
		AccessToken:  "access-123",
		TokenType:    "Bearer",
		RefreshToken: "refresh-123",
		Expiry:       time.Now().Add(time.Hour),
	}
	if err := SaveToken(mockKeyring, token); err != nil {
		t.Fatalf("save token: %v", err)
	}

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	var authHeader string
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})

	client, err := AuthenticatedClient(context.Background(), server.URL, mockKeyring)
	if err != nil {
		t.Fatalf("authenticated client: %v", err)
	}

	resp, err := client.Get(server.URL + "/api")
	if err != nil {
		t.Fatalf("GET /api: %v", err)
	}
	_ = resp.Body.Close()

	if authHeader != "Bearer access-123" {
		t.Fatalf("expected Authorization header 'Bearer access-123', got %q", authHeader)
	}
}

func TestSavingTokenSourcePersistsRefreshedToken(t *testing.T) {
	mockKeyring := &mockKeyring{data: make(map[string]string)}
	initial := &oauth2.Token{
		AccessToken:  "old",
		RefreshToken: "refresh-123",
		Expiry:       time.Now().Add(-time.Hour), // expired
	}
	if err := SaveToken(mockKeyring, initial); err != nil {
		t.Fatalf("save token: %v", err)
	}

	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	mux.HandleFunc("/v1/auth/cli/exchange", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "new-access",
			"token_type":    "Bearer",
			"refresh_token": "new-refresh",
			"expires_in":    3600,
		})
	})

	ocfg := (&Config{APIURL: server.URL}).oauth2Config("")
	base := ocfg.TokenSource(context.Background(), initial)
	ts := &savingTokenSource{base: base, kr: mockKeyring}

	tok, err := ts.Token()
	if err != nil {
		t.Fatalf("token refresh: %v", err)
	}
	if tok.AccessToken != "new-access" {
		t.Fatalf("expected new access token, got %q", tok.AccessToken)
	}

	stored, err := LoadToken(mockKeyring)
	if err != nil {
		t.Fatalf("load stored token: %v", err)
	}
	if stored.AccessToken != "new-access" {
		t.Fatalf("expected persisted access token new-access, got %q", stored.AccessToken)
	}
}

func TestPKCENoBrowser(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	var receivedVerifier string
	var receivedCode string

	mux.HandleFunc("/v1/auth/cli/exchange", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		receivedVerifier = r.FormValue("code_verifier")
		receivedCode = r.FormValue("code")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"email":        "bob@example.com",
		})
	})

	cfg := &Config{APIURL: server.URL}
	stdin := strings.NewReader("auth-code-123\n")

	result, err := RunPKCEFlow(context.Background(), cfg, PKCEOptions{NoBrowser: true, Stdin: stdin})
	if err != nil {
		t.Fatalf("no-browser flow failed: %v", err)
	}
	if result.Token.AccessToken != "test-token" {
		t.Fatalf("expected test-token, got %q", result.Token.AccessToken)
	}
	if result.Email != "bob@example.com" {
		t.Fatalf("expected bob@example.com, got %q", result.Email)
	}
	if receivedCode != "auth-code-123" {
		t.Fatalf("expected code auth-code-123, got %q", receivedCode)
	}
	if receivedVerifier == "" {
		t.Fatal("expected code_verifier to be sent")
	}
}

func TestPKCENoBrowserPastesURL(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()

	var receivedCode string
	mux.HandleFunc("/v1/auth/cli/exchange", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		receivedCode = r.FormValue("code")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	cfg := &Config{APIURL: server.URL}
	// User pastes the full callback URL instead of just the code.
	stdin := strings.NewReader("http://127.0.0.1:12345/callback?code=url-code-456&state=xyz\n")

	result, err := RunPKCEFlow(context.Background(), cfg, PKCEOptions{NoBrowser: true, Stdin: stdin})
	if err != nil {
		t.Fatalf("no-browser flow failed: %v", err)
	}
	if result.Token.AccessToken != "test-token" {
		t.Fatalf("expected test-token, got %q", result.Token.AccessToken)
	}
	if receivedCode != "url-code-456" {
		t.Fatalf("expected code url-code-456 to be extracted from URL, got %q", receivedCode)
	}
}

// mockKeyring is an in-memory keyring for testing.
type mockKeyring struct {
	data map[string]string
}

func (m *mockKeyring) Store(key, secret string) error {
	m.data[key] = secret
	return nil
}

func (m *mockKeyring) Retrieve(key string) (string, error) {
	v, ok := m.data[key]
	if !ok {
		return "", fmt.Errorf("not found")
	}
	return v, nil
}

func (m *mockKeyring) Delete(key string) error {
	delete(m.data, key)
	return nil
}

func (m *mockKeyring) Has(key string) (bool, error) {
	_, ok := m.data[key]
	return ok, nil
}
