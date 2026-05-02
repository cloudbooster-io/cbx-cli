package llm

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"time"
)

func generateCodeVerifier() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func generateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func openBrowser(url string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		args = []string{url}
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", url}
	default:
		cmd = "xdg-open"
		args = []string{url}
	}
	return exec.Command(cmd, args...).Start()
}

// ClaudeOAuthLogin performs an OAuth PKCE flow for Anthropic.
// It opens the user's browser, starts a local callback server,
// exchanges the authorization code for an access token, and returns it.
func ClaudeOAuthLogin() (string, error) {
	verifier := generateCodeVerifier()
	challenge := generateCodeChallenge(verifier)

	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("starting callback server: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	mux := http.NewServeMux()
	server := &http.Server{Addr: listener.Addr().String(), Handler: mux}

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if errParam := r.URL.Query().Get("error"); errParam != "" {
			errChan <- fmt.Errorf("OAuth error: %s", errParam)
			http.Error(w, "Authorization failed", http.StatusBadRequest)
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			errChan <- fmt.Errorf("no authorization code received")
			http.Error(w, "Missing authorization code", http.StatusBadRequest)
			return
		}
		codeChan <- code
		fmt.Fprint(w, "<html><body><h1>Authorization successful</h1><p>You can close this window.</p></body></html>")
	})

	go server.Serve(listener)
	defer server.Close()

	clientID := os.Getenv("ANTHROPIC_CLIENT_ID")
	if clientID == "" {
		clientID = "cbx-cli"
	}

	authURL := fmt.Sprintf(
		"https://api.anthropic.com/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&code_challenge=%s&code_challenge_method=S256&scope=default",
		url.QueryEscape(clientID),
		url.QueryEscape(redirectURI),
		url.QueryEscape(challenge),
	)

	if err := openBrowser(authURL); err != nil {
		fmt.Fprintf(os.Stderr, "Please open this URL in your browser to authorize:\n%s\n", authURL)
	} else {
		fmt.Fprintln(os.Stderr, "A browser window has been opened for authorization.")
	}

	select {
	case code := <-codeChan:
		return exchangeClaudeToken(code, redirectURI, verifier)
	case err := <-errChan:
		return "", err
	case <-time.After(5 * time.Minute):
		return "", fmt.Errorf("OAuth authorization timed out")
	}
}

func exchangeClaudeToken(code, redirectURI, verifier string) (string, error) {
	clientID := os.Getenv("ANTHROPIC_CLIENT_ID")
	if clientID == "" {
		clientID = "cbx-cli"
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", clientID)
	data.Set("code_verifier", verifier)

	resp, err := http.PostForm("https://api.anthropic.com/oauth/token", data)
	if err != nil {
		return "", fmt.Errorf("exchanging code for token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token exchange failed: HTTP %d", resp.StatusCode)
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("parsing token response: %w", err)
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("no access_token in response")
	}
	return result.AccessToken, nil
}
