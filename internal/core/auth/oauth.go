package auth

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const (
	clientID    = "cbx-cli"
	serviceName = "cloudbooster-cbx"

	// maxAuthResponseBytes bounds reads of auth-endpoint response bodies.
	// Token and /v1/me payloads are small JSON; 1 MiB is ample headroom
	// while preventing an unbounded allocation from a misbehaving endpoint.
	maxAuthResponseBytes = 1 << 20
)

// UserAgent is sent on every auth-flow HTTP request so the platform can
// render a friendly device label on the Devices panel (e.g.
// “cbx-cli/1.26.2 (darwin/arm64)“). Defaults to a runtime-derived value;
// “main“ overrides it at startup with the ldflags-baked version so
// release builds report their real version instead of the dev placeholder.
var UserAgent = defaultUserAgent("dev")

// SetVersion lets “main“ inject the ldflags-baked CLI version into the
// User-Agent. Call once at startup before any auth call.
func SetVersion(v string) {
	if v == "" {
		return
	}
	UserAgent = defaultUserAgent(v)
}

func defaultUserAgent(version string) string {
	v := strings.TrimPrefix(version, "v")
	if v == "" || v == "(devel)" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			if bi.Main.Version != "" && bi.Main.Version != "(devel)" {
				v = strings.TrimPrefix(bi.Main.Version, "v")
			}
		}
	}
	if v == "" {
		v = "dev"
	}
	return fmt.Sprintf("cbx-cli/%s (%s/%s)", v, runtime.GOOS, runtime.GOARCH)
}

// Config holds OAuth endpoint configuration derived from the CLI config.
type Config struct {
	APIURL string
}

func (c *Config) oauth2Config(redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:    clientID,
		RedirectURL: redirectURL,
		Scopes:      []string{"profile", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:       c.APIURL + "/v1/auth/cli/authorize",
			TokenURL:      c.APIURL + "/v1/auth/cli/exchange",
			DeviceAuthURL: c.APIURL + "/v1/auth/cli/device",
		},
	}
}

// ExchangeResult is returned after a successful token exchange.
type ExchangeResult struct {
	Token *oauth2.Token
	Email string
}

// PKCEOptions configures the authorization-code + PKCE browser flow.
type PKCEOptions struct {
	NoBrowser bool
	Stdin     io.Reader
}

// RunPKCEFlow performs the authorization-code + PKCE browser flow.
func RunPKCEFlow(ctx context.Context, cfg *Config, opts PKCEOptions) (*ExchangeResult, error) {
	verifier := oauth2.GenerateVerifier()

	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return nil, fmt.Errorf("generating state: %w", err)
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	ocfg := cfg.oauth2Config("")

	if opts.NoBrowser {
		// Bind to a local port to get a valid redirect URI, then hold it
		// so no other process can steal the port while the user visits the URL.
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, fmt.Errorf("listen: %w", err)
		}
		defer func() { _ = listener.Close() }()
		port := listener.Addr().(*net.TCPAddr).Port
		redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

		// Hold the port open in the background so the redirect URI remains valid.
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}()

		ocfg.RedirectURL = redirectURI
		authURL := ocfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))

		fmt.Fprintln(os.Stderr, "Please open the following URL in your browser:")
		fmt.Fprintln(os.Stderr, authURL)
		fmt.Fprintln(os.Stderr)
		fmt.Fprint(os.Stderr, "Paste the authorization code here: ")

		stdin := opts.Stdin
		if stdin == nil {
			stdin = os.Stdin
		}

		var code string
		scanner := bufio.NewScanner(stdin)
		if scanner.Scan() {
			code = strings.TrimSpace(scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("reading code: %w", err)
		}
		if code == "" {
			return nil, fmt.Errorf("no authorization code provided")
		}

		// User may paste the full callback URL; extract the code.
		if strings.HasPrefix(code, "http") {
			if u, err := url.Parse(code); err == nil {
				if q := u.Query().Get("code"); q != "" {
					code = q
				}
			}
		}

		return exchangeCode(ctx, cfg.APIURL+"/v1/auth/cli/exchange", code, verifier, redirectURI)
	}

	// Browser mode: start callback server and open browser.
	callbackURL, codeCh, errCh, err := startCallbackServer(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("starting callback server: %w", err)
	}

	ocfg.RedirectURL = callbackURL
	authURL := ocfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))

	if err := openBrowser(authURL); err != nil {
		fmt.Fprintln(os.Stderr, "Could not open browser. Please open the following URL manually:")
		fmt.Fprintln(os.Stderr, authURL)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-errCh:
		return nil, err
	case code := <-codeCh:
		return exchangeCode(ctx, cfg.APIURL+"/v1/auth/cli/exchange", code, verifier, callbackURL)
	}
}

// openBrowser attempts to open url in the user's default browser.
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

// RunDeviceFlow performs the OAuth2 device-authorization flow.
func RunDeviceFlow(ctx context.Context, cfg *Config) (*ExchangeResult, error) {
	ocfg := cfg.oauth2Config("")

	da, err := ocfg.DeviceAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("device authorization: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Please enter code %s at %s\n", da.UserCode, da.VerificationURI)

	token, err := ocfg.DeviceAccessToken(ctx, da)
	if err != nil {
		return nil, fmt.Errorf("device access token: %w", err)
	}

	email, _ := fetchEmail(ctx, cfg.APIURL, token)
	return &ExchangeResult{Token: token, Email: email}, nil
}

// startCallbackServer binds a single-use HTTP server to 127.0.0.1:0.
func startCallbackServer(ctx context.Context, state string) (callbackURL string, codeCh chan string, errCh chan error, err error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, nil, fmt.Errorf("listen: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	callbackURL = fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	codeCh = make(chan string, 1)
	errCh = make(chan error, 1)

	mux := http.NewServeMux()
	srv := &http.Server{
		Addr:    listener.Addr().String(),
		Handler: mux,
	}

	var once sync.Once
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() {
			q := r.URL.Query()
			if q.Get("state") != state {
				writeCallbackPage(w, http.StatusBadRequest, false, "Invalid state parameter", "Your session may have expired or been tampered with. Run cbx login again from your terminal.")
				select {
				case errCh <- fmt.Errorf("invalid state parameter"):
				default:
				}
				return
			}
			if errParam := q.Get("error"); errParam != "" {
				writeCallbackPage(w, http.StatusBadRequest, false, "Authorization denied", fmt.Sprintf("The identity provider returned: %s", errParam))
				select {
				case errCh <- fmt.Errorf("authorization error: %s", errParam):
				default:
				}
				return
			}
			code := q.Get("code")
			if code == "" {
				writeCallbackPage(w, http.StatusBadRequest, false, "Missing authorization code", "The callback did not include an authorization code. Run cbx login again to retry.")
				select {
				case errCh <- fmt.Errorf("missing authorization code"):
				default:
				}
				return
			}
			codeCh <- code
			writeCallbackPage(w, http.StatusOK, true, "You're signed in", "Return to your terminal to continue. This window can be closed.")
			go func() {
				time.Sleep(100 * time.Millisecond)
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = srv.Shutdown(shutdownCtx)
			}()
		})
	})

	go func() {
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			select {
			case errCh <- err:
			default:
			}
		}
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	return callbackURL, codeCh, errCh, nil
}

// exchangeCode exchanges an authorization code for tokens using PKCE.
func exchangeCode(ctx context.Context, tokenURL, code, verifier, redirectURL string) (*ExchangeResult, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURL)
	data.Set("client_id", clientID)
	data.Set("code_verifier", verifier)

	return doTokenRequest(ctx, tokenURL, data)
}

// httpClient returns an HTTP client with a reasonable timeout for auth
// requests AND a User-Agent-injecting transport. The transport ensures
// every subsequent call (including the ones made by oauth2.NewClient's
// token-source wrapper for /v1/me and similar) carries the cbx-cli UA
// so the platform can surface a friendly device label.
func httpClient() *http.Client {
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &userAgentTransport{base: http.DefaultTransport},
	}
}

// userAgentTransport stamps User-Agent on outgoing requests when the
// caller hasn't already set one. Wraps an underlying RoundTripper so it
// composes cleanly with oauth2.Transport (which only adds Authorization).
type userAgentTransport struct {
	base http.RoundTripper
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		// Clone so we don't mutate the caller's request when retried.
		req = req.Clone(req.Context())
		req.Header.Set("User-Agent", UserAgent)
	}
	rt := t.base
	if rt == nil {
		rt = http.DefaultTransport
	}
	return rt.RoundTrip(req)
}

// doTokenRequest posts form data to the token endpoint and parses the response.
func doTokenRequest(ctx context.Context, tokenURL string, data url.Values) (*ExchangeResult, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)

	resp, err := httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAuthResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Email        string `json:"email"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}

	token := &oauth2.Token{
		AccessToken:  result.AccessToken,
		TokenType:    result.TokenType,
		RefreshToken: result.RefreshToken,
	}
	if result.ExpiresIn > 0 {
		token.Expiry = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	}

	return &ExchangeResult{Token: token, Email: result.Email}, nil
}

// fetchEmail attempts to retrieve the user's email from the platform API.
func fetchEmail(ctx context.Context, apiURL string, token *oauth2.Token) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL+"/v1/me", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)

	resp, err := httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAuthResponseBytes)).Decode(&body); err != nil {
		return "", err
	}
	return body.Email, nil
}

// writeCallbackPage renders the OAuth landing page shown in the user's
// browser after they return from the identity provider. Both success and
// error paths share the same shell so the experience feels intentional.
func writeCallbackPage(w http.ResponseWriter, status int, ok bool, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)

	accent := "#22d3ee"
	icon := `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.25" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>`
	if !ok {
		accent = "#f87171"
		icon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.25" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"/></svg>`
	}

	esc := func(s string) string {
		r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
		return r.Replace(s)
	}

	fmt.Fprintf(w, `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>%s · CloudBooster</title>
<style>
  :root { color-scheme: dark light; }
  * { box-sizing: border-box; }
  html, body { height: 100%%; margin: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    background: radial-gradient(1200px 600px at 50%% -10%%, rgba(34,211,238,0.18), transparent 60%%),
                radial-gradient(900px 500px at 80%% 110%%, rgba(99,102,241,0.18), transparent 60%%),
                #0b0f17;
    color: #e6edf3;
    display: grid;
    place-items: center;
    padding: 24px;
  }
  .card {
    width: 100%%;
    max-width: 440px;
    background: rgba(17, 24, 39, 0.72);
    border: 1px solid rgba(148, 163, 184, 0.15);
    border-radius: 16px;
    padding: 36px 32px 28px;
    backdrop-filter: blur(12px);
    box-shadow: 0 30px 80px -30px rgba(0,0,0,0.6);
    text-align: center;
  }
  .icon {
    width: 56px;
    height: 56px;
    border-radius: 999px;
    display: inline-grid;
    place-items: center;
    background: color-mix(in srgb, %s 18%%, transparent);
    color: %s;
    margin-bottom: 18px;
  }
  .icon svg { width: 28px; height: 28px; }
  h1 {
    font-size: 22px;
    line-height: 1.25;
    margin: 0 0 8px;
    letter-spacing: -0.01em;
  }
  p {
    margin: 0;
    color: #9ca3af;
    font-size: 14.5px;
    line-height: 1.55;
  }
  .brand {
    margin-top: 28px;
    font-size: 12px;
    letter-spacing: 0.14em;
    text-transform: uppercase;
    color: #6b7280;
  }
  .brand span { color: #e6edf3; font-weight: 600; letter-spacing: 0.06em; }
  @media (prefers-color-scheme: light) {
    body { background: #f8fafc; color: #0f172a; }
    .card { background: #ffffff; border-color: rgba(15,23,42,0.08); box-shadow: 0 20px 50px -20px rgba(15,23,42,0.15); }
    p { color: #475569; }
    .brand { color: #94a3b8; }
    .brand span { color: #0f172a; }
  }
</style>
</head>
<body>
  <main class="card" role="status" aria-live="polite">
    <div class="icon" style="color: %s; background: color-mix(in srgb, %s 18%%, transparent);">%s</div>
    <h1>%s</h1>
    <p>%s</p>
    <div class="brand"><span>CloudBooster</span> &middot; cbx CLI</div>
  </main>
</body>
</html>`, esc(title), accent, accent, accent, accent, icon, esc(title), esc(message))
}
