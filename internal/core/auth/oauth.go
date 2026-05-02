package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const (
	clientID    = "cbx-cli"
	serviceName = "cloudbooster-cbx"
)

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

// RunPKCEFlow performs the authorization-code + PKCE browser flow.
func RunPKCEFlow(ctx context.Context, cfg *Config) (*ExchangeResult, error) {
	verifier := oauth2.GenerateVerifier()

	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		return nil, fmt.Errorf("generating state: %w", err)
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)

	callbackURL, codeCh, errCh, err := startCallbackServer(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("starting callback server: %w", err)
	}

	ocfg := cfg.oauth2Config(callbackURL)
	authURL := ocfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))

	fmt.Println("Please open the following URL in your browser:")
	fmt.Println(authURL)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-errCh:
		return nil, err
	case code := <-codeCh:
		return exchangeCode(ctx, cfg.APIURL+"/v1/auth/cli/exchange", code, verifier, callbackURL)
	}
}

// RunDeviceFlow performs the OAuth2 device-authorization flow.
func RunDeviceFlow(ctx context.Context, cfg *Config) (*ExchangeResult, error) {
	ocfg := cfg.oauth2Config("")

	da, err := ocfg.DeviceAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("device authorization: %w", err)
	}

	fmt.Printf("Please enter code %s at %s\n", da.UserCode, da.VerificationURI)

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
				http.Error(w, "Invalid state parameter", http.StatusBadRequest)
				select {
				case errCh <- fmt.Errorf("invalid state parameter"):
				default:
				}
				return
			}
			if errParam := q.Get("error"); errParam != "" {
				http.Error(w, fmt.Sprintf("Authorization error: %s", errParam), http.StatusBadRequest)
				select {
				case errCh <- fmt.Errorf("authorization error: %s", errParam):
				default:
				}
				return
			}
			code := q.Get("code")
			if code == "" {
				http.Error(w, "Missing authorization code", http.StatusBadRequest)
				select {
				case errCh <- fmt.Errorf("missing authorization code"):
				default:
				}
				return
			}
			codeCh <- code
			fmt.Fprint(w, "<html><body><h1>Authorization successful</h1><p>You can close this window.</p></body></html>")
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

// httpClient returns an HTTP client with a reasonable timeout for auth requests.
func httpClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

// doTokenRequest posts form data to the token endpoint and parses the response.
func doTokenRequest(ctx context.Context, tokenURL string, data url.Values) (*ExchangeResult, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
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
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	return body.Email, nil
}
