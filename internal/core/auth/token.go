package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"golang.org/x/oauth2"
)

const tokenKey = "oauth-token"

// storedToken is the JSON shape saved in the keyring.
type storedToken struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`
}

// SaveToken persists an OAuth2 token to the keyring.
func SaveToken(kr Keyring, token *oauth2.Token) error {
	st := storedToken{
		AccessToken:  token.AccessToken,
		TokenType:    token.TokenType,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
	}
	data, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("encoding token: %w", err)
	}
	return kr.Store(tokenKey, string(data))
}

// LoadToken reads an OAuth2 token from the keyring.
func LoadToken(kr Keyring) (*oauth2.Token, error) {
	data, err := kr.Retrieve(tokenKey)
	if err != nil {
		return nil, fmt.Errorf("reading token from keyring: %w", err)
	}
	var st storedToken
	if err := json.Unmarshal([]byte(data), &st); err != nil {
		return nil, fmt.Errorf("decoding token: %w", err)
	}
	return &oauth2.Token{
		AccessToken:  st.AccessToken,
		TokenType:    st.TokenType,
		RefreshToken: st.RefreshToken,
		Expiry:       st.Expiry,
	}, nil
}

// DeleteToken removes the stored OAuth2 token.
func DeleteToken(kr Keyring) error {
	return kr.Delete(tokenKey)
}

// AccessToken returns the user's CloudBooster access token from the OS
// keyring, or "" if unauthenticated or the keyring is unavailable.
//
// This is the composition-root entry point for resolving the bearer token:
// CLI commands call it and inject the result into library constructors
// (NewAPIClient, NewRunner, …). Library code must NOT call it — accepting the
// token via injection is what keeps unit tests (and other library consumers
// such as downstream consumers) from triggering the OS keychain authorization prompt.
func AccessToken() string {
	kr, err := NewKeyring()
	if err != nil {
		return ""
	}
	tok, err := LoadToken(kr)
	if err != nil || tok == nil {
		return ""
	}
	return tok.AccessToken
}

// IsAuthenticated reports whether a token exists in the keyring.
func IsAuthenticated(kr Keyring) (bool, error) {
	_, err := LoadToken(kr)
	if err != nil {
		return false, nil
	}
	return true, nil
}

// HasToken reports whether a token is present in the keyring without
// reading its contents. Used by `cbx auth status` to avoid a macOS
// Keychain access prompt when the user is logged out.
func HasToken(kr Keyring) (bool, error) {
	return kr.Has(tokenKey)
}

// AuthenticatedClient returns an HTTP client that adds Bearer tokens and
// refreshes them automatically when expired.
func AuthenticatedClient(ctx context.Context, apiURL string, kr Keyring) (*http.Client, error) {
	token, err := LoadToken(kr)
	if err != nil {
		return nil, fmt.Errorf("no authentication token found; run `cbx login` first")
	}

	ocfg := (&Config{APIURL: apiURL}).oauth2Config("")
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient())
	base := ocfg.TokenSource(ctx, token)
	ts := &savingTokenSource{base: base, kr: kr}
	return oauth2.NewClient(ctx, ts), nil
}

// savingTokenSource wraps an oauth2.TokenSource and persists refreshed tokens.
type savingTokenSource struct {
	base oauth2.TokenSource
	kr   Keyring
}

func (s *savingTokenSource) Token() (*oauth2.Token, error) {
	tok, err := s.base.Token()
	if err != nil {
		return nil, err
	}
	if err := SaveToken(s.kr, tok); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to persist refreshed token: %v\n", err)
	}
	return tok, nil
}
