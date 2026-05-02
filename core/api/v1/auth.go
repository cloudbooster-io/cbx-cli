package v1

import "net/http"

// AuthTransport injects an Authorization bearer token into every request.
type AuthTransport struct {
	Base  http.RoundTripper
	Token string
}

// RoundTrip implements http.RoundTripper.
func (t *AuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Token != "" {
		req = req.Clone(req.Context())
		req.Header.Set("Authorization", "Bearer "+t.Token)
	}
	return t.Base.RoundTrip(req)
}
