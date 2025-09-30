package msentraid

import "strings"

// AllExpectedScopes returns all the default expected scopes for a new provider.
func AllExpectedScopes() string {
	return strings.Join(New().expectedScopes, " ")
}

func (p *Provider) SetNeedsAccessTokenForGraphAPI(value bool) {
	p.needsAccessTokenForGraphAPI = value
}

// SetTokenScopesForGraphAPI can be used in tests to set the scopes for the Microsoft Graph API access token.
func (p *Provider) SetTokenScopesForGraphAPI(scopes []string) {
	p.tokenScopesForGraphAPI = scopes
}

// SetAuthorityBaseURL sets the base URL for the token authority, used in tests to override the default.
// This is not thread-safe.
func SetAuthorityBaseURL(url string) {
	authorityBaseURLMu.Lock()
	authorityBaseURL = url
	authorityBaseURLMu.Unlock()
}
