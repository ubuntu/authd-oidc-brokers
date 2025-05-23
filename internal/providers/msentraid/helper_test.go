package msentraid_test

import (
	"encoding/json"
	"time"

	"golang.org/x/oauth2"
)

var (
	validAccessToken = &oauth2.Token{
		AccessToken:  "accesstoken",
		RefreshToken: "refreshtoken",
		Expiry:       time.Now().Add(1000 * time.Hour),
	}

	validIDToken = &testIDToken{
		claims: `{"preferred_username": "valid-user",
		"sub": "valid-sub",
		"home": "/home/valid-user",
		"shell": "/bin/bash",
		"gecos": "Valid User"}`,
	}

	invalidIDToken = &testIDToken{
		claims: "invalid claims",
	}
)

type testIDToken struct {
	claims string
}

func (t *testIDToken) Claims(v interface{}) error {
	return json.Unmarshal([]byte(t.claims), v)
}
