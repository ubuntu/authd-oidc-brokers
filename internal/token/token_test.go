package token_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/ubuntu/authd-oidc-brokers/internal/fileutils"
	"github.com/ubuntu/authd-oidc-brokers/internal/providers/info"
	"github.com/ubuntu/authd-oidc-brokers/internal/token"
	"golang.org/x/oauth2"
)

var testToken = token.AuthCachedInfo{
	Token: &oauth2.Token{
		AccessToken:  "accesstoken",
		RefreshToken: "refreshtoken",
	},
	RawIDToken: "rawidtoken",
	UserInfo: info.User{
		Name:  "foo",
		UUID:  "saved-user-id",
		Home:  "/home/foo",
		Gecos: "foo",
		Shell: "/usr/bin/bash",
		Groups: []info.Group{
			{Name: "saved-remote-group", UGID: "12345"},
			{Name: "saved-local-group", UGID: ""},
		},
	},
}

func TestCacheAuthInfo(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		setup       func(t *testing.T, path string)
		expectError bool
	}{
		"Successfully store token with non-existing parent directory": {
			setup: func(t *testing.T, path string) {
				// No setup needed
			},
		},
		"Successfully store token with existing parent directory": {
			setup: func(t *testing.T, path string) {
				err := os.MkdirAll(filepath.Dir(path), 0700)
				require.NoError(t, err, "MkdirAll should not return an error")
			},
		},
		"Successfully store token with existing file": {
			setup: func(t *testing.T, path string) {
				err := os.MkdirAll(filepath.Dir(path), 0700)
				require.NoError(t, err, "MkdirAll should not return an error")
				err = token.CacheAuthInfo(path, testToken)
				require.NoError(t, err, "CacheAuthInfo should not return an error")
			},
		},

		"Error when file exists and is a directory": {
			setup: func(t *testing.T, path string) {
				err := os.MkdirAll(path, 0700)
				require.NoError(t, err, "MkdirAll should not return an error")
			},
			expectError: true,
		},
		"Error when parent directory is a file": {
			setup: func(t *testing.T, path string) {
				err := fileutils.Touch(filepath.Dir(path))
				require.NoError(t, err, "Touch should not return an error")
			},
			expectError: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tokenPath := filepath.Join(t.TempDir(), "parent", "token.json")
			tc.setup(t, tokenPath)
			err := token.CacheAuthInfo(tokenPath, testToken)
			if tc.expectError {
				require.Error(t, err, "CacheAuthInfo should return an error")
			} else {
				require.NoError(t, err, "CacheAuthInfo should not return an error")
			}
		})
	}
}

func TestLoadAuthInfo(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		setup       func(t *testing.T, path string)
		expectedRet token.AuthCachedInfo
		expectError bool
	}{
		"Successfully load token from existing file": {
			setup: func(t *testing.T, path string) {
				err := os.MkdirAll(filepath.Dir(path), 0700)
				require.NoError(t, err, "MkdirAll should not return an error")
				err = token.CacheAuthInfo(path, testToken)
				require.NoError(t, err, "CacheAuthInfo should not return an error")
			},
			expectedRet: testToken,
			expectError: false,
		},

		"Error when file does not exist": {
			setup: func(t *testing.T, path string) {
				// No setup needed
			},
			expectError: true,
		},
		"Error when file contains invalid JSON": {
			setup: func(t *testing.T, path string) {
				err := os.MkdirAll(filepath.Dir(path), 0700)
				require.NoError(t, err, "MkdirAll should not return an error")
				err = os.WriteFile(path, []byte("invalid json"), 0600)
				require.NoError(t, err, "WriteFile should not return an error")
			},
			expectError: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tokenPath := filepath.Join(t.TempDir(), "parent", "token.json")
			tc.setup(t, tokenPath)
			got, err := token.LoadAuthInfo(tokenPath)
			if tc.expectError {
				require.Error(t, err, "LoadAuthInfo should return an error")
			} else {
				require.NoError(t, err, "LoadAuthInfo should not return an error")
				require.Equal(t, tc.expectedRet, got, "LoadAuthInfo should return the expected value")
			}
		})
	}
}
