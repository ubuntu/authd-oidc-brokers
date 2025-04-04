package consts

import (
	"github.com/coreos/go-oidc/v3/oidc"
)

var (
	AzurePortalAppId         = "c44b4083-3bb0-49c1-b47d-974e53cbdf3c"
	AzurePortalScope         = AzurePortalAppId + "/.default"
	MicrosoftBrokerAppID     = "29d9ed98-a469-4536-ade2-f981bc1d605e"
	MicrosoftBrokerAppScopes = []string{"openid", "profile", "offline_access", AzurePortalScope}

	// DefaultScopes contains the OIDC scopes that we require for all providers.
	// Provider implementations can append additional scopes.
	DefaultScopes = []string{oidc.ScopeOpenID, "profile", "email"}
)
