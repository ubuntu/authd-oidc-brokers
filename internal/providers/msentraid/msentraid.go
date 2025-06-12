// Package msentraid is the Microsoft Entra ID specific extension.
package msentraid

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/k0kubun/pp"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	msgraphauth "github.com/microsoftgraph/msgraph-sdk-go-core/authentication"
	msgraphmodels "github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/ubuntu/authd-oidc-brokers/internal/broker/authmodes"
	"github.com/ubuntu/authd-oidc-brokers/internal/consts"
	providerErrors "github.com/ubuntu/authd-oidc-brokers/internal/providers/errors"
	"github.com/ubuntu/authd-oidc-brokers/internal/providers/info"
	"github.com/ubuntu/authd/log"
	"golang.org/x/oauth2"
)

func init() {
	pp.ColoringEnabled = false
}

const (
	localGroupPrefix   = "linux-"
	defaultMSGraphHost = "graph.microsoft.com"
	msgraphAPIVersion  = "v1.0"
)

// Provider is the Microsoft Entra ID provider implementation.
type Provider struct {
	expectedScopes []string
}

// New returns a new MSEntraID provider.
func New() Provider {
	return Provider{
		expectedScopes: append(consts.DefaultScopes, "GroupMember.Read.All", "User.Read"),
	}
}

// AdditionalScopes returns the generic scopes required by the EntraID provider.
func (p Provider) AdditionalScopes() []string {
	return []string{oidc.ScopeOfflineAccess, "GroupMember.Read.All", "User.Read"}
}

// AuthOptions returns the generic auth options required by the EntraID provider.
func (p Provider) AuthOptions() []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{}
}

// CheckTokenScopes checks if the token has the required scopes.
func (p Provider) CheckTokenScopes(token *oauth2.Token) error {
	scopes, err := p.getTokenScopes(token)
	if err != nil {
		return err
	}

	var missingScopes []string
	for _, s := range p.expectedScopes {
		if !slices.Contains(scopes, s) {
			missingScopes = append(missingScopes, s)
		}
	}
	if len(missingScopes) > 0 {
		return fmt.Errorf("missing required scopes: %s", strings.Join(missingScopes, ", "))
	}
	return nil
}

func (p Provider) getTokenScopes(token *oauth2.Token) ([]string, error) {
	scopesStr, ok := token.Extra("scope").(string)
	if !ok {
		return nil, fmt.Errorf("failed to cast token scopes to string: %v", token.Extra("scope"))
	}
	return strings.Split(scopesStr, " "), nil
}

// GetExtraFields returns the extra fields of the token which should be stored persistently.
func (p Provider) GetExtraFields(token *oauth2.Token) map[string]interface{} {
	return map[string]interface{}{
		"scope": token.Extra("scope"),
	}
}

// GetMetadata returns relevant metadata about the provider.
func (p Provider) GetMetadata(provider *oidc.Provider) (map[string]interface{}, error) {
	var claims struct {
		MSGraphHost string `json:"msgraph_host"`
	}

	if err := provider.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to get provider claims: %v", err)
	}

	return map[string]interface{}{
		"msgraph_host": fmt.Sprintf("https://%s/%s", claims.MSGraphHost, msgraphAPIVersion),
	}, nil
}

// GetUserInfo returns the user info from the ID token and the groups the user is a member of, which are retrieved via
// the Microsoft Graph API.
func (p Provider) GetUserInfo(ctx context.Context, accessToken *oauth2.Token, idToken info.Claimer, providerMetadata map[string]interface{}) (info.User, error) {
	msgraphHost := fmt.Sprintf("https://%s/%s", defaultMSGraphHost, msgraphAPIVersion)
	if providerMetadata["msgraph_host"] != nil {
		var ok bool
		msgraphHost, ok = providerMetadata["msgraph_host"].(string)
		if !ok {
			return info.User{}, fmt.Errorf("failed to cast msgraph_host to string: %v", providerMetadata["msgraph_host"])
		}

		// Handle the case that the provider metadata only contains the host without the protocol and API version,
		// as was the case before 5fc98520c45294ffb85bb27a81929e2ec1b89fcb. This fixes #858.
		if !strings.Contains(msgraphHost, "://") {
			msgraphHost = fmt.Sprintf("https://%s/%s", msgraphHost, msgraphAPIVersion)
		}
	}

	userClaims, err := p.userClaims(idToken)
	if err != nil {
		return info.User{}, err
	}

	userGroups, err := p.getGroups(accessToken, msgraphHost)
	if err != nil {
		return info.User{}, err
	}

	return info.NewUser(
		userClaims.PreferredUserName,
		userClaims.Home,
		userClaims.Sub,
		userClaims.Shell,
		userClaims.Gecos,
		userGroups,
	), nil
}

type claims struct {
	PreferredUserName string `json:"preferred_username"`
	Sub               string `json:"sub"`
	Home              string `json:"home"`
	Shell             string `json:"shell"`
	Gecos             string `json:"gecos"`
}

// userClaims returns the user claims parsed from the ID token.
func (p Provider) userClaims(idToken info.Claimer) (claims, error) {
	var userClaims claims
	if err := idToken.Claims(&userClaims); err != nil {
		return claims{}, fmt.Errorf("failed to get ID token claims: %v", err)
	}
	return userClaims, nil
}

// getGroups access the Microsoft Graph API to get the groups the user is a member of.
func (p Provider) getGroups(token *oauth2.Token, msgraphHost string) ([]info.Group, error) {
	log.Debug(context.Background(), "Getting user groups from Microsoft Graph API")

	// Check if the token has the GroupMember.Read.All scope
	scopes, err := p.getTokenScopes(token)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(scopes, "GroupMember.Read.All") {
		return nil, providerErrors.NewForDisplayError("the Microsoft Entra ID app is missing the GroupMember.Read.All permission")
	}

	cred := azureTokenCredential{token: token}
	auth, err := msgraphauth.NewAzureIdentityAuthenticationProvider(cred)
	if err != nil {
		return nil, fmt.Errorf("failed to create AzureIdentityAuthenticationProvider: %v", err)
	}

	adapter, err := msgraphsdk.NewGraphRequestAdapter(auth)
	if err != nil {
		return nil, fmt.Errorf("failed to create GraphRequestAdapter: %v", err)
	}
	adapter.SetBaseUrl(msgraphHost)

	client := msgraphsdk.NewGraphServiceClient(adapter)

	// Get the groups (only the groups, not directory roles or administrative units, because that would require
	// additional permissions) which the user is a member of.
	graphGroups, err := getSecurityGroups(client)
	if err != nil {
		return nil, err
	}

	var groups []info.Group
	var msGroupNames []string
	for _, msGroup := range graphGroups {
		var group info.Group

		idPtr := msGroup.GetId()
		if idPtr == nil {
			log.Warning(context.Background(), pp.Sprintf("Could not get ID for group: %v", msGroup))
			return nil, errors.New("could not get group id")
		}
		id := *idPtr

		msGroupNamePtr := msGroup.GetDisplayName()
		if msGroupNamePtr == nil {
			log.Warning(context.Background(), pp.Sprintf("Could not get display name for group object (ID: %s): %v", id, msGroup))
			return nil, errors.New("could not get group name")
		}
		msGroupName := *msGroupNamePtr

		// Check if there is a name conflict with another group returned by the Graph API. It's not clear in which case
		// the Graph API returns multiple groups with the same name (or the same group twice), but we've seen it happen
		// in https://github.com/ubuntu/authd/issues/789.
		if checkGroupIsDuplicate(msGroupName, msGroupNames) {
			continue
		}

		// Store directory extension attributes, if any.
		additionalData := msGroup.GetAdditionalData()
		if additionalData != nil {
			group.ExtraFields = make(map[string]any)
			for k, v := range additionalData {
				// Directory extension attributes start with "extension_"
				if strings.HasPrefix(k, "extension_") && v != nil {
					group.ExtraFields[k] = v
				}
			}
		}

		// Microsoft groups are case-insensitive, see https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/resource-name-rules
		group.Name = strings.ToLower(msGroupName)

		isLocalGroup := strings.HasPrefix(group.Name, localGroupPrefix)
		if isLocalGroup {
			group.Name = strings.TrimPrefix(group.Name, localGroupPrefix)
		}

		// Don't set the UGID for local groups, because that's how the user manager differentiates between local and
		// remote groups.
		if !isLocalGroup {
			group.UGID = id
		}

		groups = append(groups, group)
		msGroupNames = append(msGroupNames, msGroupName)
	}

	return groups, nil
}

func checkGroupIsDuplicate(groupName string, groupNames []string) bool {
	for _, name := range groupNames {
		// We don't want to treat local groups without the prefix as duplicates of non-local groups
		// (e.g. "linux-sudo" and "sudo"), so we compare the names as returned by the Graph API - except that we
		// ignore the case, because we use the group names in lowercase.
		if !strings.EqualFold(name, groupName) {
			// Not a duplicate
			continue
		}

		// To make debugging easier, check if the groups differ in case, and mention that in the log message.
		if name == groupName {
			log.Warningf(context.Background(), "The Microsoft Graph API returned the group %q multiple times, ignoring the duplicate", name)
		} else {
			log.Warningf(context.Background(), "The Microsoft Graph API returned the group %[1]q multiple times, but with different case (%[2]q and %[1]q), ignoring the duplicate", groupName, name)
		}

		return true
	}

	return false
}

func removeNonSecurityGroups(groups []msgraphmodels.Groupable) []msgraphmodels.Groupable {
	var securityGroups []msgraphmodels.Groupable
	for _, group := range groups {
		if !isSecurityGroup(group) {
			groupNamePtr := group.GetDisplayName()
			if groupNamePtr == nil {
				log.Debugf(context.Background(), "Removing unnamed non-security group")
				continue
			}
			log.Debugf(context.Background(), "Removing non-security group %s", *groupNamePtr)
			continue
		}
		securityGroups = append(securityGroups, group)
	}
	return securityGroups
}

func getSecurityGroups(client *msgraphsdk.GraphServiceClient) ([]msgraphmodels.Groupable, error) {
	// Initial request to get groups
	requestBuilder := client.Me().TransitiveMemberOf().GraphGroup()
	result, err := requestBuilder.Get(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get user groups: %v", err)
	}
	if result == nil {
		log.Debug(context.Background(), "Got nil response from Microsoft Graph API for user's groups, assuming that user is not a member of any group.")
		return []msgraphmodels.Groupable{}, nil
	}

	groups := result.GetValue()

	// Continue fetching groups using paging if a next link is available
	for result.GetOdataNextLink() != nil {
		nextLink := *result.GetOdataNextLink()

		result, err = requestBuilder.WithUrl(nextLink).Get(context.Background(), nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get next page of user groups: %v", err)
		}

		groups = append(groups, result.GetValue()...)
	}

	// Remove the groups which are not security groups (but for example Microsoft 365 groups, which can be created
	// by non-admin users).
	groups = removeNonSecurityGroups(groups)

	var groupNames []string
	for _, group := range groups {
		groupNamePtr := group.GetDisplayName()
		if groupNamePtr != nil {
			groupNames = append(groupNames, *groupNamePtr)
		}
	}
	log.Debugf(context.Background(), "Got groups: %s", strings.Join(groupNames, ", "))

	return groups, nil
}

func isSecurityGroup(group msgraphmodels.Groupable) bool {
	// A group is a security group if the `securityEnabled` property is true and the `groupTypes` property does not
	// contain "Unified".
	securityEnabledPtr := group.GetSecurityEnabled()
	if securityEnabledPtr == nil || !*securityEnabledPtr {
		return false
	}

	return !slices.Contains(group.GetGroupTypes(), "Unified")
}

// NormalizeUsername parses a username into a normalized version.
func (p Provider) NormalizeUsername(username string) string {
	// Microsoft Entra usernames are case-insensitive. We can safely use strings.ToLower here without worrying about
	// different Unicode characters that fold to the same lowercase letter, because the Microsoft Entra username policy
	// (which we check in VerifyUsername) ensures that the username only contains ASCII characters.
	return strings.ToLower(username)
}

// SupportedOIDCAuthModes returns the OIDC authentication modes supported by the provider.
func (p Provider) SupportedOIDCAuthModes() []string {
	return []string{authmodes.Device, authmodes.DeviceQr}
}

// VerifyUsername checks if the authenticated username matches the requested username and that both are valid.
func (p Provider) VerifyUsername(requestedUsername, authenticatedUsername string) error {
	if p.NormalizeUsername(requestedUsername) != p.NormalizeUsername(authenticatedUsername) {
		return fmt.Errorf("requested username %q does not match the authenticated user %q", requestedUsername, authenticatedUsername)
	}

	// Check that the usernames only contain the characters allowed by the Microsoft Entra username policy
	// https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-policy#username-policies
	usernameRegexp := regexp.MustCompile(`^[a-zA-Z0-9'.\-_!#^~@]+$`)
	if !usernameRegexp.MatchString(authenticatedUsername) {
		// If this error occurs, we should investigate and probably relax the username policy, so we ask the user
		// explicitly to report this error.
		return providerErrors.NewForDisplayError("the authenticated username %q contains invalid characters. Please report this error on https://github.com/ubuntu/authd/issues", authenticatedUsername)
	}
	if !usernameRegexp.MatchString(requestedUsername) {
		return fmt.Errorf("requested username %q contains invalid characters", requestedUsername)
	}

	return nil
}

type azureTokenCredential struct {
	token *oauth2.Token
}

// GetToken creates an azcore.AccessToken from an oauth2.Token.
func (c azureTokenCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{
		Token:     c.token.AccessToken,
		ExpiresOn: c.token.Expiry,
	}, nil
}

// IsTokenExpiredError returns true if the reason for the error is that the refresh token is expired.
func (p Provider) IsTokenExpiredError(err oauth2.RetrieveError) bool {
	return err.ErrorCode == "invalid_grant" && strings.HasPrefix(err.ErrorDescription, "AADSTS50173:")
}
