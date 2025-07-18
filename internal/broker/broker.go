// Package broker is the generic oidc business code.
package broker

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/ubuntu/authd-oidc-brokers/internal/broker/authmodes"
	"github.com/ubuntu/authd-oidc-brokers/internal/broker/sessionmode"
	"github.com/ubuntu/authd-oidc-brokers/internal/consts"
	"github.com/ubuntu/authd-oidc-brokers/internal/fileutils"
	"github.com/ubuntu/authd-oidc-brokers/internal/password"
	"github.com/ubuntu/authd-oidc-brokers/internal/providers"
	providerErrors "github.com/ubuntu/authd-oidc-brokers/internal/providers/errors"
	"github.com/ubuntu/authd-oidc-brokers/internal/providers/info"
	"github.com/ubuntu/authd-oidc-brokers/internal/token"
	"github.com/ubuntu/authd/log"
	"github.com/ubuntu/decorate"
	"golang.org/x/oauth2"
)

const (
	maxAuthAttempts    = 3
	maxRequestDuration = 5 * time.Second
)

// Config is the configuration for the broker.
type Config struct {
	ConfigFile            string
	DataDir               string
	OldEncryptedTokensDir string

	userConfig
}

// Broker is the real implementation of the broker to track sessions and process oidc calls.
type Broker struct {
	cfg Config

	provider providers.Provider
	oidcCfg  oidc.Config

	currentSessions   map[string]session
	currentSessionsMu sync.RWMutex

	privateKey *rsa.PrivateKey
}

type session struct {
	username string
	lang     string
	mode     string

	selectedMode    string
	authModes       []string
	attemptsPerMode map[string]int
	nextAuthModes   []string

	oidcServer            *oidc.Provider
	oauth2Config          oauth2.Config
	authInfo              map[string]any
	isOffline             bool
	userDataDir           string
	passwordPath          string
	tokenPath             string
	oldEncryptedTokenPath string

	isAuthenticating *isAuthenticatedCtx
}

type isAuthenticatedCtx struct {
	ctx        context.Context
	cancelFunc context.CancelFunc
}

type option struct {
	provider providers.Provider
}

// Option is a func that allows to override some of the broker default settings.
type Option func(*option)

// New returns a new oidc Broker with the providers listed in the configuration file.
func New(cfg Config, args ...Option) (b *Broker, err error) {
	p := providers.CurrentProvider()

	if cfg.ConfigFile != "" {
		cfg.userConfig, err = parseConfigFile(cfg.ConfigFile, p)
		if err != nil {
			return nil, fmt.Errorf("could not parse config file '%s': %v", cfg.ConfigFile, err)
		}
	}

	opts := option{
		provider: p,
	}
	for _, arg := range args {
		arg(&opts)
	}

	if cfg.DataDir == "" {
		err = errors.Join(err, errors.New("cache path is required and was not provided"))
	}
	if cfg.issuerURL == "" {
		err = errors.Join(err, errors.New("issuer URL is required and was not provided"))
	}
	if cfg.clientID == "" {
		err = errors.Join(err, errors.New("client ID is required and was not provided"))
	}
	if err != nil {
		return nil, err
	}

	if cfg.homeBaseDir == "" {
		cfg.homeBaseDir = "/home"
	}

	// Generate a new private key for the broker.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Error(context.Background(), err.Error())
		return nil, errors.New("failed to generate broker private key")
	}

	b = &Broker{
		cfg:        cfg,
		provider:   opts.provider,
		oidcCfg:    oidc.Config{ClientID: cfg.clientID},
		privateKey: privateKey,

		currentSessions:   make(map[string]session),
		currentSessionsMu: sync.RWMutex{},
	}
	return b, nil
}

// NewSession creates a new session for the user.
func (b *Broker) NewSession(username, lang, mode string) (sessionID, encryptionKey string, err error) {
	defer decorate.OnError(&err, "could not create new session for user %q", username)

	sessionID = uuid.New().String()
	s := session{
		username: username,
		lang:     lang,
		mode:     mode,

		authInfo:        make(map[string]any),
		attemptsPerMode: make(map[string]int),
	}

	pubASN1, err := x509.MarshalPKIXPublicKey(&b.privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}

	_, issuer, _ := strings.Cut(b.cfg.issuerURL, "://")
	issuer = strings.ReplaceAll(issuer, "/", "_")
	issuer = strings.ReplaceAll(issuer, ":", "_")
	s.userDataDir = filepath.Join(b.cfg.DataDir, issuer, username)
	// The token is stored in $DATA_DIR/$ISSUER/$USERNAME/token.json.
	s.tokenPath = filepath.Join(s.userDataDir, "token.json")
	// The password is stored in $DATA_DIR/$ISSUER/$USERNAME/password.
	s.passwordPath = filepath.Join(s.userDataDir, "password")
	s.oldEncryptedTokenPath = filepath.Join(b.cfg.OldEncryptedTokensDir, issuer, username+".cache")

	// Construct an OIDC provider via OIDC discovery.
	s.oidcServer, err = b.connectToOIDCServer(context.Background())
	if err != nil {
		log.Noticef(context.Background(), "Could not connect to the provider: %v. Starting session in offline mode.", err)
		s.isOffline = true
	}

	if s.oidcServer != nil {
		s.oauth2Config = oauth2.Config{
			ClientID:     b.oidcCfg.ClientID,
			ClientSecret: b.cfg.clientSecret,
			Endpoint:     s.oidcServer.Endpoint(),
			Scopes:       append(consts.DefaultScopes, b.provider.AdditionalScopes()...),
		}
	}

	b.currentSessionsMu.Lock()
	b.currentSessions[sessionID] = s
	b.currentSessionsMu.Unlock()

	return sessionID, base64.StdEncoding.EncodeToString(pubASN1), nil
}

func (b *Broker) connectToOIDCServer(ctx context.Context) (*oidc.Provider, error) {
	ctx, cancel := context.WithTimeout(ctx, maxRequestDuration)
	defer cancel()

	return oidc.NewProvider(ctx, b.cfg.issuerURL)
}

// GetAuthenticationModes returns the authentication modes available for the user.
func (b *Broker) GetAuthenticationModes(sessionID string, supportedUILayouts []map[string]string) (authModesWithLabels []map[string]string, err error) {
	session, err := b.getSession(sessionID)
	if err != nil {
		return nil, err
	}

	availableModes, err := b.availableAuthModes(session)
	if err != nil {
		return nil, err
	}

	// Store the available auth modes, so that we can check in SelectAuthenticationMode if the selected mode is valid.
	session.authModes = availableModes
	if err := b.updateSession(sessionID, session); err != nil {
		return nil, err
	}

	modesSupportedByUI := b.authModesSupportedByUI(supportedUILayouts)

	for _, mode := range availableModes {
		if !slices.Contains(modesSupportedByUI, mode) {
			log.Debugf(context.Background(), "Authentication mode %q is not supported by the UI", mode)
			continue
		}

		authModesWithLabels = append(authModesWithLabels, map[string]string{
			"id":    mode,
			"label": authmodes.Label[mode],
		})
	}

	if len(authModesWithLabels) == 0 {
		return nil, fmt.Errorf("no authentication modes available for user %q", session.username)
	}

	return authModesWithLabels, nil
}

func (b *Broker) availableAuthModes(session session) (availableModes []string, err error) {
	if len(session.nextAuthModes) > 0 {
		for _, mode := range session.nextAuthModes {
			if !authModeIsAvailable(session, mode) {
				log.Infof(context.Background(), "Authentication mode %q is not available", mode)
				continue
			}
			availableModes = append(availableModes, mode)
		}
		return availableModes, nil
	}

	switch session.mode {
	case sessionmode.ChangePassword, sessionmode.ChangePasswordOld:
		// Session is for changing the password.
		if !tokenExists(session) {
			return nil, errors.New("user has no cached token")
		}
		return []string{authmodes.Password}, nil

	default:
		// Session is for login. Check which auth modes are available.
		// The order of the modes is important, because authd picks the first supported one.
		// Password authentication should be the first option if available, to avoid performing device authentication
		// when it's not necessary.
		modes := append([]string{authmodes.Password}, b.provider.SupportedOIDCAuthModes()...)
		for _, mode := range modes {
			if authModeIsAvailable(session, mode) {
				availableModes = append(availableModes, mode)
			}
		}
		return availableModes, nil
	}
}

func authModeIsAvailable(session session, authMode string) bool {
	switch authMode {
	case authmodes.Password:
		return tokenExists(session)
	case authmodes.NewPassword:
		return true
	case authmodes.Device, authmodes.DeviceQr:
		return session.oidcServer != nil && session.oidcServer.Endpoint().DeviceAuthURL != "" && !session.isOffline
	}
	return false
}

func tokenExists(session session) bool {
	tokenExists, err := fileutils.FileExists(session.tokenPath)
	if err != nil {
		log.Warningf(context.Background(), "Could not check if token exists: %v", err)
	}
	if tokenExists {
		return true
	}

	// Check the old encrypted token path.
	tokenExists, err = fileutils.FileExists(session.oldEncryptedTokenPath)
	if err != nil {
		log.Warningf(context.Background(), "Could not check if old encrypted token exists: %v", err)
	}
	return tokenExists
}

func (b *Broker) authModesSupportedByUI(supportedUILayouts []map[string]string) (supportedModes []string) {
	for _, layout := range supportedUILayouts {
		mode := b.supportedAuthModeFromLayout(layout)
		if mode != "" {
			supportedModes = append(supportedModes, mode)
		}
	}
	return supportedModes
}

func (b *Broker) supportedAuthModeFromLayout(layout map[string]string) string {
	supportedEntries := strings.Split(strings.TrimPrefix(layout["entry"], "optional:"), ",")
	switch layout["type"] {
	case "qrcode":
		if !strings.Contains(layout["wait"], "true") {
			return ""
		}
		if layout["renders_qrcode"] == "false" {
			return authmodes.Device
		}
		return authmodes.DeviceQr

	case "form":
		if slices.Contains(supportedEntries, "chars_password") {
			return authmodes.Password
		}

	case "newpassword":
		if slices.Contains(supportedEntries, "chars_password") {
			return authmodes.NewPassword
		}
	}
	return ""
}

// SelectAuthenticationMode selects the authentication mode for the user.
func (b *Broker) SelectAuthenticationMode(sessionID, authModeID string) (uiLayoutInfo map[string]string, err error) {
	session, err := b.getSession(sessionID)
	if err != nil {
		return nil, err
	}

	// populate UI options based on selected authentication mode
	uiLayoutInfo, err = b.generateUILayout(&session, authModeID)
	if err != nil {
		return nil, err
	}

	// Store selected mode
	session.selectedMode = authModeID

	if err = b.updateSession(sessionID, session); err != nil {
		return nil, err
	}

	return uiLayoutInfo, nil
}

func (b *Broker) generateUILayout(session *session, authModeID string) (map[string]string, error) {
	if !slices.Contains(session.authModes, authModeID) {
		return nil, fmt.Errorf("selected authentication mode %q does not exist", authModeID)
	}

	var uiLayout map[string]string
	switch authModeID {
	case authmodes.Device, authmodes.DeviceQr:
		ctx, cancel := context.WithTimeout(context.Background(), maxRequestDuration)
		defer cancel()

		var authOpts []oauth2.AuthCodeOption

		// Workaround to cater for RFC compliant oauth2 server. Public providers do not properly
		// implement the RFC, (probably) because they assume that device clients are public.
		// As described in https://datatracker.ietf.org/doc/html/rfc8628#section-3.1
		// device authentication requests must provide client authentication, similar to that for
		// the token endpoint.
		// The golang/oauth2 library does not implement this, see https://github.com/golang/oauth2/issues/685.
		// We implement a workaround for implementing the client_secret_post client authn method.
		// Supporting client_secret_basic would require us to patch the http client used by the
		// oauth2 lib.
		// Some providers support both of these authentication methods, some implement only one and
		// some implement neither.
		// This was tested with the following providers:
		// - Ory Hydra: supports client_secret_post
		// TODO @shipperizer: client_authentication methods should be configurable
		if secret := session.oauth2Config.ClientSecret; secret != "" {
			authOpts = append(authOpts, oauth2.SetAuthURLParam("client_secret", secret))
		}

		response, err := session.oauth2Config.DeviceAuth(ctx, authOpts...)
		if err != nil {
			return nil, fmt.Errorf("could not generate Device Authentication code layout: %v", err)
		}
		session.authInfo["response"] = response

		label := fmt.Sprintf(
			"Access %q and use the provided login code",
			response.VerificationURI,
		)
		if authModeID == authmodes.DeviceQr {
			label = fmt.Sprintf(
				"Scan the QR code or access %q and use the provided login code",
				response.VerificationURI,
			)
		}

		uiLayout = map[string]string{
			"type":    "qrcode",
			"label":   label,
			"wait":    "true",
			"button":  "Request new login code",
			"content": response.VerificationURI,
			"code":    response.UserCode,
		}

	case authmodes.Password:
		uiLayout = map[string]string{
			"type":  "form",
			"label": "Enter your local password",
			"entry": "chars_password",
		}

	case authmodes.NewPassword:
		label := "Create a local password"
		if session.mode == sessionmode.ChangePassword || session.mode == sessionmode.ChangePasswordOld {
			label = "Update your local password"
		}

		uiLayout = map[string]string{
			"type":  "newpassword",
			"label": label,
			"entry": "chars_password",
		}
	}

	return uiLayout, nil
}

// IsAuthenticated evaluates the provided authenticationData and returns the authentication status for the user.
func (b *Broker) IsAuthenticated(sessionID, authenticationData string) (string, string, error) {
	session, err := b.getSession(sessionID)
	if err != nil {
		return AuthDenied, "{}", err
	}

	var authData map[string]string
	if authenticationData != "" {
		if err := json.Unmarshal([]byte(authenticationData), &authData); err != nil {
			return AuthDenied, "{}", fmt.Errorf("authentication data is not a valid json value: %v", err)
		}
	}

	ctx, err := b.startAuthenticate(sessionID)
	if err != nil {
		return AuthDenied, "{}", err
	}

	// Cleans up the IsAuthenticated context when the call is done.
	defer b.CancelIsAuthenticated(sessionID)

	authDone := make(chan struct{})
	var access string
	var iadResponse isAuthenticatedDataResponse
	go func() {
		access, iadResponse = b.handleIsAuthenticated(ctx, &session, authData)
		close(authDone)
	}()

	select {
	case <-authDone:
	case <-ctx.Done():
		// We can ignore the error here since the message is constant.
		msg, _ := json.Marshal(errorMessage{Message: "authentication request cancelled"})
		return AuthCancelled, string(msg), ctx.Err()
	}

	switch access {
	case AuthRetry:
		session.attemptsPerMode[session.selectedMode]++
		if session.attemptsPerMode[session.selectedMode] == maxAuthAttempts {
			access = AuthDenied
			iadResponse = errorMessage{Message: "maximum number of attempts reached"}
		}
	}

	if err = b.updateSession(sessionID, session); err != nil {
		return AuthDenied, "{}", err
	}

	encoded, err := json.Marshal(iadResponse)
	if err != nil {
		return AuthDenied, "{}", fmt.Errorf("could not parse data to JSON: %v", err)
	}

	data := string(encoded)
	if data == "null" {
		data = "{}"
	}
	return access, data, nil
}

func (b *Broker) handleIsAuthenticated(ctx context.Context, session *session, authData map[string]string) (access string, data isAuthenticatedDataResponse) {
	defer decorateErrorMessage(&data, "authentication failure")

	rawSecret, ok := authData[AuthDataSecret]
	if !ok {
		rawSecret = authData[AuthDataSecretOld]
	}

	// Decrypt secret if present.
	secret, err := decodeRawSecret(b.privateKey, rawSecret)
	if err != nil {
		log.Errorf(context.Background(), "could not decode secret: %s", err)
		return AuthRetry, errorMessage{Message: "could not decode secret"}
	}

	var authInfo token.AuthCachedInfo
	switch session.selectedMode {
	case authmodes.Device, authmodes.DeviceQr:
		response, ok := session.authInfo["response"].(*oauth2.DeviceAuthResponse)
		if !ok {
			log.Error(context.Background(), "could not get device auth response")
			return AuthDenied, errorMessage{Message: "could not get required response"}
		}

		if response.Expiry.IsZero() {
			response.Expiry = time.Now().Add(time.Hour)
			log.Debugf(context.Background(), "Device code does not have an expiry time, using default of %s", response.Expiry)
		} else {
			log.Debugf(context.Background(), "Device code expiry time: %s", response.Expiry)
		}
		expiryCtx, cancel := context.WithDeadline(ctx, response.Expiry)
		defer cancel()
		t, err := session.oauth2Config.DeviceAccessToken(expiryCtx, response, b.provider.AuthOptions()...)
		if err != nil {
			log.Errorf(context.Background(), "could not authenticate user remotely: %s", err)
			return AuthRetry, errorMessage{Message: "could not authenticate user remotely"}
		}

		if err = b.provider.CheckTokenScopes(t); err != nil {
			log.Warningf(context.Background(), "error checking token scopes: %s", err)
		}

		rawIDToken, ok := t.Extra("id_token").(string)
		if !ok {
			log.Error(context.Background(), "could not get ID token")
			return AuthDenied, errorMessage{Message: "could not get ID token"}
		}

		authInfo = token.NewAuthCachedInfo(t, rawIDToken, b.provider)

		authInfo.ProviderMetadata, err = b.provider.GetMetadata(session.oidcServer)
		if err != nil {
			log.Errorf(context.Background(), "could not get provider metadata: %s", err)
			return AuthDenied, errorMessage{Message: "could not get provider metadata"}
		}

		authInfo.UserInfo, err = b.fetchUserInfo(ctx, session, &authInfo)
		if err != nil {
			log.Errorf(context.Background(), "could not fetch user info: %s", err)
			return AuthDenied, errorMessageForDisplay(err, "could not fetch user info")
		}

		if !b.userNameIsAllowed(authInfo.UserInfo.Name) {
			log.Warning(context.Background(), b.userNotAllowedLogMsg(authInfo.UserInfo.Name))
			return AuthDenied, errorMessage{Message: "user not allowed in broker configuration"}
		}

		session.authInfo["auth_info"] = authInfo
		session.nextAuthModes = []string{authmodes.NewPassword}

		return AuthNext, nil

	case authmodes.Password:
		useOldEncryptedToken, err := token.UseOldEncryptedToken(session.tokenPath, session.passwordPath, session.oldEncryptedTokenPath)
		if err != nil {
			log.Error(context.Background(), err.Error())
			return AuthDenied, errorMessage{Message: "could not check password file"}
		}

		if useOldEncryptedToken {
			authInfo, err = token.LoadOldEncryptedAuthInfo(session.oldEncryptedTokenPath, secret)
			if err != nil {
				log.Error(context.Background(), err.Error())
				return AuthDenied, errorMessage{Message: "could not load encrypted token"}
			}

			// We were able to decrypt the old token with the password, so we can now hash and store the password in the
			// new format.
			if err = password.HashAndStorePassword(secret, session.passwordPath); err != nil {
				log.Error(context.Background(), err.Error())
				return AuthDenied, errorMessage{Message: "could not store password"}
			}
		} else {
			ok, err := password.CheckPassword(secret, session.passwordPath)
			if err != nil {
				log.Error(context.Background(), err.Error())
				return AuthDenied, errorMessage{Message: "could not check password"}
			}
			if !ok {
				log.Noticef(context.Background(), "Authentication failure: incorrect local password for user %q", session.username)
				return AuthRetry, errorMessage{Message: "incorrect password"}
			}

			authInfo, err = token.LoadAuthInfo(session.tokenPath)
			if err != nil {
				log.Error(context.Background(), err.Error())
				return AuthDenied, errorMessage{Message: "could not load stored token"}
			}
		}

		// If the session is for changing the password, we don't need to refresh the token and user info (and we don't
		// want the method call to return an error if refreshing the token or user info fails).
		if session.mode == sessionmode.ChangePassword || session.mode == sessionmode.ChangePasswordOld {
			session.authInfo["auth_info"] = authInfo
			return AuthNext, nil
		}

		if b.cfg.forceProviderAuthentication && session.isOffline {
			return AuthDenied, errorMessage{Message: "could not refresh token: provider is not reachable"}
		}

		// Refresh the token if we're online even if the token has not expired
		if b.cfg.forceProviderAuthentication || !session.isOffline {
			authInfo, err = b.refreshToken(ctx, session.oauth2Config, authInfo)
			var retrieveErr *oauth2.RetrieveError
			if errors.As(err, &retrieveErr) && b.provider.IsTokenExpiredError(*retrieveErr) {
				// The refresh token is expired, so the user needs to authenticate via OIDC again.
				session.nextAuthModes = []string{authmodes.Device, authmodes.DeviceQr}
				return AuthNext, nil
			}
			if err != nil {
				log.Error(context.Background(), err.Error())
				return AuthDenied, errorMessage{Message: "could not refresh token"}
			}
		}

		// Try to refresh the user info
		userInfo, err := b.fetchUserInfo(ctx, session, &authInfo)
		if err != nil && authInfo.UserInfo.Name == "" {
			// We don't have a valid user info, so we can't proceed.
			log.Errorf(context.Background(), "could not fetch user info: %s", err)
			return AuthDenied, errorMessageForDisplay(err, "could not fetch user info")
		}
		if err != nil {
			// We couldn't fetch the user info, but we have a valid cached one.
			log.Warningf(context.Background(), "Could not fetch user info: %v. Using cached user info.", err)
		} else {
			authInfo.UserInfo = userInfo
		}

	case authmodes.NewPassword:
		if secret == "" {
			return AuthRetry, errorMessage{Message: "empty secret"}
		}

		var ok bool
		// This mode must always come after a authentication mode, so it has to have an auth_info.
		authInfo, ok = session.authInfo["auth_info"].(token.AuthCachedInfo)
		if !ok {
			log.Error(context.Background(), "could not get required information")
			return AuthDenied, errorMessage{Message: "could not get required information"}
		}

		if err = password.HashAndStorePassword(secret, session.passwordPath); err != nil {
			log.Error(context.Background(), err.Error())
			return AuthDenied, errorMessage{Message: "could not store password"}
		}
	}

	if b.cfg.shouldRegisterOwner() {
		if err := b.cfg.registerOwner(b.cfg.ConfigFile, authInfo.UserInfo.Name); err != nil {
			// The user is not allowed if we fail to create the owner-autoregistration file.
			// Otherwise the owner might change if the broker is restarted.
			log.Errorf(context.Background(), "Failed to assign the owner role: %v", err)
			return AuthDenied, errorMessage{Message: "could not register the owner"}
		}
	}

	if !b.userNameIsAllowed(authInfo.UserInfo.Name) {
		log.Warning(context.Background(), b.userNotAllowedLogMsg(authInfo.UserInfo.Name))
		return AuthDenied, errorMessage{Message: "user not allowed in broker configuration"}
	}

	// Add extra groups to the user info.
	for _, name := range b.cfg.extraGroups {
		log.Debugf(context.Background(), "Adding extra group %q", name)
		authInfo.UserInfo.Groups = append(authInfo.UserInfo.Groups, info.Group{Name: name})
	}

	if b.isOwner(authInfo.UserInfo.Name) {
		// Add the owner extra groups to the user info.
		for _, name := range b.cfg.ownerExtraGroups {
			log.Debugf(context.Background(), "Adding owner extra group %q", name)
			authInfo.UserInfo.Groups = append(authInfo.UserInfo.Groups, info.Group{Name: name})
		}
	}

	if session.isOffline {
		return AuthGranted, userInfoMessage{UserInfo: authInfo.UserInfo}
	}

	if err := token.CacheAuthInfo(session.tokenPath, authInfo); err != nil {
		log.Error(context.Background(), err.Error())
		return AuthDenied, errorMessage{Message: "could not cache user info"}
	}

	// At this point we successfully stored the hashed password and a new token, so we can now safely remove any old
	// encrypted token.
	token.CleanupOldEncryptedToken(session.oldEncryptedTokenPath)

	return AuthGranted, userInfoMessage{UserInfo: authInfo.UserInfo}
}

// userNameIsAllowed checks whether the user's username is allowed to access the machine.
func (b *Broker) userNameIsAllowed(userName string) bool {
	return b.cfg.userNameIsAllowed(b.provider.NormalizeUsername(userName))
}

// isOwner returns true if the user is the owner of the machine.
func (b *Broker) isOwner(userName string) bool {
	return b.cfg.owner == b.provider.NormalizeUsername(userName)
}

func (b *Broker) userNotAllowedLogMsg(userName string) string {
	logMsg := fmt.Sprintf("User %q is not in the list of allowed users.", userName)
	logMsg += fmt.Sprintf("\nYou can add the user to allowed_users in %s", b.cfg.ConfigFile)
	return logMsg
}

func (b *Broker) startAuthenticate(sessionID string) (context.Context, error) {
	session, err := b.getSession(sessionID)
	if err != nil {
		return nil, err
	}

	if session.isAuthenticating != nil {
		log.Errorf(context.Background(), "Authentication already running for session %q", sessionID)
		return nil, errors.New("authentication already running for this user session")
	}

	ctx, cancel := context.WithCancel(context.Background())
	session.isAuthenticating = &isAuthenticatedCtx{ctx: ctx, cancelFunc: cancel}

	if err := b.updateSession(sessionID, session); err != nil {
		cancel()
		return nil, err
	}

	return ctx, nil
}

// EndSession ends the session for the user.
func (b *Broker) EndSession(sessionID string) error {
	session, err := b.getSession(sessionID)
	if err != nil {
		return err
	}

	// Checks if there is a isAuthenticated call running for this session and cancels it before ending the session.
	if session.isAuthenticating != nil {
		b.CancelIsAuthenticated(sessionID)
	}

	b.currentSessionsMu.Lock()
	defer b.currentSessionsMu.Unlock()
	delete(b.currentSessions, sessionID)
	return nil
}

// CancelIsAuthenticated cancels the IsAuthenticated call for the user.
func (b *Broker) CancelIsAuthenticated(sessionID string) {
	session, err := b.getSession(sessionID)
	if err != nil {
		return
	}

	if session.isAuthenticating == nil {
		return
	}

	session.isAuthenticating.cancelFunc()
	session.isAuthenticating = nil

	if err := b.updateSession(sessionID, session); err != nil {
		log.Errorf(context.Background(), "Error when cancelling IsAuthenticated: %v", err)
	}
}

// UserPreCheck checks if the user is valid and can be allowed to authenticate.
// It returns the user info in JSON format if the user is valid, or an empty string if the user is not allowed.
func (b *Broker) UserPreCheck(username string) (string, error) {
	found := false
	for _, suffix := range b.cfg.allowedSSHSuffixes {
		if suffix == "" {
			continue
		}

		// If suffx is only "*", TrimPrefix will return the empty string and that works for the 'match all' case also.
		suffix = strings.TrimPrefix(suffix, "*")
		if strings.HasSuffix(username, suffix) {
			found = true
			break
		}
	}

	if !found {
		// The username does not match any of the allowed suffixes.
		return "", nil
	}

	u := info.NewUser(username, filepath.Join(b.cfg.homeBaseDir, username), "", "", "", nil)
	encoded, err := json.Marshal(u)
	if err != nil {
		return "", fmt.Errorf("could not marshal user info: %v", err)
	}
	return string(encoded), nil
}

// getSession returns the session information for the specified session ID or an error if the session is not active.
func (b *Broker) getSession(sessionID string) (session, error) {
	b.currentSessionsMu.RLock()
	defer b.currentSessionsMu.RUnlock()
	s, active := b.currentSessions[sessionID]
	if !active {
		return session{}, fmt.Errorf("%s is not a current transaction", sessionID)
	}
	return s, nil
}

// updateSession checks if the session is still active and updates the session info.
func (b *Broker) updateSession(sessionID string, session session) error {
	// Checks if the session was ended in the meantime, otherwise we would just accidentally recreate it.
	if _, err := b.getSession(sessionID); err != nil {
		return err
	}
	b.currentSessionsMu.Lock()
	defer b.currentSessionsMu.Unlock()
	b.currentSessions[sessionID] = session
	return nil
}

// refreshToken refreshes the OAuth2 token and returns the updated AuthCachedInfo.
func (b *Broker) refreshToken(ctx context.Context, oauth2Config oauth2.Config, oldToken token.AuthCachedInfo) (token.AuthCachedInfo, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, maxRequestDuration)
	defer cancel()
	// set cached token expiry time to one hour in the past
	// this makes sure the token is refreshed even if it has not 'actually' expired
	oldToken.Token.Expiry = time.Now().Add(-time.Hour)
	oauthToken, err := oauth2Config.TokenSource(timeoutCtx, oldToken.Token).Token()
	if err != nil {
		return token.AuthCachedInfo{}, err
	}

	// Update the raw ID token
	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok {
		log.Debug(context.Background(), "refreshed token does not contain an ID token, keeping the old one")
		rawIDToken = oldToken.RawIDToken
	}

	t := token.NewAuthCachedInfo(oauthToken, rawIDToken, b.provider)
	t.ProviderMetadata = oldToken.ProviderMetadata
	t.UserInfo = oldToken.UserInfo
	return t, nil
}

func (b *Broker) fetchUserInfo(ctx context.Context, session *session, t *token.AuthCachedInfo) (userInfo info.User, err error) {
	if session.isOffline {
		return info.User{}, errors.New("session is in offline mode")
	}

	idToken, err := session.oidcServer.Verifier(&b.oidcCfg).Verify(ctx, t.RawIDToken)
	if err != nil {
		return info.User{}, fmt.Errorf("could not verify token: %v", err)
	}

	userInfo, err = b.provider.GetUserInfo(ctx, t.Token, idToken, t.ProviderMetadata)
	if err != nil {
		return info.User{}, err
	}

	if err = b.provider.VerifyUsername(session.username, userInfo.Name); err != nil {
		return info.User{}, fmt.Errorf("username verification failed: %w", err)
	}

	// This means that home was not provided by the claims, so we need to set it to the broker default.
	if !filepath.IsAbs(userInfo.Home) {
		userInfo.Home = filepath.Join(b.cfg.homeBaseDir, userInfo.Home)
	}

	return userInfo, err
}

// decorateErrorMessage decorates the isAuthenticatedDataResponse with the provided message, if it's an errorMessage.
func decorateErrorMessage(data *isAuthenticatedDataResponse, msg string) {
	if *data == nil {
		return
	}
	errMsg, ok := (*data).(errorMessage)
	if !ok {
		return
	}
	errMsg.Message = fmt.Sprintf("%s: %s", msg, errMsg.Message)
	*data = errMsg
}

// Checks if the provided error is of type ForDisplayError. If it is, it returns the error message. Else, it returns
// the provided fallback message.
func errorMessageForDisplay(err error, fallback string) errorMessage {
	var e *providerErrors.ForDisplayError
	if errors.As(err, &e) {
		return errorMessage{Message: e.Error()}
	}
	return errorMessage{Message: fallback}
}
