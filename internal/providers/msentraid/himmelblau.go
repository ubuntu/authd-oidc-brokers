package msentraid

//go:generate ./generate-himmelblau.sh

/*
#cgo LDFLAGS: -L${SRCDIR} -Wl,-rpath=${SRCDIR} -lhimmelblau
#include "himmelblau.h"
*/
import "C"

import (
	"context"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"github.com/ubuntu/authd/log"
	"golang.org/x/oauth2"
)

var tpm *C.BoxedDynTpm
var authValue *C.char
var loadableMachineKey *C.LoadableMachineKey
var machineKey *C.MachineKey
var brokerClientApp *C.BrokerClientApplication

func init() {
	var err *C.MSAL_ERROR

	err = C.set_global_tracing_level(C.TRACE)
	if err != nil {
		panic(fmt.Sprintf("failed to set global tracing level: %v", C.GoString(err.msg)))
	}

	// An optional TPM Transmission Interface. If this parameter is NULL, a soft TPM is initialized.
	var tctiName *C.char
	err = C.tpm_init(tctiName, &tpm)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize TPM: %v", C.GoString(err.msg)))
	}

	err = C.auth_value_generate(&authValue)
	if err != nil {
		panic(fmt.Sprintf("failed to generate auth value: %v", C.GoString(err.msg)))
	}

	err = C.tpm_machine_key_create(tpm, authValue, &loadableMachineKey)
	if err != nil {
		panic(fmt.Sprintf("failed to create machine key: %v", C.GoString(err.msg)))
	}

	err = C.tpm_machine_key_load(tpm, authValue, loadableMachineKey, &machineKey)
	if err != nil {
		panic(fmt.Sprintf("failed to load machine key: %v", C.GoString(err.msg)))
	}
}

var registered = false

func (p *Provider) registerDevice(ctx context.Context, token *oauth2.Token, tenantID, domain string) error {
	if registered {
		return nil
	}

	var err *C.MSAL_ERROR

	authority := C.CString("https://login.microsoftonline.com/" + tenantID)
	err = C.broker_init(
		authority,
		nil, /* client_id */
		nil, /* transport_key */
		nil, /* cert_key */
		&brokerClientApp,
	)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize BrokerClientApplication: %v", C.GoString(err.msg)))
	}

	var attrs *C.EnrollAttrs

	cDomain := C.CString(domain)

	err = C.enroll_attrs_init(
		cDomain,
		C.CString(hostname()),
		nil, /* device_type - default is "Linux" */
		0,   /* join_type - 0: Azure AD join */
		C.CString(OSVersion()),
		&attrs,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize enroll attributes: %v", C.GoString(err.msg))
	}

	var transportKey *C.LoadableMsOapxbcRsaKey
	defer C.loadable_ms_oapxbc_rsa_key_free(transportKey)
	var certKey *C.LoadableMsDeviceEnrolmentKey
	defer C.loadable_ms_device_enrollment_key_free(certKey)
	var deviceID *C.char
	defer C.free(unsafe.Pointer(deviceID))
	err = C.broker_enroll_device(
		brokerClientApp,
		C.CString(token.RefreshToken),
		attrs,
		tpm,
		machineKey,
		&transportKey,
		&certKey,
		&deviceID,
	)
	if err != nil {
		return fmt.Errorf("failed to enroll device: %v", C.GoString(err.msg))
	}

	log.Infof(ctx, "Enrolled device with ID: %v", C.GoString(deviceID))

	registered = true

	return nil
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return name
}

// OSVersion gets the pretty name of the OS release from the system.
func OSVersion() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "unknown"
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
		}
	}

	return "unknown"
}

// acquireAccessTokenForGraphAPI uses the refresh token from the provided OAuth2
// token with the required scopes to access the Microsoft Graph API.
func acquireAccessTokenForGraphAPI(ctx context.Context, clientID string, token *oauth2.Token) (string, error) {
	if brokerClientApp == nil {
		return "", fmt.Errorf("broker client application is not initialized. Please report this issue")
	}

	var userToken *C.UserToken
	defer C.user_token_free(userToken)
	scopes := []*C.char{C.CString("GroupMember.Read.All")}
	scopesPtr := (**C.char)(unsafe.Pointer(&scopes[0]))
	err := C.broker_acquire_token_by_refresh_token(
		brokerClientApp,
		C.CString(token.RefreshToken),
		scopesPtr,
		C.int(len(scopes)),
		nil, /* request_resource */
		// We could use `nil` here instead of the client ID if we also use `nil` as the client ID
		// in the `broker_init` call, which means that the user doesn't even have to register
		// an OIDC app in Entra. However, that has the effect that we can't fetch the groups
		// of the user.
		C.CString(clientID),
		//nil, /* client_id */
		tpm,
		machineKey,
		&userToken,
	)
	if err != nil {
		return "", fmt.Errorf("failed to acquire token by refresh token: %v", C.GoString(err.msg))
	}

	var accessToken *C.char
	defer C.free(unsafe.Pointer(accessToken))
	err = C.user_token_access_token(userToken, &accessToken)
	if err != nil {
		return "", fmt.Errorf("failed to get access token: %v", C.GoString(err.msg))
	}

	log.Infof(ctx, "Acquired access token: %v", C.GoString(accessToken))

	return C.GoString(accessToken), nil
}
