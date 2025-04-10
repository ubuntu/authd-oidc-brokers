package msentraid

/*
#cgo LDFLAGS: -lhimmelblau
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

const edgeBrowserClientID = "d7b530a4-7680-4c23-a8bf-c52c121d2e87"

var tpm *C.BoxedDynTpm
var authValue *C.char
var loadableMachineKey *C.LoadableMachineKey
var machineKey *C.MachineKey
var brokerClientApp *C.BrokerClientApplication

var appClientID string

func init() {
	var ret C.enum_MSAL_ERROR

	ret = C.set_global_tracing_level(C.TRACE)
	if ret != C.SUCCESS {
		panic(fmt.Sprintf("failed to set global tracing level: %d", int(ret)))
	}

	// An optional TPM Transmission Interface. If this parameter is NULL, a Soft Tpm is initialized.
	var tcti_name *C.char
	ret = C.tpm_init(tcti_name, &tpm)
	if ret != C.SUCCESS {
		panic(fmt.Sprintf("failed to initialize TPM: %d", int(ret)))
	}

	ret = C.auth_value_generate(&authValue)
	if ret != C.SUCCESS {
		panic(fmt.Sprintf("failed to generate auth value: %d", int(ret)))
	}

	ret = C.tpm_machine_key_create(tpm, authValue, &loadableMachineKey)
	if ret != C.SUCCESS {
		panic(fmt.Sprintf("failed to create machine key: %d", int(ret)))
	}

	ret = C.tpm_machine_key_load(tpm, authValue, loadableMachineKey, &machineKey)
	if ret != C.SUCCESS {
		panic(fmt.Sprintf("failed to load machine key: %d", int(ret)))
	}
}

func (p Provider) SupportsDeviceRegistration() bool {
	return true
}

var registered = false

func (p Provider) RegisterDevice(ctx context.Context, token *oauth2.Token, clientID, tenantID, domain string) error {
	if registered {
		return nil
	}

	appClientID = clientID

	var ret C.enum_MSAL_ERROR

	authority := C.CString("https://login.microsoftonline.com/" + tenantID)
	ret = C.broker_init(
		authority,
		C.CString(clientID),
		nil,
		nil,
		&brokerClientApp,
	)
	if ret != C.SUCCESS {
		panic(fmt.Sprintf("failed to initialize BrokerClientApplication: %d", int(ret)))
	}

	//var tpm *C.BoxedDynTpm
	//defer C.tpm_free(tpm)
	//// An optional TPM Transmission Interface. If this parameter is NULL, a Soft Tpm is initialized.
	//var tcti_name *C.char
	//ret = C.tpm_init(tcti_name, &tpm)
	//if ret != C.SUCCESS {
	//	return fmt.Errorf("failed to initialize TPM: %d", int(ret))
	//}
	//
	//var authValue *C.char
	//defer C.free(unsafe.Pointer(authValue))
	//ret = C.auth_value_generate(&authValue)
	//if ret != C.SUCCESS {
	//	return fmt.Errorf("failed to generate auth value: %d", int(ret))
	//}
	//
	//var loadableMachineKey *C.LoadableMachineKey
	//defer C.loadable_machine_key_free(loadableMachineKey)
	//ret = C.tpm_machine_key_create(tpm, authValue, &loadableMachineKey)
	//if ret != C.SUCCESS {
	//	return fmt.Errorf("failed to create machine key: %d", int(ret))
	//}
	//
	//var machineKey *C.MachineKey
	//defer C.machine_key_free(machineKey)
	//ret = C.tpm_machine_key_load(tpm, authValue, loadableMachineKey, &machineKey)
	//if ret != C.SUCCESS {
	//	return fmt.Errorf("failed to load machine key: %d", int(ret))
	//}
	//
	//var brokerClientApp *C.BrokerClientApplication
	//defer C.broker_free(brokerClientApp)
	//ret = C.broker_init(nil, nil, nil, nil, &brokerClientApp)
	//if ret != C.SUCCESS {
	//	return fmt.Errorf("failed to initialize BrokerClientApplication: %d", int(ret))
	//}

	//var deviceAuthResp *C.DeviceAuthorizationResponse
	//ret = C.broker_initiate_device_flow_for_device_enrollment(brokerClientApp, &deviceAuthResp)
	//if ret != C.SUCCESS {
	//	return fmt.Errorf("failed to initiate device flow for device enrollment: %d", int(ret))
	//}
	//
	//var userToken *C.UserToken
	//ret = C.broker_acquire_token_by_device_flow(brokerClientApp, deviceAuthResp, &userToken)
	//if ret != C.SUCCESS {
	//	return fmt.Errorf("failed to acquire token by device flow: %d", int(ret))
	//}

	//var userToken *C.UserToken
	//oldRefreshToken := C.CString(token.RefreshToken)
	//enrollmentScope := C.CString("https://enrollment.manage.microsoft.com/.default")
	//scopes := []*C.char{enrollmentScope, C.CString("openid"), C.CString("profile"), C.CString("offline_access")}
	//ret = C.broker_acquire_token_by_refresh_token(
	//	brokerClientApp,
	//	oldRefreshToken,
	//	scopes,
	//	len(scopes),
	//)

	//var refreshToken *C.char
	//defer C.free(unsafe.Pointer(refreshToken))
	//
	//ret = C.user_token_refresh_token(userToken, &refreshToken)
	//if ret != C.SUCCESS {
	//	return fmt.Errorf("failed to get refresh token: %d", int(ret))
	//}

	var attrs *C.EnrollAttrs
	// TODO: Memory leak because attrs are not freed?
	cDomain := C.CString(domain)

	ret = C.enroll_attrs_init(
		cDomain,
		C.CString(hostname()),
		nil,
		0,
		C.CString(osVersion()),
		&attrs,
	)
	if ret != C.SUCCESS {
		return fmt.Errorf("failed to initialize enroll attributes: %d", int(ret))
	}

	var transportKey *C.LoadableMsOapxbcRsaKey
	defer C.loadable_ms_oapxbc_rsa_key_free(transportKey)
	var certKey *C.LoadableIdentityKey
	defer C.loadable_identity_key_free(certKey)
	var deviceID *C.char
	defer C.free(unsafe.Pointer(deviceID))
	ret = C.broker_enroll_device(
		brokerClientApp,
		C.CString(token.RefreshToken),
		attrs,
		tpm,
		machineKey,
		&transportKey,
		&certKey,
		&deviceID,
	)
	if ret != C.SUCCESS {
		return fmt.Errorf("failed to enroll device: %d", int(ret))
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

// osVersion gets the pretty name of the OS release from the system
func osVersion() string {
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

func AcquireAccessTokenForGraphAPI(ctx context.Context, token *oauth2.Token) (string, error) {
	// Retrieve an access token with the Microsoft Graph scopes
	var userToken *C.UserToken
	defer C.user_token_free(userToken)
	scopes := []*C.char{
		//C.CString("openid"),
		//C.CString("profile"),
		//C.CString("offline_access"),
		//C.CString("GroupMember.Read.All"),
		//C.CString("User.Read"),
		C.CString("https://graph.microsoft.com/.default"),
	}
	scopesPtr := (**C.char)(unsafe.Pointer(&scopes[0]))
	ret := C.broker_acquire_token_by_refresh_token(
		brokerClientApp,
		C.CString(token.RefreshToken),
		scopesPtr,
		C.int(len(scopes)),
		nil,
		// We have to use the edge browser client ID here, else the GET request to the
		// https://login.microsoftonline.com/<tenant-ID>/oauth2/v2.0/authorize endpoint
		// fails with "AADSTS500113: no reply address is registered for the application".
		// Note: Alternatively, we could use `nil` here if we also use `nil` as the client ID
		// in the `broker_init` call, which means that the user doesn't even have to register
		// an OIDC app in Entra. However, that has the effect that we can't fetch the groups
		// of the user.
		C.CString(edgeBrowserClientID),
		tpm,
		machineKey,
		&userToken,
	)
	if ret != C.SUCCESS {
		return "", fmt.Errorf("failed to acquire token by refresh token: %d", int(ret))
	}

	var accessToken *C.char
	defer C.free(unsafe.Pointer(accessToken))
	ret = C.user_token_access_token(userToken, &accessToken)
	if ret != C.SUCCESS {
		return "", fmt.Errorf("failed to get access token: %d", int(ret))
	}

	log.Infof(ctx, "Acquired access token: %v", C.GoString(accessToken))

	return C.GoString(accessToken), nil
}
