package msentraid

/*
#cgo LDFLAGS: -lhimmelblau
#include "himmelblau.h"
*/
import "C"

import (
	"context"
	"fmt"
	"unsafe"

	"github.com/ubuntu/authd/log"
	"golang.org/x/oauth2"
)

var ClientID string

var tpm *C.BoxedDynTpm
var authValue *C.char
var loadableMachineKey *C.LoadableMachineKey
var machineKey *C.MachineKey
var brokerClientApp *C.BrokerClientApplication

func init() {
	// An optional TPM Transmission Interface. If this parameter is NULL, a Soft Tpm is initialized.
	var tcti_name *C.char
	ret := C.tpm_init(tcti_name, &tpm)
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

	ret = C.broker_init(nil, nil, nil, nil, &brokerClientApp)
	if ret != C.SUCCESS {
		panic(fmt.Sprintf("failed to initialize BrokerClientApplication: %d", int(ret)))
	}
}

func (p Provider) SupportsDeviceRegistration() bool {
	return true
}

func (p Provider) RegisterDevice(ctx context.Context, token *oauth2.Token, clientID, tenantID, domain string) error {
	ret := C.set_global_tracing_level(C.TRACE)
	if ret != C.SUCCESS {
		return fmt.Errorf("failed to set global tracing level: %d", int(ret))
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
	deviceDisplayName := C.CString("My Ubuntu Device")
	cDomain := C.CString(domain)
	ret = C.enroll_attrs_init(
		cDomain,
		deviceDisplayName,
		nil,
		0,
		nil,
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

	return nil
}

func AcquireAccessTokenForGraphAPI(ctx context.Context, token *oauth2.Token) (string, error) {
	// Retrieve an access token with the Microsoft Graph scopes
	var userToken *C.UserToken
	defer C.user_token_free(userToken)
	scopes := []*C.char{
		C.CString("openid"),
		C.CString("profile"),
		C.CString("offline_access"),
		C.CString("GroupMember.Read.All"),
		C.CString("User.Read"),
	}
	scopesPtr := (**C.char)(unsafe.Pointer(&scopes[0]))
	ret := C.broker_acquire_token_by_refresh_token(
		brokerClientApp,
		C.CString(token.RefreshToken),
		scopesPtr,
		C.int(len(scopes)),
		nil,
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
