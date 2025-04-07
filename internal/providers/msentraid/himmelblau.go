package msentraid

/*
#cgo LDFLAGS: -lhimmelblau
#include "himmelblau.h"
*/
import "C"

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"unsafe"

	"github.com/ubuntu/authd/log"
	"golang.org/x/oauth2"
)

// BCRYPT_RSAKEY_BLOB structure constants
const (
	BCRYPT_RSAPUBLIC_MAGIC                    = 0x31415352 // "RSA1"
	RSA_KEY_SIZE                              = 2048       // 2048-bit key
	MICROSOFT_AUTHENTICATION_BROKER_CLIENT_ID = "29d9ed98-a469-4536-ade2-f981bc1d605e"
)

// NonceOID represents the OID for the Nonce extension
var NonceOID = asn1.ObjectIdentifier{1, 2, 840, 113556, 1, 5, 284, 2, 1}

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

	log.Info(ctx, "Enrolled device with ID: %s", C.GoString(deviceID))

	return nil
}

func (p Provider) RegisterDeviceInGo(ctx context.Context, token *oauth2.Token, clientID, tenantID string) error {
	accessToken, err := acquireAccessTokenForRegisteringDevice(ctx, token, clientID, tenantID)
	if err != nil {
		return fmt.Errorf("error acquiring access token for registering device: %w", err)
	}
	log.Debugf(ctx, "XXX: Access token for registering device: %s", accessToken)

	// Fetch nonce from the Nonce Service
	nonce, err := fetchNonce(tenantID)
	if err != nil {
		return fmt.Errorf("error fetching nonce: %w", err)
	}

	certificateRequest, err := generateCertificateRequest(nonce)
	if err != nil {
		return fmt.Errorf("error generating certificate request: %w", err)
	}

	transportKey, err := generateTransportKey()
	if err != nil {
		return fmt.Errorf("error generating transport key: %w", err)
	}

	// XXX
	targetDomain := "ubudev1.onmicrosoft.com"

	deviceType := "Linux"

	// XXX
	osVersion := "Ubuntu 24.04"

	// XXX
	deviceDisplayName := "My Ubuntu Device"

	// 0 is "Azure AD join"
	// 4 is "Azure AD register"
	joinType := 0

	// Send the POST request to the device registration endpoint
	endpoint := "https://enterpriseregistration.windows.net/EnrollmentServer/device/?api-version=2.0"
	// The body in JSON format
	reqBody := fmt.Sprintf(`{
		"Attributes": {
			"ReuseDevice": "true",
			"ReturnClientSid": "true"
		},
		"CertificateRequest": {
			"Data": "%s",
			"Type": "pkcs10"
		},
		"DeviceDisplayName": "%s",
		"DeviceType": "%s",
		"JoinType": %d,
		"OSVersion": "%s",
		"TargetDomain": "%s",
		"TransportKey": "%s"
	}`, certificateRequest, deviceDisplayName, deviceType, joinType, osVersion, targetDomain, transportKey)

	log.Debugf(ctx, "XXX: POST %s┕━%s", endpoint, reqBody)

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create POST request: %w", err)
	}

	//.header(header::AUTHORIZATION, format!("Bearer {}", access_token))
	//.header(header::CONTENT_TYPE, "application/json")
	//.header(DRS_CLIENT_NAME_HEADER_FIELD, env!("CARGO_PKG_NAME"))
	//.header(DRS_CLIENT_VERSION_HEADER_FIELD, env!("CARGO_PKG_VERSION"))
	//.header(header::ACCEPT, "application/json, text/plain, */*")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("Content-Type", "application/json")
	//req.Header.Set("ocp-adrs-client-name", "authd")
	//req.Header.Set("ocp-adrs-client-version", consts.Version)
	req.Header.Set("Accept", "application/json, text/plain, */*")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send POST request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body := new(bytes.Buffer)
		_, err = body.ReadFrom(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}
		log.Errorf(ctx, "Failed to register device: status code %d. Response body: %s", resp.StatusCode, body.String())
		return fmt.Errorf("failed to register device: status code %d", resp.StatusCode)
	}

	return nil
}

type NonceResponse struct {
	ResponseStatus struct {
		Message string `json:"message"`
		TraceID string `json:"traceId"`
		Time    string `json:"time"`
	} `json:"ReponseStatus"`
	Value string `json:"Value"`
}

func fetchNonce(tenantID string) (string, error) {
	url := fmt.Sprintf("https://enterpriseregistration.windows.net/EnrollmentServer/nonce/%s/?api-version=1.0", tenantID)
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch nonce: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch nonce: status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}
	log.Debugf(context.Background(), "Nonce response body: %s", body)

	var nonceResp NonceResponse
	if err := json.Unmarshal(body, &nonceResp); err != nil {
		return "", fmt.Errorf("failed to parse JSON response: %w", err)
	}
	log.Debugf(context.Background(), "Nonce response: %+v", nonceResp)

	return nonceResp.Value, nil
}

func generateCertificateRequest(nonce string) (string, error) {
	// Generate a 2048-bit RSA private key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Define the subject with the required CN
	subject := pkix.Name{CommonName: "7E980AD9-B86D-4306-9425-9AC066FB014A"}

	// Encode the Nonce extension
	nonceExt, err := asn1.Marshal(nonce)
	if err != nil {
		return "", fmt.Errorf("failed to encode Nonce extension: %w", err)
	}

	extensions := []pkix.Extension{
		{
			Id:       NonceOID,
			Critical: false,
			Value:    nonceExt,
		},
	}

	// Create a certificate request template
	template := x509.CertificateRequest{
		Subject:            subject,
		SignatureAlgorithm: x509.SHA256WithRSA,
		ExtraExtensions:    extensions,
	}

	// Create the CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privKey)
	if err != nil {
		return "", fmt.Errorf("failed to create certificate request: %w", err)
	}

	// Encode the CSR as PEM
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	if csrPEM == nil {
		return "", fmt.Errorf("failed to encode CSR to PEM")
	}

	// Base64 encode the CSR
	csrBase64 := base64.StdEncoding.EncodeToString(csrPEM)

	return csrBase64, nil
}

// generateTransportKey generates a base64-encoded transport key in BCRYPT_RSAKEY_BLOB format
func generateTransportKey() (string, error) {
	// Generate a 2048-bit RSA key
	privKey, err := rsa.GenerateKey(rand.Reader, RSA_KEY_SIZE)
	if err != nil {
		return "", fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Extract public key components
	pubKey := privKey.PublicKey
	modulus := pubKey.N.Bytes()
	publicExp := []byte{0x01, 0x00, 0x01} // 65537 in big-endian

	// Prepare the BCRYPT_RSAKEY_BLOB
	var blob bytes.Buffer
	writeLE := func(value interface{}) error {
		return binary.Write(&blob, binary.LittleEndian, value)
	}

	// Write header with error checking
	if err := writeLE(uint32(BCRYPT_RSAPUBLIC_MAGIC)); err != nil {
		return "", fmt.Errorf("failed to write Magic: %w", err)
	}
	if err := writeLE(uint32(RSA_KEY_SIZE)); err != nil {
		return "", fmt.Errorf("failed to write BitLength: %w", err)
	}
	if err := writeLE(uint32(len(publicExp))); err != nil {
		return "", fmt.Errorf("failed to write cbPublicExpLength: %w", err)
	}
	if err := writeLE(uint32(len(modulus))); err != nil {
		return "", fmt.Errorf("failed to write cbModulusLength: %w", err)
	}
	if err := writeLE(uint32(0)); err != nil {
		return "", fmt.Errorf("failed to write cbPrime1Length: %w", err)
	}
	if err := writeLE(uint32(0)); err != nil {
		return "", fmt.Errorf("failed to write cbPrime2Length: %w", err)
	}

	// Write public exponent
	if _, err := blob.Write(publicExp); err != nil {
		return "", fmt.Errorf("failed to write public exponent: %w", err)
	}

	// Write modulus
	if _, err := blob.Write(modulus); err != nil {
		return "", fmt.Errorf("failed to write modulus: %w", err)
	}

	// Base64 encode the transport key
	transportKey := base64.StdEncoding.EncodeToString(blob.Bytes())

	return transportKey, nil
}

func acquireAccessTokenForRegisteringDevice(ctx context.Context, token *oauth2.Token, clientID, tenantID string) (string, error) {
	if token == nil {
		return "", fmt.Errorf("token is nil")
	}

	if !token.Valid() {
		return "", fmt.Errorf("token is invalid")
	}

	//let mut all_scopes = vec!["openid", "profile", "offline_access"];
	//    all_scopes.extend(scopes);
	//    let scopes_str = all_scopes.join(" ");
	//
	//    let params = [
	//        ("client_id", self.client_id.as_str()),
	//        ("scope", &scopes_str),
	//        ("grant_type", "refresh_token"),
	//        ("refresh_token", refresh_token),
	//        ("client_info", "1"),
	//    ];
	//    let payload = params
	//        .iter()
	//        .map(|(k, v)| format!("{}={}", k, url_encode(v)))
	//        .collect::<Vec<String>>()
	//        .join("&");
	//
	//    let resp = self
	//        .client
	//        .post(format!("{}/oauth2/v2.0/token", self.authority))
	//        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
	//        .header(header::ACCEPT, "application/json")
	//        .body(payload)
	//        .send()
	//        .await
	//        .map_err(|e| MsalError::RequestFailed(format!("{}", e)))?;
	//    if resp.status().is_success() {
	//        let token: UserToken = resp
	//            .json()
	//            .await
	//            .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
	//
	//        Ok(token)
	//    } else {
	//        let json_resp: ErrorResponse = resp
	//            .json()
	//            .await
	//            .map_err(|e| MsalError::InvalidJson(format!("{}", e)))?;
	//        Err(MsalError::AcquireTokenFailed(json_resp))
	//    }

	endpoint := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)
	params := map[string]string{
		"client_id":     MICROSOFT_AUTHENTICATION_BROKER_CLIENT_ID,
		"scope":         "openid profile offline_access 01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9/.default",
		"grant_type":    "refresh_token",
		"refresh_token": token.RefreshToken,
		"client_info":   "1",
	}

	payload := ""
	for k, v := range params {
		payload += fmt.Sprintf("%s=%s&", k, url.PathEscape(v))
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBufferString(payload))
	if err != nil {
		return "", fmt.Errorf("failed to create POST request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	log.Debugf(ctx, "XXX: POST %s┕━%s", endpoint, payload)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send POST request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to acquire access token for registering device: status code %d. Response body: %s", resp.StatusCode, body)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse JSON response: %w", err)
	}

	return tokenResp.AccessToken, nil
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

	log.Infof(ctx, "Acquired access token: %s", C.GoString(accessToken))

	return C.GoString(accessToken), nil
}
