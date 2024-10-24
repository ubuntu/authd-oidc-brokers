// Package authmodes lists the authentication modes that providers can support.
package authmodes

const (
	// PasswordID is the ID of the password authentication method.
	PasswordID = "password"

	// DeviceID is the ID of the device authentication method.
	DeviceID = "device_auth"

	// DeviceQrID is the ID of the device authentication method when QrCode rendering is enabled.
	DeviceQrID = "device_auth_qr"

	// NewPasswordID is the ID of the new password configuration method.
	NewPasswordID = "newpassword"
)
