// Package sessionmode defines the session modes supported by the broker.
package sessionmode

const (
	// LoginNew is used when the session is for user login.
	LoginNew = "login"
	// ChangePasswordNew is used when the session is for changing the user password.
	ChangePasswordNew = "change-password"
)
