package broker

const (
	// AuthDataSecret is the key for the secret in the authentication data.
	AuthDataSecret = "secret"
	// AuthDataSecretOld is the old key for the secret in the authentication data, which is now deprecated
	// TODO(UDENG-5844): Remove this once all authd installations use "secret" instead of "challenge".
	AuthDataSecretOld = "challenge"
)
