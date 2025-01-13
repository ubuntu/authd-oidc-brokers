// Package stringutils provides utility functions for string operations.
package stringutils

// IsASCII checks if a string contains only ASCII characters.
func IsASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}
