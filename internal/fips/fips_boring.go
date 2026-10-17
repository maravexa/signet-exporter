//go:build boringcrypto

package fips

import "crypto/boring"

// Enabled reports whether BoringCrypto handles supported crypto operations.
func Enabled() bool { return boring.Enabled() }
