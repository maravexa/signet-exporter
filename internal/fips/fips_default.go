//go:build !boringcrypto

package fips

// Enabled returns false: this binary was compiled without BoringCrypto.
func Enabled() bool { return false }
