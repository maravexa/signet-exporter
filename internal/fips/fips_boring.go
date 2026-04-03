//go:build boringcrypto

package fips

// Enabled returns true: this binary was compiled with GOEXPERIMENT=boringcrypto.
func Enabled() bool { return true }
