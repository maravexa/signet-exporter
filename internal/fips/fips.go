// Package fips provides runtime FIPS mode detection.
// Enabled returns true when the binary was compiled with BoringCrypto
// (GOEXPERIMENT=boringcrypto). In standard builds it is always false.
package fips
