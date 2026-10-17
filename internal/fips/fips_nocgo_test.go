//go:build boringcrypto && !cgo

package fips

import "testing"

func TestFIPSEnabled_WithoutCGO(t *testing.T) {
	if Enabled() {
		t.Fatal("BoringCrypto cannot handle crypto operations without CGO")
	}
}
