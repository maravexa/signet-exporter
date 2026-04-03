package fips

import "testing"

// TestFIPSEnabled_Default verifies that Enabled() returns false in a standard
// (non-boringcrypto) test build. The GOEXPERIMENT=boringcrypto path is tested
// by the fips-validate CI job, which builds and runs tests under that experiment.
func TestFIPSEnabled_Default(t *testing.T) {
	if Enabled() {
		t.Error("Enabled() returned true in a non-boringcrypto build")
	}
}
