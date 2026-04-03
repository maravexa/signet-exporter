package audit

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestCEFFormatter_HeaderFormat(t *testing.T) {
	var buf strings.Builder
	f := NewCEFFormatter(&buf, "1.2.3")
	ip := net.ParseIP("10.0.1.5")
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	f.NewHost(ip, "10.0.1.0/24", mac, "Acme Corp", "host1.local")

	line := buf.String()
	if !strings.HasPrefix(line, "CEF:0|Signet|signet-exporter|1.2.3|100|New Host Discovered|3|") {
		t.Errorf("unexpected CEF header: %q", line)
	}
	if !strings.HasSuffix(line, "\n") {
		t.Error("CEF line must end with newline")
	}
}

func TestCEFFormatter_NewHost(t *testing.T) {
	var buf strings.Builder
	f := NewCEFFormatter(&buf, "0.0.1")
	ip := net.ParseIP("192.168.1.1")
	mac, _ := net.ParseMAC("de:ad:be:ef:00:01")
	f.NewHost(ip, "192.168.1.0/24", mac, "VendorX", "myhost")

	line := buf.String()
	if !strings.Contains(line, "src=192.168.1.1") {
		t.Errorf("missing src field: %q", line)
	}
	if !strings.Contains(line, "mac=de:ad:be:ef:00:01") {
		t.Errorf("missing mac field: %q", line)
	}
	if !strings.Contains(line, "vendor=VendorX") {
		t.Errorf("missing vendor field: %q", line)
	}
	if !strings.Contains(line, "hostname=myhost") {
		t.Errorf("missing hostname field: %q", line)
	}
}

func TestCEFFormatter_MACIPChange(t *testing.T) {
	var buf strings.Builder
	f := NewCEFFormatter(&buf, "1.0.0")
	ip := net.ParseIP("10.0.0.1")
	oldMAC, _ := net.ParseMAC("aa:aa:aa:aa:aa:aa")
	newMAC, _ := net.ParseMAC("bb:bb:bb:bb:bb:bb")
	f.MACIPChange(ip, "10.0.0.0/24", oldMAC, newMAC, "OldVendor", "NewVendor")

	line := buf.String()
	if !strings.Contains(line, "|200|") {
		t.Errorf("expected event ID 200: %q", line)
	}
	if !strings.Contains(line, "|7|") {
		t.Errorf("expected severity 7: %q", line)
	}
	if !strings.Contains(line, "oldMac=aa:aa:aa:aa:aa:aa") {
		t.Errorf("missing oldMac: %q", line)
	}
	if !strings.Contains(line, "newMac=bb:bb:bb:bb:bb:bb") {
		t.Errorf("missing newMac: %q", line)
	}
}

func TestCEFFormatter_UnauthorizedDevice(t *testing.T) {
	var buf strings.Builder
	f := NewCEFFormatter(&buf, "1.0.0")
	ip := net.ParseIP("10.0.0.50")
	mac, _ := net.ParseMAC("ca:fe:ba:be:00:01")
	f.UnauthorizedDevice(ip, "10.0.0.0/24", mac, "Unknown")

	line := buf.String()
	if !strings.Contains(line, "|300|") {
		t.Errorf("expected event ID 300: %q", line)
	}
	if !strings.Contains(line, "|9|") {
		t.Errorf("expected severity 9 for unauthorized: %q", line)
	}
}

func TestCEFFormatter_ScanError(t *testing.T) {
	var buf strings.Builder
	f := NewCEFFormatter(&buf, "1.0.0")
	f.ScanError("10.0.1.0/24", "arp", errors.New("socket: permission denied"))

	line := buf.String()
	if !strings.Contains(line, "|600|") {
		t.Errorf("expected event ID 600: %q", line)
	}
	if !strings.Contains(line, "msg=socket: permission denied") {
		t.Errorf("missing error message: %q", line)
	}
}

func TestCEFFormatter_CertReloaded_Success(t *testing.T) {
	var buf strings.Builder
	f := NewCEFFormatter(&buf, "1.0.0")
	f.CertReloaded("/etc/signet/tls/server.pem", nil)

	line := buf.String()
	if !strings.Contains(line, "|800|") {
		t.Errorf("expected event ID 800: %q", line)
	}
	if !strings.Contains(line, "TLS Certificate Reloaded") {
		t.Errorf("expected success name: %q", line)
	}
	if !strings.Contains(line, "certPath=/etc/signet/tls/server.pem") {
		t.Errorf("missing certPath: %q", line)
	}
}

func TestCEFFormatter_CertReloaded_Failure(t *testing.T) {
	var buf strings.Builder
	f := NewCEFFormatter(&buf, "1.0.0")
	f.CertReloaded("/etc/signet/tls/server.pem", errors.New("no such file"))

	line := buf.String()
	if !strings.Contains(line, "TLS Certificate Reload Failed") {
		t.Errorf("expected failure name: %q", line)
	}
	if !strings.Contains(line, "|7|") {
		t.Errorf("expected severity 7 on failure: %q", line)
	}
	if !strings.Contains(line, "msg=no such file") {
		t.Errorf("missing error msg: %q", line)
	}
}

func TestCEFFormatter_EscapesSpecialChars(t *testing.T) {
	var buf strings.Builder
	f := NewCEFFormatter(&buf, "1.0.0")
	// Vendor name with pipe, backslash and equals — all must be escaped in extensions.
	ip := net.ParseIP("10.0.0.1")
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	f.NewHost(ip, "10.0.0.0/24", mac, `A|B\C=D`, "host")

	line := buf.String()
	// In extension values: | → \|, \ → \\, = → \=
	if !strings.Contains(line, `vendor=A\|B\\C\=D`) {
		t.Errorf("special chars not properly escaped in extension value: %q", line)
	}
}

func TestCEFFormatter_HostDisappeared(t *testing.T) {
	var buf strings.Builder
	f := NewCEFFormatter(&buf, "1.0.0")
	ip := net.ParseIP("10.1.1.1")
	mac, _ := net.ParseMAC("11:22:33:44:55:66")
	ts := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)
	f.HostDisappeared(ip, "10.1.1.0/24", mac, "TestVendor", ts)

	line := buf.String()
	if !strings.Contains(line, "|150|") {
		t.Errorf("expected event ID 150: %q", line)
	}
	if !strings.Contains(line, "lastSeen=2025-01-15T12:00:00Z") {
		t.Errorf("missing lastSeen timestamp: %q", line)
	}
}
