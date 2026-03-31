//go:build linux

package scanner

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
)

// makeMAC parses a MAC string for use in tests.
func makeMAC(s string) net.HardwareAddr {
	hw, err := net.ParseMAC(s)
	if err != nil {
		panic("invalid MAC in test: " + err.Error())
	}
	return hw
}

// makeARPReply hand-constructs a valid 42-byte ARP reply frame with the given
// sender MAC and IP. Used by multiple tests.
func makeARPReply(senderMAC net.HardwareAddr, senderIP netip.Addr) []byte {
	frame := make([]byte, 42)
	// Ethernet header: dst=ff:ff:ff:ff:ff:ff src=senderMAC ethertype=0x0806
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], senderMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)
	// ARP payload
	binary.BigEndian.PutUint16(frame[14:16], 0x0001) // hw type: Ethernet
	binary.BigEndian.PutUint16(frame[16:18], 0x0800) // proto type: IPv4
	frame[18] = 6
	frame[19] = 4
	binary.BigEndian.PutUint16(frame[20:22], 0x0002) // op: reply
	copy(frame[22:28], senderMAC)                    // sender hw addr
	b4 := senderIP.As4()
	copy(frame[28:32], b4[:]) // sender proto addr
	// target hw addr [32:38] and target proto addr [38:42] left as zero
	return frame
}

func TestBuildARPRequest_ValidPacket(t *testing.T) {
	srcMAC := makeMAC("aa:bb:cc:dd:ee:ff")
	srcIP := netip.MustParseAddr("10.0.1.1")
	dstIP := netip.MustParseAddr("10.0.1.50")

	frame, err := buildARPRequest(srcMAC, srcIP, dstIP)
	if err != nil {
		t.Fatalf("buildARPRequest error: %v", err)
	}

	if len(frame) != 42 {
		t.Fatalf("frame length = %d, want 42", len(frame))
	}

	// Ethernet header
	wantBroadcast := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if !equalMAC(frame[0:6], wantBroadcast) {
		t.Errorf("dst MAC = % x, want broadcast", frame[0:6])
	}
	if !equalMAC(frame[6:12], srcMAC) {
		t.Errorf("src MAC = % x, want %v", frame[6:12], srcMAC)
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x0806 {
		t.Errorf("EtherType = %04x, want 0x0806", binary.BigEndian.Uint16(frame[12:14]))
	}

	// ARP payload
	if binary.BigEndian.Uint16(frame[14:16]) != 0x0001 {
		t.Errorf("hw type = %04x, want 0x0001", binary.BigEndian.Uint16(frame[14:16]))
	}
	if binary.BigEndian.Uint16(frame[16:18]) != 0x0800 {
		t.Errorf("proto type = %04x, want 0x0800", binary.BigEndian.Uint16(frame[16:18]))
	}
	if frame[18] != 6 {
		t.Errorf("hw addr len = %d, want 6", frame[18])
	}
	if frame[19] != 4 {
		t.Errorf("proto addr len = %d, want 4", frame[19])
	}
	if binary.BigEndian.Uint16(frame[20:22]) != 0x0001 {
		t.Errorf("operation = %04x, want 0x0001 (request)", binary.BigEndian.Uint16(frame[20:22]))
	}

	// Sender fields
	if !equalMAC(frame[22:28], srcMAC) {
		t.Errorf("sender hw addr = % x, want %v", frame[22:28], srcMAC)
	}
	wantSrcIP := srcIP.As4()
	if [4]byte(frame[28:32]) != wantSrcIP {
		t.Errorf("sender proto addr = % x, want % x", frame[28:32], wantSrcIP)
	}

	// Target fields
	wantZeroMAC := [6]byte{}
	if [6]byte(frame[32:38]) != wantZeroMAC {
		t.Errorf("target hw addr should be zero, got % x", frame[32:38])
	}
	wantDstIP := dstIP.As4()
	if [4]byte(frame[38:42]) != wantDstIP {
		t.Errorf("target proto addr = % x, want % x", frame[38:42], wantDstIP)
	}
}

func TestBuildARPRequest_DifferentAddresses(t *testing.T) {
	tests := []struct {
		name   string
		srcMAC string
		srcIP  string
		dstIP  string
	}{
		{"basic", "aa:bb:cc:dd:ee:ff", "10.0.1.1", "10.0.1.100"},
		{"gateway", "11:22:33:44:55:66", "192.168.1.1", "192.168.1.254"},
		{"small subnet", "de:ad:be:ef:00:01", "172.16.0.1", "172.16.0.2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srcMAC := makeMAC(tt.srcMAC)
			srcIP := netip.MustParseAddr(tt.srcIP)
			dstIP := netip.MustParseAddr(tt.dstIP)

			frame, err := buildARPRequest(srcMAC, srcIP, dstIP)
			if err != nil {
				t.Fatalf("buildARPRequest error: %v", err)
			}
			if len(frame) != 42 {
				t.Fatalf("frame length = %d, want 42", len(frame))
			}

			// Verify key fields at expected offsets
			if binary.BigEndian.Uint16(frame[12:14]) != 0x0806 {
				t.Error("wrong EtherType")
			}
			if binary.BigEndian.Uint16(frame[20:22]) != 0x0001 {
				t.Error("operation should be request (0x0001)")
			}
			if !equalMAC(frame[22:28], srcMAC) {
				t.Errorf("sender hw addr mismatch")
			}
			wantSrc := srcIP.As4()
			if [4]byte(frame[28:32]) != wantSrc {
				t.Errorf("sender proto addr mismatch")
			}
			wantDst := dstIP.As4()
			if [4]byte(frame[38:42]) != wantDst {
				t.Errorf("target proto addr mismatch")
			}
		})
	}
}

func TestParseARPReply_ValidReply(t *testing.T) {
	senderMAC := makeMAC("11:22:33:44:55:66")
	senderIP := netip.MustParseAddr("10.0.1.42")

	frame := makeARPReply(senderMAC, senderIP)

	mac, ip, ok := parseARPReply(frame)
	if !ok {
		t.Fatal("parseARPReply returned ok=false for valid reply")
	}
	if !equalMAC(mac, senderMAC) {
		t.Errorf("MAC = %v, want %v", mac, senderMAC)
	}
	if ip != senderIP {
		t.Errorf("IP = %v, want %v", ip, senderIP)
	}
}

func TestParseARPReply_RequestIgnored(t *testing.T) {
	frame := makeARPReply(makeMAC("aa:bb:cc:dd:ee:ff"), netip.MustParseAddr("10.0.1.1"))
	// Flip operation from reply (0x0002) to request (0x0001)
	binary.BigEndian.PutUint16(frame[20:22], 0x0001)

	_, _, ok := parseARPReply(frame)
	if ok {
		t.Error("parseARPReply should return ok=false for ARP request")
	}
}

func TestParseARPReply_TooShort(t *testing.T) {
	_, _, ok := parseARPReply(make([]byte, 30))
	if ok {
		t.Error("parseARPReply should return ok=false for frame shorter than 42 bytes")
	}
}

func TestParseARPReply_WrongEtherType(t *testing.T) {
	frame := makeARPReply(makeMAC("aa:bb:cc:dd:ee:ff"), netip.MustParseAddr("10.0.1.1"))
	// Replace EtherType with 0x0800 (IPv4)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)

	_, _, ok := parseARPReply(frame)
	if ok {
		t.Error("parseARPReply should return ok=false for non-ARP EtherType")
	}
}

func TestParseARPReply_ReturnsDeepCopy(t *testing.T) {
	senderMAC := makeMAC("aa:bb:cc:dd:ee:01")
	senderIP := netip.MustParseAddr("10.0.1.1")
	frame := makeARPReply(senderMAC, senderIP)

	mac, _, ok := parseARPReply(frame)
	if !ok {
		t.Fatal("parseARPReply returned ok=false")
	}

	// Overwrite the original frame's sender MAC bytes
	for i := 22; i < 28; i++ {
		frame[i] = 0xff
	}

	// The returned MAC should be unaffected
	if equalMAC(mac, net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
		t.Error("returned MAC was not a deep copy — it was mutated when buffer was overwritten")
	}
	if !equalMAC(mac, senderMAC) {
		t.Errorf("MAC = %v, want %v after buffer mutation", mac, senderMAC)
	}
}

func TestBuildThenParse_RoundTrip(t *testing.T) {
	srcMAC := makeMAC("de:ad:be:ef:ca:fe")
	srcIP := netip.MustParseAddr("10.5.0.1")
	dstIP := netip.MustParseAddr("10.5.0.99")

	frame, err := buildARPRequest(srcMAC, srcIP, dstIP)
	if err != nil {
		t.Fatalf("buildARPRequest: %v", err)
	}

	// Transform into a reply:
	// - Change operation to reply (0x0002)
	// - Swap sender and target fields so parseARPReply sees the "responder"
	binary.BigEndian.PutUint16(frame[20:22], 0x0002) // op: reply

	// The sender fields are already srcMAC/srcIP from buildARPRequest.
	// parseARPReply reads sender MAC from [22:28] and sender IP from [28:32].

	mac, ip, ok := parseARPReply(frame)
	if !ok {
		t.Fatal("parseARPReply returned ok=false for crafted reply")
	}
	if !equalMAC(mac, srcMAC) {
		t.Errorf("MAC = %v, want %v", mac, srcMAC)
	}
	if ip != srcIP {
		t.Errorf("IP = %v, want %v", ip, srcIP)
	}
}

// equalMAC returns true if a and b have the same bytes.
func equalMAC(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
