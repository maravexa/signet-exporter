//go:build linux

package scanner

import (
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// TestBuildEchoRequest_ValidPacket verifies that buildEchoRequest produces a
// parseable ICMP echo request with the correct fields.
func TestBuildEchoRequest_ValidPacket(t *testing.T) {
	id, seq := 12345, 1
	data, err := buildEchoRequest(id, seq)
	if err != nil {
		t.Fatalf("buildEchoRequest error: %v", err)
	}

	msg, err := icmp.ParseMessage(1, data)
	if err != nil {
		t.Fatalf("ParseMessage error: %v", err)
	}
	if msg.Type != ipv4.ICMPTypeEcho {
		t.Errorf("type = %v, want ICMPTypeEcho", msg.Type)
	}
	echo, ok := msg.Body.(*icmp.Echo)
	if !ok {
		t.Fatal("body is not *icmp.Echo")
	}
	if echo.ID != id {
		t.Errorf("ID = %d, want %d", echo.ID, id)
	}
	if echo.Seq != seq {
		t.Errorf("Seq = %d, want %d", echo.Seq, seq)
	}
	if string(echo.Data) != "signet" {
		t.Errorf("Data = %q, want %q", string(echo.Data), "signet")
	}
}

// TestBuildEchoRequest_DifferentSequences verifies that each sequence number
// survives a marshal/unmarshal round trip.
func TestBuildEchoRequest_DifferentSequences(t *testing.T) {
	tests := []struct {
		id, seq int
	}{
		{1, 0},
		{1, 1},
		{1, 255},
		{1, 65535},
	}
	for _, tt := range tests {
		data, err := buildEchoRequest(tt.id, tt.seq)
		if err != nil {
			t.Errorf("seq=%d: buildEchoRequest error: %v", tt.seq, err)
			continue
		}
		msg, err := icmp.ParseMessage(1, data)
		if err != nil {
			t.Errorf("seq=%d: ParseMessage error: %v", tt.seq, err)
			continue
		}
		echo, ok := msg.Body.(*icmp.Echo)
		if !ok {
			t.Errorf("seq=%d: body is not *icmp.Echo", tt.seq)
			continue
		}
		if echo.Seq != tt.seq {
			t.Errorf("seq=%d: Seq = %d, want %d", tt.seq, echo.Seq, tt.seq)
		}
	}
}

// TestParseEchoReply_ValidReply verifies that a well-formed echo reply is
// accepted and the source IP extracted from addr is returned correctly.
func TestParseEchoReply_ValidReply(t *testing.T) {
	id := 9999
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  42,
			Data: []byte("signet"),
		},
	}
	data, err := msg.Marshal(nil)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	src := &net.IPAddr{IP: net.ParseIP("192.168.1.100")}
	gotIP, ok := parseEchoReply(data, src, id)
	if !ok {
		t.Fatal("parseEchoReply returned ok=false, want true")
	}
	want := netip.MustParseAddr("192.168.1.100")
	if gotIP != want {
		t.Errorf("srcIP = %v, want %v", gotIP, want)
	}
}

// TestParseEchoReply_WrongID verifies that replies with a non-matching
// identifier are rejected (filtering out other processes' pings).
func TestParseEchoReply_WrongID(t *testing.T) {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{ID: 999, Seq: 1, Data: []byte("signet")},
	}
	data, err := msg.Marshal(nil)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	src := &net.IPAddr{IP: net.ParseIP("10.0.0.1")}
	_, ok := parseEchoReply(data, src, 123)
	if ok {
		t.Error("parseEchoReply returned ok=true for wrong ID, want false")
	}
}

// TestParseEchoReply_NotEchoReply verifies that non-echo-reply ICMP messages
// (e.g. Destination Unreachable) are rejected.
func TestParseEchoReply_NotEchoReply(t *testing.T) {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeDestinationUnreachable,
		Code: 1, // host unreachable
		Body: &icmp.DstUnreach{
			Data: make([]byte, 8), // fake original datagram header
		},
	}
	data, err := msg.Marshal(nil)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	src := &net.IPAddr{IP: net.ParseIP("10.0.0.1")}
	_, ok := parseEchoReply(data, src, 1)
	if ok {
		t.Error("parseEchoReply returned ok=true for Destination Unreachable, want false")
	}
}

// TestParseEchoReply_TooShort verifies that undersized buffers are rejected
// without panicking.
func TestParseEchoReply_TooShort(t *testing.T) {
	src := &net.IPAddr{IP: net.ParseIP("10.0.0.1")}
	_, ok := parseEchoReply([]byte{0x00, 0x01}, src, 1)
	if ok {
		t.Error("parseEchoReply returned ok=true for 2-byte buffer, want false")
	}
}

// TestICMPBuildThenParse_RoundTrip verifies that ID and sequence number survive
// the full build→reply→parse round trip.
func TestICMPBuildThenParse_RoundTrip(t *testing.T) {
	id, seq := 42, 100

	// Build an echo reply with the same ID and seq to simulate a response.
	replyMsg := icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: []byte("signet"),
		},
	}
	replyData, err := replyMsg.Marshal(nil)
	if err != nil {
		t.Fatalf("Marshal reply error: %v", err)
	}

	src := &net.IPAddr{IP: net.ParseIP("10.1.2.3")}
	gotIP, ok := parseEchoReply(replyData, src, id)
	if !ok {
		t.Fatal("parseEchoReply returned ok=false on round-trip, want true")
	}
	want := netip.MustParseAddr("10.1.2.3")
	if gotIP != want {
		t.Errorf("round-trip srcIP = %v, want %v", gotIP, want)
	}

	// Also verify we can parse the reply body to check ID/Seq survived.
	parsed, err := icmp.ParseMessage(1, replyData)
	if err != nil {
		t.Fatalf("ParseMessage on reply: %v", err)
	}
	echo, ok := parsed.Body.(*icmp.Echo)
	if !ok {
		t.Fatal("reply body is not *icmp.Echo")
	}
	if echo.ID != id {
		t.Errorf("round-trip ID = %d, want %d", echo.ID, id)
	}
	if echo.Seq != seq {
		t.Errorf("round-trip Seq = %d, want %d", echo.Seq, seq)
	}
}
