package netutil

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func mustParsePrefix(s string) netip.Prefix {
	return netip.MustParsePrefix(s)
}

func collectAddrs(ctx context.Context, prefix netip.Prefix) []netip.Addr {
	var addrs []netip.Addr
	for addr := range SubnetAddrs(ctx, prefix) {
		addrs = append(addrs, addr)
	}
	return addrs
}

func TestSubnetAddrs_Slash24(t *testing.T) {
	ctx := context.Background()
	addrs := collectAddrs(ctx, mustParsePrefix("10.0.1.0/24"))

	if len(addrs) != 254 {
		t.Fatalf("got %d addresses, want 254", len(addrs))
	}
	if addrs[0] != netip.MustParseAddr("10.0.1.1") {
		t.Errorf("first addr = %v, want 10.0.1.1", addrs[0])
	}
	if addrs[len(addrs)-1] != netip.MustParseAddr("10.0.1.254") {
		t.Errorf("last addr = %v, want 10.0.1.254", addrs[len(addrs)-1])
	}
}

func TestSubnetAddrs_Slash32(t *testing.T) {
	ctx := context.Background()
	addrs := collectAddrs(ctx, mustParsePrefix("10.0.1.5/32"))

	if len(addrs) != 1 {
		t.Fatalf("got %d addresses, want 1", len(addrs))
	}
	if addrs[0] != netip.MustParseAddr("10.0.1.5") {
		t.Errorf("addr = %v, want 10.0.1.5", addrs[0])
	}
}

func TestSubnetAddrs_Slash31(t *testing.T) {
	ctx := context.Background()
	addrs := collectAddrs(ctx, mustParsePrefix("10.0.1.0/31"))

	if len(addrs) != 2 {
		t.Fatalf("got %d addresses, want 2 (RFC 3021)", len(addrs))
	}
	if addrs[0] != netip.MustParseAddr("10.0.1.0") {
		t.Errorf("first addr = %v, want 10.0.1.0", addrs[0])
	}
	if addrs[1] != netip.MustParseAddr("10.0.1.1") {
		t.Errorf("second addr = %v, want 10.0.1.1", addrs[1])
	}
}

func TestSubnetAddrs_Slash30(t *testing.T) {
	ctx := context.Background()
	addrs := collectAddrs(ctx, mustParsePrefix("10.0.1.0/30"))

	if len(addrs) != 2 {
		t.Fatalf("got %d addresses, want 2", len(addrs))
	}
	if addrs[0] != netip.MustParseAddr("10.0.1.1") {
		t.Errorf("first addr = %v, want 10.0.1.1", addrs[0])
	}
	if addrs[1] != netip.MustParseAddr("10.0.1.2") {
		t.Errorf("second addr = %v, want 10.0.1.2", addrs[1])
	}
}

func TestSubnetAddrs_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	ch := SubnetAddrs(ctx, mustParsePrefix("10.0.0.0/16"))

	// Read 10 addresses then cancel
	for i := 0; i < 10; i++ {
		select {
		case _, ok := <-ch:
			if !ok {
				t.Fatal("channel closed before reading 10 addresses")
			}
		case <-time.After(time.Second):
			t.Fatal("timed out reading from channel")
		}
	}
	cancel()

	// Channel should be closed shortly after cancellation
	deadline := time.After(time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return // channel closed — goroutine exited cleanly
			}
		case <-deadline:
			t.Error("channel not closed within 1s after context cancellation (goroutine leak?)")
			return
		}
	}
}

func TestSubnetAddrs_Slash16_Count(t *testing.T) {
	ctx := context.Background()
	addrs := collectAddrs(ctx, mustParsePrefix("10.1.0.0/16"))

	if len(addrs) != 65534 {
		t.Errorf("got %d addresses, want 65534", len(addrs))
	}
}

func TestSubnetSize(t *testing.T) {
	tests := []struct {
		prefix string
		want   uint64
	}{
		{"10.0.0.0/24", 254},
		{"10.0.0.0/32", 1},
		{"10.0.0.0/31", 2},
		{"10.0.0.0/30", 2},
		{"10.0.0.0/16", 65534},
		{"10.0.0.0/8", 16777214},
	}

	for _, tt := range tests {
		got := SubnetSize(mustParsePrefix(tt.prefix))
		if got != tt.want {
			t.Errorf("SubnetSize(%s) = %d, want %d", tt.prefix, got, tt.want)
		}
	}
}
