package scanner

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/maravexa/signet-exporter/internal/state"
)

// startTestListener creates a TCP listener on a random port bound to all interfaces.
// Binding to 0.0.0.0 allows both 127.0.0.1 and 127.0.0.2 (both loopback on Linux) to connect.
// Returns the port number and a cleanup function.
func startTestListener(t *testing.T) (uint16, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("failed to start test listener: %v", err)
	}

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	port := uint16(l.Addr().(*net.TCPAddr).Port)
	return port, func() { l.Close() }
}

func newTestPortScanner(store state.Store, subnetPorts map[string][]uint16, defaultPorts []uint16) *PortScanner {
	return NewPortScanner(store, subnetPorts, defaultPorts, 500*time.Millisecond, 32, nil)
}

func TestCheckPort_OpenPort(t *testing.T) {
	port, cleanup := startTestListener(t)
	defer cleanup()

	p := newTestPortScanner(state.NewMemoryStore(), nil, nil)
	ip := netip.MustParseAddr("127.0.0.1")

	if !p.checkPort(context.Background(), ip, port) {
		t.Errorf("expected port %d to be open", port)
	}
}

func TestCheckPort_ClosedPort(t *testing.T) {
	p := newTestPortScanner(state.NewMemoryStore(), nil, nil)
	ip := netip.MustParseAddr("127.0.0.1")

	// Port 59999 is very unlikely to be in use; if it is this test may flake.
	if p.checkPort(context.Background(), ip, 59999) {
		t.Error("expected port 59999 to be closed")
	}
}

func TestCheckPort_Timeout(t *testing.T) {
	p := newTestPortScanner(state.NewMemoryStore(), nil, nil)
	// Use a very short context deadline to force a timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	ip := netip.MustParseAddr("10.255.255.1") // non-routable, will time out
	start := time.Now()
	open := p.checkPort(ctx, ip, 80)
	elapsed := time.Since(start)

	if open {
		t.Error("expected non-routable address to return false")
	}
	// Should return quickly (context fires at 10ms + small epsilon), not hang for the full 500ms timeout.
	if elapsed > 500*time.Millisecond {
		t.Errorf("checkPort took too long (%v), expected it to respect context deadline", elapsed)
	}
}

func TestCheckPort_ContextCancelled(t *testing.T) {
	p := newTestPortScanner(state.NewMemoryStore(), nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	ip := netip.MustParseAddr("127.0.0.1")
	if p.checkPort(ctx, ip, 80) {
		t.Error("expected cancelled context to return false")
	}
}

func TestPortScan_FullCycle(t *testing.T) {
	port1, cleanup1 := startTestListener(t)
	defer cleanup1()
	port2, cleanup2 := startTestListener(t)
	defer cleanup2()
	port3, cleanup3 := startTestListener(t)
	defer cleanup3()

	// closedPort should not appear in results.
	closedPort := uint16(59998)

	store := state.NewMemoryStore()
	ip := netip.MustParseAddr("127.0.0.1")
	subnet := netip.MustParsePrefix("127.0.0.1/32")

	_ = store.UpdateHost(context.Background(), state.HostRecord{
		IP:       ip,
		LastSeen: time.Now(),
		Alive:    true,
	})

	ports := []uint16{port1, port2, port3, closedPort}
	p := newTestPortScanner(store, map[string][]uint16{subnet.String(): ports}, nil)

	results, err := p.Scan(context.Background(), subnet)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if r.IP != ip {
		t.Errorf("expected IP %v, got %v", ip, r.IP)
	}
	if len(r.OpenPorts) != 3 {
		t.Errorf("expected 3 open ports, got %d: %v", len(r.OpenPorts), r.OpenPorts)
	}

	// Verify closed port is absent.
	for _, p := range r.OpenPorts {
		if p == closedPort {
			t.Errorf("closed port %d should not appear in open ports", closedPort)
		}
	}

	// Verify ports are sorted.
	for i := 1; i < len(r.OpenPorts); i++ {
		if r.OpenPorts[i] < r.OpenPorts[i-1] {
			t.Errorf("ports not sorted: %v", r.OpenPorts)
		}
	}
}

func TestPortScan_NoPorts_ReturnsNil(t *testing.T) {
	store := state.NewMemoryStore()
	subnet := netip.MustParsePrefix("10.0.0.0/24")

	// No ports configured for this subnet, no default ports.
	p := newTestPortScanner(store, nil, nil)

	results, err := p.Scan(context.Background(), subnet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results != nil {
		t.Errorf("expected nil results when no ports configured, got %v", results)
	}
}

func TestPortScan_EmptyStore_ReturnsNil(t *testing.T) {
	store := state.NewMemoryStore()
	subnet := netip.MustParsePrefix("10.0.0.0/24")

	p := newTestPortScanner(store, map[string][]uint16{subnet.String(): {80, 443}}, nil)

	results, err := p.Scan(context.Background(), subnet)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if results != nil {
		t.Errorf("expected nil results for empty store, got %v", results)
	}
}

func TestPortScan_MultipleHosts(t *testing.T) {
	port1, cleanup1 := startTestListener(t)
	defer cleanup1()
	port2, cleanup2 := startTestListener(t)
	defer cleanup2()

	store := state.NewMemoryStore()
	// Both 127.0.0.1 and 127.0.0.2 are loopback on Linux.
	ip1 := netip.MustParseAddr("127.0.0.1")
	ip2 := netip.MustParseAddr("127.0.0.2")
	subnet := netip.MustParsePrefix("127.0.0.0/24")

	for _, ip := range []netip.Addr{ip1, ip2} {
		_ = store.UpdateHost(context.Background(), state.HostRecord{
			IP:       ip,
			LastSeen: time.Now(),
			Alive:    true,
		})
	}

	ports := []uint16{port1, port2}
	p := newTestPortScanner(store, map[string][]uint16{subnet.String(): ports}, nil)

	results, err := p.Scan(context.Background(), subnet)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	for _, r := range results {
		if len(r.OpenPorts) != 2 {
			t.Errorf("host %v: expected 2 open ports, got %d: %v", r.IP, len(r.OpenPorts), r.OpenPorts)
		}
	}
}

func TestPortScan_WorkerPoolLimiting(t *testing.T) {
	port, cleanup := startTestListener(t)
	defer cleanup()

	store := state.NewMemoryStore()
	subnet := netip.MustParsePrefix("127.0.0.0/24")

	// Insert 20 hosts — all pointing to loopback (will connect to the same listener).
	for i := 1; i <= 20; i++ {
		ip := netip.AddrFrom4([4]byte{127, 0, 0, byte(i)})
		_ = store.UpdateHost(context.Background(), state.HostRecord{
			IP:       ip,
			LastSeen: time.Now(),
			Alive:    true,
		})
	}

	// maxWorkers=4 to exercise the semaphore path.
	p := NewPortScanner(store, map[string][]uint16{subnet.String(): {port}}, nil, 500*time.Millisecond, 4, nil)

	results, err := p.Scan(context.Background(), subnet)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}
	if len(results) == 0 {
		t.Error("expected at least one result from worker pool scan")
	}
}

func TestPortScan_SubnetSpecificPorts(t *testing.T) {
	portA, cleanupA := startTestListener(t)
	defer cleanupA()
	portB, cleanupB := startTestListener(t)
	defer cleanupB()

	store := state.NewMemoryStore()
	subnetA := netip.MustParsePrefix("127.0.0.1/32")
	subnetB := netip.MustParsePrefix("127.0.0.2/32")

	ipA := netip.MustParseAddr("127.0.0.1")
	ipB := netip.MustParseAddr("127.0.0.2")

	for _, h := range []struct {
		ip netip.Addr
	}{{ipA}, {ipB}} {
		_ = store.UpdateHost(context.Background(), state.HostRecord{
			IP:       h.ip,
			LastSeen: time.Now(),
			Alive:    true,
		})
	}

	subnetPorts := map[string][]uint16{
		subnetA.String(): {portA},
		subnetB.String(): {portB},
	}
	p := newTestPortScanner(store, subnetPorts, nil)

	// Subnet A should only scan portA.
	resultsA, err := p.Scan(context.Background(), subnetA)
	if err != nil {
		t.Fatalf("Scan A error: %v", err)
	}
	if len(resultsA) != 1 {
		t.Fatalf("subnet A: expected 1 result, got %d", len(resultsA))
	}
	if len(resultsA[0].OpenPorts) != 1 || resultsA[0].OpenPorts[0] != portA {
		t.Errorf("subnet A: expected only portA (%d), got %v", portA, resultsA[0].OpenPorts)
	}

	// Subnet B should only scan portB.
	resultsB, err := p.Scan(context.Background(), subnetB)
	if err != nil {
		t.Fatalf("Scan B error: %v", err)
	}
	if len(resultsB) != 1 {
		t.Fatalf("subnet B: expected 1 result, got %d", len(resultsB))
	}
	if len(resultsB[0].OpenPorts) != 1 || resultsB[0].OpenPorts[0] != portB {
		t.Errorf("subnet B: expected only portB (%d), got %v", portB, resultsB[0].OpenPorts)
	}
}
