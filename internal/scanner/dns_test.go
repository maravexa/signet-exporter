package scanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/maravexa/signet-exporter/internal/state"
)

// --- mock resolver ---

// mockDNSLookup is an in-process mock for the dnsLookup interface.
type mockDNSLookup struct {
	// ptrRecords maps IP string → list of FQDNs (with trailing dot, as real resolvers return).
	ptrRecords map[string][]string
	// aRecords maps hostname (no trailing dot) → list of IP strings.
	aRecords map[string][]string
	// failAddrs maps IP string → error to return from LookupAddr.
	failAddrs map[string]error
	// failHosts maps hostname → error to return from LookupHost.
	failHosts map[string]error
}

func (m *mockDNSLookup) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if err, ok := m.failAddrs[addr]; ok {
		return nil, err
	}
	names, ok := m.ptrRecords[addr]
	if !ok {
		return nil, &net.DNSError{Err: "no PTR record", Name: addr, IsNotFound: true}
	}
	return names, nil
}

func (m *mockDNSLookup) LookupHost(_ context.Context, host string) ([]string, error) {
	if err, ok := m.failHosts[host]; ok {
		return nil, err
	}
	addrs, ok := m.aRecords[host]
	if !ok {
		return nil, &net.DNSError{Err: "no A record", Name: host, IsNotFound: true}
	}
	return addrs, nil
}

// cancelOnNthLookup wraps a dnsLookup and cancels a context after n LookupAddr calls.
type cancelOnNthLookup struct {
	n      int
	count  int
	cancel func()
	inner  dnsLookup
}

func (c *cancelOnNthLookup) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	c.count++
	if c.count >= c.n {
		c.cancel()
	}
	return c.inner.LookupAddr(ctx, addr)
}

func (c *cancelOnNthLookup) LookupHost(ctx context.Context, host string) ([]string, error) {
	return c.inner.LookupHost(ctx, host)
}

// --- helpers ---

// newDNSWithMock creates a DNSScanner wired to store and mock for testing.
func newDNSWithMock(store state.Store, mock dnsLookup) *DNSScanner {
	return &DNSScanner{
		store:   store,
		lookup:  mock,
		timeout: 2 * time.Second,
		logger:  slog.Default(),
	}
}

func insertHost(t *testing.T, store state.Store, ip, mac string) {
	t.Helper()
	hw, err := net.ParseMAC(mac)
	if err != nil {
		t.Fatalf("invalid MAC %q: %v", mac, err)
	}
	rec := state.HostRecord{
		IP:       netip.MustParseAddr(ip),
		MAC:      hw,
		LastSeen: time.Now(),
		Alive:    true,
	}
	if _, err := store.UpdateHost(context.Background(), rec); err != nil {
		t.Fatalf("UpdateHost: %v", err)
	}
}

// findResult returns the ScanResult for ip in results, or nil.
func findResult(results []ScanResult, ip string) *ScanResult {
	want := netip.MustParseAddr(ip)
	for i := range results {
		if results[i].IP == want {
			return &results[i]
		}
	}
	return nil
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// --- tests ---

// TestDNSScan_ConsistentRecords verifies that hosts with consistent PTR+A records
// get their Hostnames populated and have an empty (not nil) DNSMismatches slice.
func TestDNSScan_ConsistentRecords(t *testing.T) {
	store := state.NewMemoryStore()
	insertHost(t, store, "10.0.1.1", "aa:bb:cc:dd:ee:01")
	insertHost(t, store, "10.0.1.2", "aa:bb:cc:dd:ee:02")

	mock := &mockDNSLookup{
		ptrRecords: map[string][]string{
			"10.0.1.1": {"server1.example.com."},
			"10.0.1.2": {"server2.example.com."},
		},
		aRecords: map[string][]string{
			"server1.example.com": {"10.0.1.1"},
			"server2.example.com": {"10.0.1.2"},
		},
	}

	scanner := newDNSWithMock(store, mock)
	results, err := scanner.Scan(context.Background(), netip.MustParsePrefix("10.0.1.0/24"))
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	for _, ip := range []string{"10.0.1.1", "10.0.1.2"} {
		r := findResult(results, ip)
		if r == nil {
			t.Errorf("no result for %s", ip)
			continue
		}
		if len(r.Hostnames) == 0 {
			t.Errorf("%s: Hostnames is empty", ip)
		}
		if r.DNSMismatches == nil {
			t.Errorf("%s: DNSMismatches is nil, want empty slice", ip)
		}
		if len(r.DNSMismatches) != 0 {
			t.Errorf("%s: DNSMismatches = %v, want empty", ip, r.DNSMismatches)
		}
	}
}

// TestDNSScan_ForwardReverseMismatch verifies that a hostname whose forward
// lookup returns a different IP is flagged in DNSMismatches.
func TestDNSScan_ForwardReverseMismatch(t *testing.T) {
	store := state.NewMemoryStore()
	insertHost(t, store, "10.0.1.1", "aa:bb:cc:dd:ee:01")

	mock := &mockDNSLookup{
		ptrRecords: map[string][]string{
			"10.0.1.1": {"server1.example.com."},
		},
		aRecords: map[string][]string{
			"server1.example.com": {"10.0.1.99"}, // different IP!
		},
	}

	scanner := newDNSWithMock(store, mock)
	results, err := scanner.Scan(context.Background(), netip.MustParsePrefix("10.0.1.0/24"))
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := &results[0]
	if !containsString(r.DNSMismatches, "server1.example.com") {
		t.Errorf("DNSMismatches = %v, want to contain %q", r.DNSMismatches, "server1.example.com")
	}
}

// TestDNSScan_NoPTRRecord verifies that a successful negative PTR lookup emits
// an explicit empty result, allowing source-owned state to clear stale DNS data.
func TestDNSScan_NoPTRRecord(t *testing.T) {
	store := state.NewMemoryStore()
	insertHost(t, store, "10.0.1.1", "aa:bb:cc:dd:ee:01")

	mock := &mockDNSLookup{
		ptrRecords: map[string][]string{}, // no PTR records
		aRecords:   map[string][]string{},
	}

	scanner := newDNSWithMock(store, mock)
	results, err := scanner.Scan(context.Background(), netip.MustParsePrefix("10.0.1.0/24"))
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one explicit empty result for host with no PTR, got %d", len(results))
	}
	if results[0].Hostnames == nil || results[0].DNSMismatches == nil {
		t.Errorf("successful empty DNS result must carry non-nil owned fields: %+v", results[0])
	}
	if len(results[0].Hostnames) != 0 || len(results[0].DNSMismatches) != 0 {
		t.Errorf("expected empty DNS fields, got hostnames=%v mismatches=%v", results[0].Hostnames, results[0].DNSMismatches)
	}
}

func TestDNSScan_PreservesDiscoveryLiveness(t *testing.T) {
	store := state.NewMemoryStore()
	oldSeen := time.Now().Add(-time.Hour).Round(0)
	mac, err := net.ParseMAC("aa:bb:cc:dd:ee:01")
	if err != nil {
		t.Fatal(err)
	}
	host := state.HostRecord{
		IP:       netip.MustParseAddr("10.0.1.1"),
		MAC:      mac,
		LastSeen: oldSeen,
		Alive:    false,
	}
	if _, err := store.UpdateHost(context.Background(), host); err != nil {
		t.Fatal(err)
	}
	scanner := newDNSWithMock(store, &mockDNSLookup{
		ptrRecords: map[string][]string{"10.0.1.1": {"server.example.com."}},
		aRecords:   map[string][]string{"server.example.com": {"10.0.1.1"}},
	})
	results, err := scanner.Scan(context.Background(), netip.MustParsePrefix("10.0.1.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if results[0].Alive {
		t.Errorf("DNS result changed discovery liveness: Alive=%t", results[0].Alive)
	}
	if !results[0].Timestamp.After(oldSeen) {
		t.Errorf("DNS observation timestamp %s was not refreshed after %s", results[0].Timestamp, oldSeen)
	}
}

// TestDNSScan_ForwardLookupFails verifies that a hostname whose forward lookup
// fails is treated as a mismatch (cannot verify = mismatch).
func TestDNSScan_ForwardLookupFailurePreservesPriorObservation(t *testing.T) {
	store := state.NewMemoryStore()
	insertHost(t, store, "10.0.1.1", "aa:bb:cc:dd:ee:01")

	mock := &mockDNSLookup{
		ptrRecords: map[string][]string{
			"10.0.1.1": {"server1.example.com."},
		},
		failHosts: map[string]error{
			"server1.example.com": errors.New("SERVFAIL"),
		},
	}

	scanner := newDNSWithMock(store, mock)
	results, err := scanner.Scan(context.Background(), netip.MustParsePrefix("10.0.1.0/24"))
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("forward lookup transport failure returned %d updates; want preservation", len(results))
	}
}

func TestDNSScan_ForwardTransportFailurePreservesPriorObservation(t *testing.T) {
	store := state.NewMemoryStore()
	insertHost(t, store, "10.0.1.1", "aa:bb:cc:dd:ee:01")

	scanner := newDNSWithMock(store, &mockDNSLookup{
		ptrRecords: map[string][]string{"10.0.1.1": {"server1.example.com."}},
		failHosts:  map[string]error{"server1.example.com": errors.New("resolver timeout")},
	})
	results, err := scanner.Scan(context.Background(), netip.MustParsePrefix("10.0.1.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Fatalf("forward transport failure returned DNS update %v; want preservation", results)
	}
}

// TestDNSScan_MultipleHostnames verifies that a host with multiple PTR records
// gets all names in Hostnames and only the mismatching ones in DNSMismatches.
func TestDNSScan_MultipleHostnames(t *testing.T) {
	store := state.NewMemoryStore()
	insertHost(t, store, "10.0.1.1", "aa:bb:cc:dd:ee:01")

	mock := &mockDNSLookup{
		ptrRecords: map[string][]string{
			"10.0.1.1": {"web.example.com.", "server1.example.com."},
		},
		aRecords: map[string][]string{
			// web.example.com → 10.0.1.1 (consistent), server1 → 10.0.1.99 (mismatch)
			"web.example.com":     {"10.0.1.1"},
			"server1.example.com": {"10.0.1.99"},
		},
	}

	scanner := newDNSWithMock(store, mock)
	results, err := scanner.Scan(context.Background(), netip.MustParsePrefix("10.0.1.0/24"))
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := &results[0]
	if len(r.Hostnames) != 2 {
		t.Errorf("Hostnames = %v, want 2 names", r.Hostnames)
	}
	if containsString(r.DNSMismatches, "web.example.com") {
		t.Errorf("web.example.com should not be in DNSMismatches (it's consistent)")
	}
	if !containsString(r.DNSMismatches, "server1.example.com") {
		t.Errorf("server1.example.com should be in DNSMismatches (it mismatches)")
	}
}

func TestDNSScan_CapsAndSortsHostnameEvidence(t *testing.T) {
	store := state.NewMemoryStore()
	insertHost(t, store, "10.0.1.1", "aa:bb:cc:dd:ee:01")
	names := make([]string, 0, maxDNSNamesPerHost+8)
	aRecords := make(map[string][]string)
	for i := maxDNSNamesPerHost + 7; i >= 0; i-- {
		name := fmt.Sprintf("host-%02d.example.com", i)
		names = append(names, name+".")
		aRecords[name] = []string{"10.0.1.1"}
	}
	// Include a duplicate to verify normalized unique output.
	names = append(names, names[0])
	scanner := newDNSWithMock(store, &mockDNSLookup{
		ptrRecords: map[string][]string{"10.0.1.1": names},
		aRecords:   aRecords,
	})
	results, err := scanner.Scan(context.Background(), netip.MustParsePrefix("10.0.1.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	r := results[0]
	if len(r.Hostnames) != maxDNSNamesPerHost || r.Metadata["dns_results_truncated"] != "true" {
		t.Fatalf("hostnames=%d metadata=%v; want cap %d and truncation", len(r.Hostnames), r.Metadata, maxDNSNamesPerHost)
	}
	for i := 1; i < len(r.Hostnames); i++ {
		if r.Hostnames[i-1] > r.Hostnames[i] {
			t.Fatalf("hostnames not sorted: %v", r.Hostnames)
		}
	}
}

// TestDNSScan_TrailingDotStripped verifies that FQDNs with trailing dots are
// stored without the trailing dot.
func TestDNSScan_TrailingDotStripped(t *testing.T) {
	store := state.NewMemoryStore()
	insertHost(t, store, "10.0.1.1", "aa:bb:cc:dd:ee:01")

	mock := &mockDNSLookup{
		ptrRecords: map[string][]string{
			"10.0.1.1": {"server1.example.com."}, // with trailing dot
		},
		aRecords: map[string][]string{
			"server1.example.com": {"10.0.1.1"},
		},
	}

	scanner := newDNSWithMock(store, mock)
	results, err := scanner.Scan(context.Background(), netip.MustParsePrefix("10.0.1.0/24"))
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	for _, name := range results[0].Hostnames {
		if len(name) > 0 && name[len(name)-1] == '.' {
			t.Errorf("hostname %q has trailing dot, want it stripped", name)
		}
	}
	if !containsString(results[0].Hostnames, "server1.example.com") {
		t.Errorf("Hostnames = %v, want to contain %q", results[0].Hostnames, "server1.example.com")
	}
}

// TestDNSScan_EmptyStore verifies that scanning an empty subnet returns no
// results and no error.
func TestDNSScan_EmptyStore(t *testing.T) {
	store := state.NewMemoryStore()

	mock := &mockDNSLookup{
		ptrRecords: map[string][]string{},
		aRecords:   map[string][]string{},
	}

	scanner := newDNSWithMock(store, mock)
	results, err := scanner.Scan(context.Background(), netip.MustParsePrefix("10.0.1.0/24"))
	if err != nil {
		t.Fatalf("Scan error on empty store: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty store, got %d", len(results))
	}
}

// TestDNSScan_ContextCancellation verifies that cancellation is not represented
// as a successful partial enrichment scan.
func TestDNSScan_ContextCancellation(t *testing.T) {
	store := state.NewMemoryStore()
	// Insert 20 hosts, all with PTR records.
	innerMock := &mockDNSLookup{
		ptrRecords: make(map[string][]string),
		aRecords:   make(map[string][]string),
	}
	for i := 1; i <= 20; i++ {
		ip := netip.AddrFrom4([4]byte{10, 0, 1, byte(i)}).String()
		mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, byte(i)}.String()
		insertHost(t, store, ip, mac)
		hostname := "host" + ip + ".example.com"
		innerMock.ptrRecords[ip] = []string{hostname + "."}
		innerMock.aRecords[hostname] = []string{ip}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Cancel after the 5th reverse lookup.
	mock := &cancelOnNthLookup{n: 5, cancel: cancel, inner: innerMock}

	scanner := newDNSWithMock(store, mock)
	results, err := scanner.Scan(ctx, netip.MustParsePrefix("10.0.1.0/24"))

	// Should return a context error.
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	if results != nil {
		t.Errorf("cancelled scan returned partial results %v; want nil", results)
	}
}
