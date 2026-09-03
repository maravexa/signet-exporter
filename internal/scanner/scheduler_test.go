package scanner

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/maravexa/signet-exporter/internal/audit"
	"github.com/maravexa/signet-exporter/internal/state"
)

// --- mock scanners ---

type mockScanner struct {
	name    string
	results []ScanResult
	err     error
	calls   atomic.Int32
	delay   time.Duration
}

func (m *mockScanner) Name() string { return m.name }

func (m *mockScanner) Scan(ctx context.Context, _ netip.Prefix) ([]ScanResult, error) {
	m.calls.Add(1)
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return m.results, m.err
}

// concurrencyTrackingScanner counts peak concurrent Scan invocations.
type concurrencyTrackingScanner struct {
	active  atomic.Int32
	maxSeen atomic.Int32
	delay   time.Duration
}

type rejectAuthorizationStore struct{ state.Store }

func (s rejectAuthorizationStore) UpdateHost(ctx context.Context, record state.HostRecord) (state.HostChange, error) {
	if record.Source == state.SourceAuthorization {
		return state.HostChange{}, nil
	}
	return s.Store.UpdateHost(ctx, record)
}

func (c *concurrencyTrackingScanner) Name() string { return "arp" }

func (c *concurrencyTrackingScanner) Scan(ctx context.Context, _ netip.Prefix) ([]ScanResult, error) {
	current := c.active.Add(1)
	defer c.active.Add(-1)

	// Track peak concurrency with a CAS loop.
	for {
		old := c.maxSeen.Load()
		if current <= old {
			break
		}
		if c.maxSeen.CompareAndSwap(old, current) {
			break
		}
	}

	select {
	case <-time.After(c.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return nil, nil
}

// --- helpers ---

func makeSubnetConfig(cidr string, interval time.Duration) SubnetConfig {
	return SubnetConfig{
		Prefix:       netip.MustParsePrefix(cidr),
		ScanInterval: interval,
	}
}

func makeScanResult(ip, mac string) ScanResult {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		panic("bad MAC: " + err.Error())
	}
	return ScanResult{
		IP:        netip.MustParseAddr(ip),
		MAC:       hw,
		Alive:     true,
		Source:    "arp",
		Timestamp: time.Now(),
	}
}

func waitReady(t *testing.T, sched *Scheduler, timeout time.Duration) {
	t.Helper()
	select {
	case <-sched.Ready():
	case <-time.After(timeout):
		t.Fatal("scheduler did not become ready within timeout")
	}
}

// --- tests ---

func TestScheduler_ImmediateFirstScan(t *testing.T) {
	store := state.NewMemoryStore()
	subnet := makeSubnetConfig("10.1.0.0/24", time.Hour) // long interval — only first scan matters

	mock := &mockScanner{
		name: "arp",
		results: []ScanResult{
			makeScanResult("10.1.0.1", "aa:bb:cc:dd:ee:01"),
			makeScanResult("10.1.0.2", "aa:bb:cc:dd:ee:02"),
		},
	}

	sched := NewScheduler([]Scanner{mock}, store, []SubnetConfig{subnet}, 2, nil, nil, nil, nil, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = sched.Run(ctx) }()
	waitReady(t, sched, 5*time.Second)

	// Exactly one scan should have run.
	if got := mock.calls.Load(); got != 1 {
		t.Errorf("scanner called %d times, want 1", got)
	}

	// Store should have both hosts.
	ctx2 := context.Background()
	hosts, err := store.ListHosts(ctx2, subnet.Prefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 {
		t.Errorf("store has %d hosts, want 2", len(hosts))
	}

	cancel()
}

func TestScheduler_PeriodicScans(t *testing.T) {
	store := state.NewMemoryStore()
	subnet := makeSubnetConfig("10.2.0.0/24", 80*time.Millisecond)

	mock := &mockScanner{name: "arp"}
	sched := NewScheduler([]Scanner{mock}, store, []SubnetConfig{subnet}, 2, nil, nil, nil, nil, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = sched.Run(ctx) }()
	waitReady(t, sched, 5*time.Second)

	// Wait for 2–3 periodic ticks after the first scan.
	time.Sleep(280 * time.Millisecond)
	cancel()

	calls := mock.calls.Load()
	// Expect: 1 (immediate) + 3 ticks in 280ms at 80ms interval = 4 calls. Accept 3–5 for timing jitter.
	if calls < 3 || calls > 6 {
		t.Errorf("scanner called %d times, want 3–6", calls)
	}
}

func TestScheduler_ConcurrencyLimit(t *testing.T) {
	store := state.NewMemoryStore()
	delay := 150 * time.Millisecond
	maxParallel := 2

	// 4 subnets, each scan takes 150ms.
	subnets := []SubnetConfig{
		makeSubnetConfig("10.3.0.0/24", time.Hour),
		makeSubnetConfig("10.3.1.0/24", time.Hour),
		makeSubnetConfig("10.3.2.0/24", time.Hour),
		makeSubnetConfig("10.3.3.0/24", time.Hour),
	}

	tracker := &concurrencyTrackingScanner{delay: delay}
	sched := NewScheduler([]Scanner{tracker}, store, subnets, maxParallel, nil, nil, nil, nil, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = sched.Run(ctx) }()

	// Wait long enough for all 4 subnets to finish their first scan (2 batches of 2 × 150ms).
	waitReady(t, sched, 5*time.Second)
	cancel()

	if got := tracker.maxSeen.Load(); got > int32(maxParallel) {
		t.Errorf("peak concurrent scans = %d, want <= %d", got, maxParallel)
	}
	if got := tracker.maxSeen.Load(); got == 0 {
		t.Error("no scans ran")
	}
}

func TestScheduler_ScanError_Continues(t *testing.T) {
	ctx := context.Background()
	store := state.NewMemoryStore()
	subnet := makeSubnetConfig("10.4.0.0/24", 60*time.Millisecond)

	mock := &mockScanner{name: "arp", err: errFakeScanError}
	sched := NewScheduler([]Scanner{mock}, store, []SubnetConfig{subnet}, 2, nil, nil, nil, nil, 0)
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = sched.Run(runCtx) }()
	// A failed discovery cycle is not a usable readiness signal.
	select {
	case <-sched.Ready():
		t.Fatal("scheduler became ready after only failed discovery scans")
	case <-time.After(150 * time.Millisecond):
	}
	cancel()

	calls := mock.calls.Load()
	if calls < 2 {
		t.Errorf("scanner called %d times on error path, want >= 2 (errors must not stop the loop)", calls)
	}

	// Scan error metadata must have been recorded.
	metas, err := store.GetScanMeta(ctx, subnet.Prefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) == 0 {
		t.Fatal("no scan metadata recorded after error scan")
	}
	if metas[0].ErrorCount == 0 {
		t.Error("ErrorCount should be > 0 after scan errors")
	}
}

// errFakeScanError is a sentinel error returned by the mock scanner in error tests.
var errFakeScanError = &fakeError{"simulated scan failure"}

type fakeError struct{ msg string }

func (e *fakeError) Error() string { return e.msg }

func TestScheduler_ContextCancellation(t *testing.T) {
	store := state.NewMemoryStore()
	// Use a very short delay so the scan doesn't block shutdown too long.
	subnet := makeSubnetConfig("10.5.0.0/24", time.Hour)
	mock := &mockScanner{name: "arp", delay: 10 * time.Millisecond}

	sched := NewScheduler([]Scanner{mock}, store, []SubnetConfig{subnet}, 2, nil, nil, nil, nil, 0)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = sched.Run(ctx)
	}()

	// Cancel immediately after starting.
	cancel()

	select {
	case <-done:
		// Run returned promptly — correct.
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3s after context cancellation")
	}
}

func TestScheduler_PrunesExpiredHostsBeforeFirstScan(t *testing.T) {
	store := state.NewMemoryStore()
	subnet := makeSubnetConfig("10.5.1.0/24", time.Hour)
	old := time.Now().Add(-2 * time.Hour)
	_, err := store.UpdateHost(context.Background(), state.HostRecord{
		IP:       netip.MustParseAddr("10.5.1.10"),
		LastSeen: old,
		Alive:    true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// The scanner's first result is intentionally empty: a stale persisted host
	// must be removed before the normal scan/readiness path begins.
	mock := &mockScanner{name: "arp"}
	sched := NewScheduler([]Scanner{mock}, store, []SubnetConfig{subnet}, 1, nil, nil, nil, nil, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = sched.Run(ctx) }()
	waitReady(t, sched, 5*time.Second)

	host, err := store.GetHost(context.Background(), netip.MustParseAddr("10.5.1.10"))
	if err != nil {
		t.Fatal(err)
	}
	if host != nil {
		t.Fatalf("expired host remained after scheduler startup: %+v", host)
	}
}

func TestScheduler_NormalizesDuplicateAndOverlappingSubnets(t *testing.T) {
	store := state.NewMemoryStore()
	mock := &mockScanner{name: "arp"}
	sched := NewScheduler([]Scanner{mock}, store, []SubnetConfig{
		makeSubnetConfig("10.5.2.0/24", time.Hour),
		makeSubnetConfig("10.5.2.42/24", time.Hour), // canonical duplicate
		makeSubnetConfig("10.5.0.0/16", time.Hour),  // overlap
	}, 2, nil, nil, nil, nil, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = sched.Run(ctx) }()
	waitReady(t, sched, 5*time.Second)
	if got := mock.calls.Load(); got != 1 {
		t.Fatalf("duplicate/overlap normalization ran %d scans, want 1", got)
	}
}

func TestScheduler_ConcurrentReloadStartsOneWorkerPerNewSubnet(t *testing.T) {
	store := state.NewMemoryStore()
	tracker := &concurrencyTrackingScanner{delay: 30 * time.Millisecond}
	sched := NewScheduler([]Scanner{tracker}, store, nil, 4, nil, nil, nil, nil, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = sched.Run(ctx) }()
	waitReady(t, sched, 5*time.Second) // empty initial config is immediately ready

	params := ApplyConfigParams{Subnets: []SubnetConfig{makeSubnetConfig("10.5.3.0/24", time.Hour)}}
	const reloads = 12
	done := make(chan struct{}, reloads)
	for i := 0; i < reloads; i++ {
		go func() {
			sched.ApplyConfig(params)
			done <- struct{}{}
		}()
	}
	for i := 0; i < reloads; i++ {
		<-done
	}

	deadline := time.After(2 * time.Second)
	for tracker.maxSeen.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("reloaded subnet was never scanned")
		case <-time.After(time.Millisecond):
		}
	}
	// Reload wakes the worker to re-snapshot, so it may run more than once. Its
	// peak concurrency must nevertheless remain one for the added prefix.
	time.Sleep(75 * time.Millisecond)
	if got := tracker.maxSeen.Load(); got != 1 {
		t.Fatalf("new subnet peak concurrency = %d, want one worker", got)
	}
}

func TestScheduler_ApplyConfigBeforeAndAfterRunDoesNotDeadlock(t *testing.T) {
	sched := NewScheduler(nil, state.NewMemoryStore(), nil, 1, nil, nil, nil, nil, 0)
	params := ApplyConfigParams{Subnets: []SubnetConfig{makeSubnetConfig("10.5.4.0/24", time.Hour)}}
	sched.ApplyConfig(params) // before Run must release the configuration lock

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = sched.Run(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not stop")
	}

	after := make(chan struct{})
	go func() {
		sched.ApplyConfig(params) // after shutdown must also release the lock
		close(after)
	}()
	select {
	case <-after:
	case <-time.After(time.Second):
		t.Fatal("ApplyConfig deadlocked after scheduler shutdown")
	}
}

func TestScheduler_ReloadWakesIntervalAndRemoval(t *testing.T) {
	store := state.NewMemoryStore()
	prefix := makeSubnetConfig("10.5.5.0/24", time.Hour)
	mock := &mockScanner{name: "arp"}
	sched := NewScheduler([]Scanner{mock}, store, []SubnetConfig{prefix}, 1, nil, nil, nil, nil, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = sched.Run(ctx) }()
	waitReady(t, sched, time.Second)

	sched.ApplyConfig(ApplyConfigParams{Subnets: []SubnetConfig{makeSubnetConfig("10.5.5.0/24", time.Millisecond)}})
	deadline := time.After(time.Second)
	for mock.calls.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("shorter reload interval did not wake the worker")
		case <-time.After(time.Millisecond):
		}
	}

	sched.ApplyConfig(ApplyConfigParams{})
	for {
		sched.mu.RLock()
		workers := len(sched.workers)
		sched.mu.RUnlock()
		if workers == 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("removed subnet worker did not exit promptly")
		case <-time.After(time.Millisecond):
		}
	}
}

func TestScheduler_ReadyAfterAllSubnets(t *testing.T) {
	store := state.NewMemoryStore()
	scanDelay := 60 * time.Millisecond

	// 3 subnets, all using the same scanner with a fixed delay.
	subnets := []SubnetConfig{
		makeSubnetConfig("10.6.0.0/24", time.Hour),
		makeSubnetConfig("10.6.1.0/24", time.Hour),
		makeSubnetConfig("10.6.2.0/24", time.Hour),
	}

	mock := &mockScanner{name: "arp", delay: scanDelay}
	// maxParallel=3 so all subnets start simultaneously.
	sched := NewScheduler([]Scanner{mock}, store, subnets, 3, nil, nil, nil, nil, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	start := time.Now()
	go func() { _ = sched.Run(ctx) }()

	// Ready() must not be closed before the scans have had time to start and run.
	select {
	case <-sched.Ready():
		elapsed := time.Since(start)
		if elapsed < scanDelay/2 {
			t.Errorf("Ready closed too early (elapsed=%v, expected >= %v)", elapsed, scanDelay/2)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Ready() not closed within timeout")
	}

	// All 3 subnets must have been scanned (one call per subnet).
	if got := mock.calls.Load(); got != 3 {
		t.Errorf("scanner called %d times, want 3", got)
	}
}

func TestScheduler_WritesToStore(t *testing.T) {
	ctx := context.Background()
	store := state.NewMemoryStore()
	subnet := makeSubnetConfig("10.7.0.0/24", time.Hour)

	results := []ScanResult{
		makeScanResult("10.7.0.1", "aa:00:00:00:00:01"),
		makeScanResult("10.7.0.2", "aa:00:00:00:00:02"),
		makeScanResult("10.7.0.3", "aa:00:00:00:00:03"),
	}
	mock := &mockScanner{name: "arp", results: results}
	sched := NewScheduler([]Scanner{mock}, store, []SubnetConfig{subnet}, 2, nil, nil, nil, nil, 0)

	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = sched.Run(runCtx) }()
	waitReady(t, sched, 5*time.Second)

	// All 3 hosts must be in the store.
	hosts, err := store.ListHosts(ctx, subnet.Prefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 3 {
		t.Errorf("store has %d hosts, want 3", len(hosts))
	}

	// Scan metadata must be recorded with a valid duration and scanner name.
	metas, err := store.GetScanMeta(ctx, subnet.Prefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 1 {
		t.Fatalf("expected 1 scan meta entry, got %d", len(metas))
	}
	if metas[0].Scanner != "arp" {
		t.Errorf("scanner = %q, want %q", metas[0].Scanner, "arp")
	}
	if metas[0].Duration < 0 {
		t.Errorf("duration = %v, want >= 0", metas[0].Duration)
	}
	if metas[0].Timestamp.IsZero() {
		t.Error("timestamp is zero")
	}
}

func TestScheduler_MapsDNSResultToSourceOwnedObservation(t *testing.T) {
	store := state.NewMemoryStore()
	subnet := makeSubnetConfig("10.7.1.0/24", time.Hour)
	ip := netip.MustParseAddr("10.7.1.1")
	oldSeen := time.Now().Add(-time.Hour).Round(0)
	_, err := store.UpdateHost(context.Background(), state.HostRecord{
		IP:         ip,
		Source:     state.SourceARP,
		ObservedAt: oldSeen,
		LastSeen:   oldSeen,
		Alive:      false,
	})
	if err != nil {
		t.Fatal(err)
	}

	newDNSAt := time.Now().Round(0)
	dns := &mockScanner{name: "dns", results: []ScanResult{{
		IP:            ip,
		Alive:         true, // scheduler must not let this refresh liveness
		Source:        "dns",
		Timestamp:     newDNSAt,
		Hostnames:     []string{"host.example"},
		DNSMismatches: []string{},
	}}}
	sched := NewScheduler([]Scanner{dns}, store, []SubnetConfig{subnet}, 1, nil, nil, nil, nil, 0)
	sched.scanSubnet(context.Background(), scanCycle{subnet: subnet})

	host, err := store.GetHost(context.Background(), ip)
	if err != nil {
		t.Fatal(err)
	}
	if host == nil {
		t.Fatal("host unexpectedly missing")
	}
	if host.Alive || !host.LastSeen.Equal(oldSeen) {
		t.Errorf("DNS result refreshed liveness: Alive=%t LastSeen=%s", host.Alive, host.LastSeen)
	}
	if host.DNSObservedAt != newDNSAt || len(host.Hostnames) != 1 || host.Hostnames[0] != "host.example" {
		t.Errorf("DNS observation was not source-owned as expected: %+v", host)
	}
}

func TestScheduler_DoesNotAuditRejectedAuthorizationObservation(t *testing.T) {
	ctx := context.Background()
	base := state.NewMemoryStore()
	prefix := netip.MustParsePrefix("10.7.3.0/24")
	if _, err := base.UpdateHost(ctx, state.HostRecord{
		IP:         netip.MustParseAddr("10.7.3.1"),
		MAC:        net.HardwareAddr{0, 1, 2, 3, 4, 5},
		Source:     state.SourceARP,
		ObservedAt: time.Now(),
		Alive:      true,
	}); err != nil {
		t.Fatal(err)
	}
	allowlistPath := filepath.Join(t.TempDir(), "allowlist.txt")
	if err := os.WriteFile(allowlistPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	allowlist, err := LoadAllowlist(allowlistPath)
	if err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLog, err := audit.NewLogger(audit.Config{Enabled: true, Output: auditPath})
	if err != nil {
		t.Fatal(err)
	}
	sched := NewScheduler(nil, rejectAuthorizationStore{Store: base}, []SubnetConfig{{Prefix: prefix, ScanInterval: time.Hour}}, 1, nil, nil, auditLog, nil, 0)
	sched.checkAuthorization(ctx, SubnetConfig{Prefix: prefix, ScanInterval: time.Hour}, allowlist, 1)
	if err := auditLog.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), string(audit.EventUnauthorizedDevice)) {
		t.Fatalf("rejected authorization observation produced an audit event: %s", data)
	}
}

func TestScheduler_DropsUnknownObservationSource(t *testing.T) {
	store := state.NewMemoryStore()
	subnet := makeSubnetConfig("10.7.2.0/24", time.Hour)
	bad := &mockScanner{name: "arp", results: []ScanResult{{
		IP:        netip.MustParseAddr("10.7.2.1"),
		Alive:     true,
		Source:    "malicious-extension",
		Timestamp: time.Now(),
	}}}
	sched := NewScheduler([]Scanner{bad}, store, []SubnetConfig{subnet}, 1, nil, nil, nil, nil, 0)
	sched.scanSubnet(context.Background(), scanCycle{subnet: subnet})
	host, err := store.GetHost(context.Background(), netip.MustParseAddr("10.7.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	if host != nil {
		t.Fatalf("unsupported observation source mutated state: %+v", host)
	}
}

func TestScheduler_MultipleScannersPerSubnet(t *testing.T) {
	ctx := context.Background()
	store := state.NewMemoryStore()
	subnet := makeSubnetConfig("10.8.0.0/24", time.Hour)

	arp := &mockScanner{name: "arp"}
	icmp := &mockScanner{name: "icmp"}
	sched := NewScheduler([]Scanner{arp, icmp}, store, []SubnetConfig{subnet}, 2, nil, nil, nil, nil, 0)

	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = sched.Run(runCtx) }()
	waitReady(t, sched, 5*time.Second)

	// Both scanners must have been invoked.
	if got := arp.calls.Load(); got != 1 {
		t.Errorf("arp scanner called %d times, want 1", got)
	}
	if got := icmp.calls.Load(); got != 1 {
		t.Errorf("icmp scanner called %d times, want 1", got)
	}

	// Metadata must exist for both scanner names.
	metas, err := store.GetScanMeta(ctx, subnet.Prefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 2 {
		t.Fatalf("expected 2 scan meta entries (one per scanner), got %d", len(metas))
	}
	names := make(map[string]bool)
	for _, m := range metas {
		names[m.Scanner] = true
	}
	for _, want := range []string{"arp", "icmp"} {
		if !names[want] {
			t.Errorf("missing scan metadata for scanner %q", want)
		}
	}
}
