//go:build !race

package internal_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/maravexa/signet-exporter/internal/collector"
	"github.com/maravexa/signet-exporter/internal/scanner"
	"github.com/maravexa/signet-exporter/internal/server"
	"github.com/maravexa/signet-exporter/internal/state"
)

// integrationMockScanner returns a fixed list of hosts for any subnet.
type integrationMockScanner struct {
	results []scanner.ScanResult
}

func (m *integrationMockScanner) Name() string { return "mock" }

func (m *integrationMockScanner) Scan(_ context.Context, _ netip.Prefix) ([]scanner.ScanResult, error) {
	return m.results, nil
}

func makeMockResults() []scanner.ScanResult {
	hosts := []struct{ ip, mac string }{
		{"10.99.0.1", "aa:bb:cc:dd:ee:01"},
		{"10.99.0.2", "aa:bb:cc:dd:ee:02"},
		{"10.99.0.3", "aa:bb:cc:dd:ee:03"},
		{"10.99.0.4", "aa:bb:cc:dd:ee:04"},
		{"10.99.0.5", "aa:bb:cc:dd:ee:05"},
	}
	results := make([]scanner.ScanResult, len(hosts))
	for i, h := range hosts {
		hw, _ := net.ParseMAC(h.mac)
		results[i] = scanner.ScanResult{
			IP:        netip.MustParseAddr(h.ip),
			MAC:       hw,
			Alive:     true,
			Source:    "mock",
			Timestamp: time.Now(),
		}
	}
	return results
}

func TestFullStack_MockScan_MetricsExposed(t *testing.T) {
	subnet := netip.MustParsePrefix("10.99.0.0/24")
	subnetStr := subnet.String()

	// Wire up all components.
	store := state.NewMemoryStore()
	mock := &integrationMockScanner{results: makeMockResults()}
	subnetCfg := scanner.SubnetConfig{
		Prefix:       subnet,
		ScanInterval: time.Minute, // long interval — only first scan matters
	}

	sched := scanner.NewScheduler(
		[]scanner.Scanner{mock},
		store,
		[]scanner.SubnetConfig{subnetCfg},
		2,
		nil,
		nil,
		nil,
		nil,
		0,
	)

	col := collector.NewSignetCollector(store, []netip.Prefix{subnet}, nil)
	handler := server.NewHandler(col, sched.Ready())
	ts := httptest.NewServer(handler)
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = sched.Run(ctx) }()

	// Wait for the scheduler to complete its first scan cycle.
	select {
	case <-sched.Ready():
	case <-time.After(10 * time.Second):
		t.Fatal("scheduler did not become ready within 10s")
	}

	// /health must always return 200.
	t.Run("health", func(t *testing.T) {
		status, _ := getURL(t, ctx, ts.URL+"/health")
		if status != http.StatusOK {
			t.Errorf("/health status = %d, want 200", status)
		}
	})

	// /ready must return 200 after the first scan cycle.
	t.Run("ready", func(t *testing.T) {
		status, _ := getURL(t, ctx, ts.URL+"/ready")
		if status != http.StatusOK {
			t.Errorf("/ready status = %d, want 200 (scheduler is ready)", status)
		}
	})

	// /metrics must return 200 and contain expected metric output.
	t.Run("metrics", func(t *testing.T) {
		status, body := getURL(t, ctx, ts.URL+"/metrics")
		if status != http.StatusOK {
			t.Errorf("/metrics status = %d, want 200", status)
		}

		text := string(body)

		assertMetricPresent(t, text, "signet_exporter_build_info")
		assertMetricPresent(t, text, "signet_host_up")
		assertMetricPresent(t, text, "signet_subnet_addresses_used")
		assertMetricPresent(t, text, "signet_subnet_addresses_total")
		assertMetricPresent(t, text, "signet_scan_duration_seconds")
		assertMetricPresent(t, text, "signet_last_scan_timestamp")

		// Verify subnet label appears in utilisation metrics.
		assertContains(t, text, `signet_subnet_addresses_used{subnet="`+subnetStr+`"} 5`)
		assertContains(t, text, `signet_subnet_addresses_total{subnet="`+subnetStr+`"} 254`)

		// 5 hosts should appear as signet_host_up.
		count := strings.Count(text, "signet_host_up{")
		if count != 5 {
			t.Errorf("signet_host_up count = %d, want 5\nmetrics output:\n%s", count, text)
		}

		// scan_duration_seconds must have a non-negative value.
		assertMetricValueAbove(t, text, "signet_scan_duration_seconds", -1)

		// signet_last_scan_timestamp must be a plausible unix timestamp (after 2020-01-01).
		const year2020Unix = 1577836800
		assertMetricValueAbove(t, text, "signet_last_scan_timestamp", year2020Unix)
	})
}

func TestFullStack_ReadyGating(t *testing.T) {
	// Verify /ready returns 503 before the scheduler signals readiness.
	subnet := netip.MustParsePrefix("10.100.0.0/24")

	store := state.NewMemoryStore()
	// Use a scanner with a delay so the first scan doesn't complete instantly.
	slowMock := &delayedMockScanner{delay: 200 * time.Millisecond}
	subnetCfg := scanner.SubnetConfig{
		Prefix:       subnet,
		ScanInterval: time.Minute,
	}

	sched := scanner.NewScheduler(
		[]scanner.Scanner{slowMock},
		store,
		[]scanner.SubnetConfig{subnetCfg},
		2,
		nil,
		nil,
		nil,
		nil,
		0,
	)

	col := collector.NewSignetCollector(store, []netip.Prefix{subnet}, nil)
	handler := server.NewHandler(col, sched.Ready())
	ts := httptest.NewServer(handler)
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = sched.Run(ctx) }()

	// /ready should return 503 before the first scan finishes.
	status, _ := getURL(t, ctx, ts.URL+"/ready")
	if status != http.StatusServiceUnavailable {
		t.Errorf("before ready: /ready status = %d, want 503", status)
	}

	// Wait for readiness, then verify 200.
	select {
	case <-sched.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("scheduler did not become ready")
	}

	status2, _ := getURL(t, ctx, ts.URL+"/ready")
	if status2 != http.StatusOK {
		t.Errorf("after ready: /ready status = %d, want 200", status2)
	}
}

// delayedMockScanner simulates a slow scan.
type delayedMockScanner struct{ delay time.Duration }

func (d *delayedMockScanner) Name() string { return "slow-mock" }

func (d *delayedMockScanner) Scan(ctx context.Context, _ netip.Prefix) ([]scanner.ScanResult, error) {
	select {
	case <-time.After(d.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return nil, nil
}

// getURL makes a GET request with context, reads and closes the body, and returns
// the HTTP status code and body bytes. Fails the test on any transport error.
// Returning (int, []byte) instead of (*http.Response, []byte) keeps the response
// body from escaping the function, satisfying the bodyclose linter.
func getURL(t *testing.T, ctx context.Context, url string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext %s: %v", url, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	body, readErr := io.ReadAll(resp.Body)
	if closeErr := resp.Body.Close(); closeErr != nil && readErr == nil {
		readErr = closeErr
	}
	if readErr != nil {
		t.Fatalf("reading body from %s: %v", url, readErr)
	}
	return resp.StatusCode, body
}

// --- assertion helpers ---

func assertMetricPresent(t *testing.T, body, name string) {
	t.Helper()
	if !strings.Contains(body, name) {
		t.Errorf("metric %q not found in /metrics output", name)
	}
}

func assertContains(t *testing.T, body, substr string) {
	t.Helper()
	if !strings.Contains(body, substr) {
		t.Errorf("expected %q in /metrics output", substr)
	}
}

func assertMetricValueAbove(t *testing.T, body, metricPrefix string, minValue float64) {
	t.Helper()
	idx := strings.Index(body, metricPrefix+"{")
	if idx < 0 {
		t.Errorf("metric %q not found in /metrics output", metricPrefix)
		return
	}
	// Find the value at the end of the line (after the last space).
	line := body[idx:]
	if nl := strings.IndexByte(line, '\n'); nl > 0 {
		line = line[:nl]
	}
	lastSpace := strings.LastIndexByte(line, ' ')
	if lastSpace < 0 {
		t.Errorf("cannot parse value from line: %s", line)
		return
	}
	valStr := strings.TrimSpace(line[lastSpace+1:])
	var val float64
	if _, err := fmt.Sscanf(valStr, "%f", &val); err != nil {
		t.Errorf("cannot parse float from %q: %v", valStr, err)
		return
	}
	if val <= minValue {
		t.Errorf("metric %q value = %v, want > %v", metricPrefix, val, minValue)
	}
}
