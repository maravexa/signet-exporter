package collector

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/maravexa/signet-exporter/internal/fips"
	"github.com/maravexa/signet-exporter/internal/state"
	"github.com/prometheus/client_golang/prometheus"
)

// --- test helpers ---

func newTestCollector(store state.Store, subnets ...string) *SignetCollector {
	prefixes := make([]netip.Prefix, 0, len(subnets))
	for _, s := range subnets {
		prefixes = append(prefixes, netip.MustParsePrefix(s))
	}
	return NewSignetCollector(store, prefixes, nil)
}

// collectMetrics runs a full Collect cycle and returns gathered metric families.
func collectMetrics(c *SignetCollector) []*dto.MetricFamily {
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	families, _ := reg.Gather()
	return families
}

// findMetric searches gathered families for a metric family with the given name.
func findMetric(families []*dto.MetricFamily, name string) *dto.MetricFamily {
	for _, f := range families {
		if f.GetName() == name {
			return f
		}
	}
	return nil
}

// findSample searches a MetricFamily for a sample matching all the given label key/value pairs.
func findSample(family *dto.MetricFamily, labels map[string]string) *dto.Metric {
	for _, m := range family.GetMetric() {
		if labelsMatch(m.GetLabel(), labels) {
			return m
		}
	}
	return nil
}

// labelsMatch returns true if all key/value pairs in want appear in got.
// Extra labels in got are permitted — this is a subset match.
func labelsMatch(got []*dto.LabelPair, want map[string]string) bool {
	index := make(map[string]string, len(got))
	for _, lp := range got {
		index[lp.GetName()] = lp.GetValue()
	}
	for k, v := range want {
		if index[k] != v {
			return false
		}
	}
	return true
}

// hasLabel returns true if the metric carries a label with the given name.
func hasLabel(m *dto.Metric, name string) bool {
	for _, lp := range m.GetLabel() {
		if lp.GetName() == name {
			return true
		}
	}
	return false
}

func makeHost(ip, mac string, opts ...func(*state.HostRecord)) state.HostRecord {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		panic("invalid MAC: " + err.Error())
	}
	h := state.HostRecord{
		IP:         netip.MustParseAddr(ip),
		MAC:        hw,
		Vendor:     "TestVendor",
		LastSeen:   time.Now(),
		Alive:      true,
		Authorized: true,
	}
	for _, opt := range opts {
		opt(&h)
	}
	return h
}

// --- tests ---

func TestCollect_BuildInfo(t *testing.T) {
	store := state.NewMemoryStore()
	c := newTestCollector(store)

	families := collectMetrics(c)

	fam := findMetric(families, "signet_exporter_build_info")
	if fam == nil {
		t.Fatal("signet_exporter_build_info not emitted")
	}
	if len(fam.GetMetric()) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(fam.GetMetric()))
	}
	m := fam.GetMetric()[0]
	if m.GetGauge().GetValue() != 1.0 {
		t.Errorf("build_info value = %v, want 1", m.GetGauge().GetValue())
	}
	labels := make(map[string]string)
	for _, lp := range m.GetLabel() {
		labels[lp.GetName()] = lp.GetValue()
	}
	for _, key := range []string{"version", "commit", "goversion"} {
		if _, ok := labels[key]; !ok {
			t.Errorf("build_info missing label %q", key)
		}
	}
}

func TestCollect_HostUp(t *testing.T) {
	ctx := context.Background()
	store := state.NewMemoryStore()
	subnet := "10.0.1.0/24"

	hosts := []struct{ ip, mac, vendor string }{
		{"10.0.1.1", "aa:bb:cc:dd:ee:01", "VendorA"},
		{"10.0.1.2", "aa:bb:cc:dd:ee:02", "VendorB"},
		{"10.0.1.3", "aa:bb:cc:dd:ee:03", "VendorC"},
	}
	for _, h := range hosts {
		rec := makeHost(h.ip, h.mac, func(r *state.HostRecord) { r.Vendor = h.vendor })
		if _, err := store.UpdateHost(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}

	c := newTestCollector(store, subnet)
	families := collectMetrics(c)

	fam := findMetric(families, "signet_host_up")
	if fam == nil {
		t.Fatal("signet_host_up not emitted")
	}
	if len(fam.GetMetric()) != 3 {
		t.Fatalf("expected 3 host_up samples, got %d", len(fam.GetMetric()))
	}
	for _, h := range hosts {
		// host_up must match on ip + subnet only (no mac/vendor/hostname).
		sample := findSample(fam, map[string]string{
			"ip":     h.ip,
			"subnet": subnet,
		})
		if sample == nil {
			t.Errorf("no host_up sample for ip=%s", h.ip)
			continue
		}
		if sample.GetGauge().GetValue() != 1.0 {
			t.Errorf("host_up[%s] = %v, want 1", h.ip, sample.GetGauge().GetValue())
		}
	}
}

func TestCollect_HostUp_Stale(t *testing.T) {
	ctx := context.Background()
	store := state.NewMemoryStore()
	subnet := "10.0.1.0/24"

	rec := makeHost("10.0.1.10", "aa:bb:cc:dd:ee:10", func(r *state.HostRecord) {
		r.LastSeen = time.Now().Add(-10 * time.Minute) // older than 5m staleness threshold
	})
	if _, err := store.UpdateHost(ctx, rec); err != nil {
		t.Fatal(err)
	}

	c := newTestCollector(store, subnet)
	families := collectMetrics(c)

	fam := findMetric(families, "signet_host_up")
	if fam == nil {
		t.Fatal("signet_host_up not emitted")
	}
	if len(fam.GetMetric()) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(fam.GetMetric()))
	}
	if fam.GetMetric()[0].GetGauge().GetValue() != 0.0 {
		t.Errorf("stale host: host_up = %v, want 0", fam.GetMetric()[0].GetGauge().GetValue())
	}
}

func TestCollect_SubnetUtilization(t *testing.T) {
	ctx := context.Background()
	store := state.NewMemoryStore()
	subnet := "10.0.2.0/24"

	for i := 1; i <= 5; i++ {
		ip := netip.AddrFrom4([4]byte{10, 0, 2, byte(i)}).String()
		mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, byte(i)}.String()
		if _, err := store.UpdateHost(ctx, makeHost(ip, mac)); err != nil {
			t.Fatal(err)
		}
	}

	c := newTestCollector(store, subnet)
	families := collectMetrics(c)

	usedFam := findMetric(families, "signet_subnet_addresses_used")
	if usedFam == nil {
		t.Fatal("signet_subnet_addresses_used not emitted")
	}
	usedSample := findSample(usedFam, map[string]string{"subnet": subnet})
	if usedSample == nil {
		t.Fatal("no sample for subnet")
	}
	if usedSample.GetGauge().GetValue() != 5.0 {
		t.Errorf("addresses_used = %v, want 5", usedSample.GetGauge().GetValue())
	}

	totalFam := findMetric(families, "signet_subnet_addresses_total")
	if totalFam == nil {
		t.Fatal("signet_subnet_addresses_total not emitted")
	}
	totalSample := findSample(totalFam, map[string]string{"subnet": subnet})
	if totalSample == nil {
		t.Fatal("no total sample for subnet")
	}
	if totalSample.GetGauge().GetValue() != 254.0 {
		t.Errorf("addresses_total = %v, want 254", totalSample.GetGauge().GetValue())
	}
}

func TestCollect_MultipleSubnets(t *testing.T) {
	ctx := context.Background()
	store := state.NewMemoryStore()

	subnet1 := "10.1.0.0/24"
	subnet2 := "10.2.0.0/24"

	// 2 hosts in subnet1
	for i := 1; i <= 2; i++ {
		ip := netip.AddrFrom4([4]byte{10, 1, 0, byte(i)}).String()
		mac := net.HardwareAddr{0xaa, 0x01, 0x00, 0x00, 0x00, byte(i)}.String()
		if _, err := store.UpdateHost(ctx, makeHost(ip, mac)); err != nil {
			t.Fatal(err)
		}
	}
	// 3 hosts in subnet2
	for i := 1; i <= 3; i++ {
		ip := netip.AddrFrom4([4]byte{10, 2, 0, byte(i)}).String()
		mac := net.HardwareAddr{0xaa, 0x02, 0x00, 0x00, 0x00, byte(i)}.String()
		if _, err := store.UpdateHost(ctx, makeHost(ip, mac)); err != nil {
			t.Fatal(err)
		}
	}

	c := newTestCollector(store, subnet1, subnet2)
	families := collectMetrics(c)

	usedFam := findMetric(families, "signet_subnet_addresses_used")
	if usedFam == nil {
		t.Fatal("signet_subnet_addresses_used not emitted")
	}

	s1 := findSample(usedFam, map[string]string{"subnet": subnet1})
	if s1 == nil || s1.GetGauge().GetValue() != 2 {
		t.Errorf("subnet1 used = %v, want 2", s1.GetGauge().GetValue())
	}
	s2 := findSample(usedFam, map[string]string{"subnet": subnet2})
	if s2 == nil || s2.GetGauge().GetValue() != 3 {
		t.Errorf("subnet2 used = %v, want 3", s2.GetGauge().GetValue())
	}

	// Hosts in subnet1 should have subnet1 label, not subnet2.
	hostFam := findMetric(families, "signet_host_up")
	if hostFam == nil {
		t.Fatal("signet_host_up not emitted")
	}
	ip1 := netip.AddrFrom4([4]byte{10, 1, 0, 1}).String()
	s := findSample(hostFam, map[string]string{
		"ip":     ip1,
		"subnet": subnet1,
	})
	if s == nil {
		t.Errorf("host %s not found with subnet1 label", ip1)
	}
	s = findSample(hostFam, map[string]string{
		"ip":     ip1,
		"subnet": subnet2,
	})
	if s != nil {
		t.Errorf("host %s incorrectly appears under subnet2 label", ip1)
	}
}

func TestCollect_UnauthorizedDevice(t *testing.T) {
	ctx := context.Background()
	store := state.NewMemoryStore()
	subnet := "10.0.3.0/24"

	// Checked + unauthorized: must emit metric with value 1.
	rogue := makeHost("10.0.3.1", "aa:bb:cc:dd:ee:01", func(r *state.HostRecord) {
		r.Authorized = false
		r.AuthorizationChecked = true
	})
	// Checked + authorized: must NOT emit metric.
	legit := makeHost("10.0.3.2", "aa:bb:cc:dd:ee:02", func(r *state.HostRecord) {
		r.Authorized = true
		r.AuthorizationChecked = true
	})
	// Unchecked (no allowlist configured): must NOT emit metric.
	unchecked := makeHost("10.0.3.3", "aa:bb:cc:dd:ee:03")

	for _, rec := range []state.HostRecord{rogue, legit, unchecked} {
		if _, err := store.UpdateHost(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}

	c := newTestCollector(store, subnet)
	families := collectMetrics(c)

	fam := findMetric(families, "signet_unauthorized_device_detected")
	if fam == nil {
		t.Fatal("signet_unauthorized_device_detected not emitted at all")
	}
	if len(fam.GetMetric()) != 1 {
		t.Fatalf("expected exactly 1 sample (rogue only), got %d", len(fam.GetMetric()))
	}

	unauthSample := findSample(fam, map[string]string{
		"ip":     "10.0.3.1",
		"mac":    "aa:bb:cc:dd:ee:01",
		"vendor": "TestVendor",
		"subnet": subnet,
	})
	if unauthSample == nil {
		t.Fatal("no sample for rogue host")
	}
	if unauthSample.GetGauge().GetValue() != 1.0 {
		t.Errorf("rogue host value = %v, want 1", unauthSample.GetGauge().GetValue())
	}

	// Authorized+checked host must not appear.
	legitSample := findSample(fam, map[string]string{"ip": "10.0.3.2"})
	if legitSample != nil {
		t.Error("authorized host should not appear in signet_unauthorized_device_detected")
	}

	// Unchecked host must not appear.
	uncheckedSample := findSample(fam, map[string]string{"ip": "10.0.3.3"})
	if uncheckedSample != nil {
		t.Error("unchecked host should not appear in signet_unauthorized_device_detected")
	}
}

func TestCollect_PortOpen(t *testing.T) {
	ctx := context.Background()
	store := state.NewMemoryStore()
	subnet := "10.0.4.0/24"

	rec := makeHost("10.0.4.1", "aa:bb:cc:dd:ee:01", func(r *state.HostRecord) {
		r.OpenPorts = []uint16{22, 443}
	})
	if _, err := store.UpdateHost(ctx, rec); err != nil {
		t.Fatal(err)
	}

	c := newTestCollector(store, subnet)
	families := collectMetrics(c)

	fam := findMetric(families, "signet_port_open")
	if fam == nil {
		t.Fatal("signet_port_open not emitted")
	}
	if len(fam.GetMetric()) != 2 {
		t.Fatalf("expected 2 port_open samples, got %d", len(fam.GetMetric()))
	}
	for _, port := range []string{"22", "443"} {
		s := findSample(fam, map[string]string{
			"ip":     "10.0.4.1",
			"port":   port,
			"subnet": subnet,
		})
		if s == nil {
			t.Errorf("no port_open sample for port %s", port)
			continue
		}
		if s.GetGauge().GetValue() != 1.0 {
			t.Errorf("port_open[%s] = %v, want 1", port, s.GetGauge().GetValue())
		}
	}
}

func TestCollect_MACBindingChanges(t *testing.T) {
	ctx := context.Background()
	store := state.NewMemoryStore()
	subnet := "10.0.5.0/24"
	ip := "10.0.5.1"

	// Insert initial record
	if _, err := store.UpdateHost(ctx, makeHost(ip, "aa:bb:cc:dd:ee:01")); err != nil {
		t.Fatal(err)
	}

	// First MAC change
	if _, err := store.UpdateHost(ctx, makeHost(ip, "aa:bb:cc:dd:ee:02", func(r *state.HostRecord) {
		r.LastSeen = time.Now().Add(time.Second)
	})); err != nil {
		t.Fatal(err)
	}

	c := newTestCollector(store, subnet)
	families := collectMetrics(c)

	fam := findMetric(families, "signet_mac_ip_binding_changes_total")
	if fam == nil {
		t.Fatal("signet_mac_ip_binding_changes_total not emitted after first change")
	}
	s := findSample(fam, map[string]string{"ip": ip, "subnet": subnet})
	if s == nil {
		t.Fatal("no sample for ip/subnet")
	}
	if s.GetCounter().GetValue() != 1.0 {
		t.Errorf("binding_changes count = %v, want 1", s.GetCounter().GetValue())
	}

	// Second MAC change
	if _, err := store.UpdateHost(ctx, makeHost(ip, "aa:bb:cc:dd:ee:03", func(r *state.HostRecord) {
		r.LastSeen = time.Now().Add(2 * time.Second)
	})); err != nil {
		t.Fatal(err)
	}

	families = collectMetrics(c)
	fam = findMetric(families, "signet_mac_ip_binding_changes_total")
	if fam == nil {
		t.Fatal("signet_mac_ip_binding_changes_total not emitted after second change")
	}
	s = findSample(fam, map[string]string{"ip": ip, "subnet": subnet})
	if s == nil {
		t.Fatal("no sample for ip/subnet after second change")
	}
	if s.GetCounter().GetValue() != 2.0 {
		t.Errorf("binding_changes count = %v, want 2", s.GetCounter().GetValue())
	}
}

func TestCollect_EmptyStore(t *testing.T) {
	store := state.NewMemoryStore()
	subnets := []string{"10.0.10.0/24", "10.0.11.0/25"}
	c := newTestCollector(store, subnets...)
	families := collectMetrics(c)

	// No host_up metrics when store is empty.
	if fam := findMetric(families, "signet_host_up"); fam != nil && len(fam.GetMetric()) > 0 {
		t.Errorf("expected no host_up metrics for empty store, got %d", len(fam.GetMetric()))
	}

	// subnet_addresses_used = 0 for each subnet.
	usedFam := findMetric(families, "signet_subnet_addresses_used")
	if usedFam == nil {
		t.Fatal("signet_subnet_addresses_used not emitted for empty store")
	}
	for _, sub := range subnets {
		s := findSample(usedFam, map[string]string{"subnet": sub})
		if s == nil {
			t.Errorf("no addresses_used sample for subnet %s", sub)
			continue
		}
		if s.GetGauge().GetValue() != 0.0 {
			t.Errorf("addresses_used[%s] = %v, want 0", sub, s.GetGauge().GetValue())
		}
	}

	// subnet_addresses_total is correct per subnet size.
	totalFam := findMetric(families, "signet_subnet_addresses_total")
	if totalFam == nil {
		t.Fatal("signet_subnet_addresses_total not emitted")
	}
	wantTotal := map[string]float64{
		"10.0.10.0/24": 254,
		"10.0.11.0/25": 126,
	}
	for sub, want := range wantTotal {
		s := findSample(totalFam, map[string]string{"subnet": sub})
		if s == nil {
			t.Errorf("no addresses_total sample for subnet %s", sub)
			continue
		}
		if s.GetGauge().GetValue() != want {
			t.Errorf("addresses_total[%s] = %v, want %v", sub, s.GetGauge().GetValue(), want)
		}
	}

	// build_info is always emitted.
	if fam := findMetric(families, "signet_exporter_build_info"); fam == nil {
		t.Error("signet_exporter_build_info must be emitted even for empty store")
	}
}

func TestCollect_ScanMeta(t *testing.T) {
	ctx := context.Background()
	store := state.NewMemoryStore()
	subnet := "10.0.6.0/24"

	scanTime := time.Unix(1700000000, 0)
	if err := store.RecordScanMeta(ctx, state.ScanMeta{
		Subnet:    netip.MustParsePrefix(subnet),
		Scanner:   "arp",
		Duration:  1500 * time.Millisecond,
		Timestamp: scanTime,
	}); err != nil {
		t.Fatal(err)
	}

	c := newTestCollector(store, subnet)
	families := collectMetrics(c)

	durFam := findMetric(families, "signet_scan_duration_seconds")
	if durFam == nil {
		t.Fatal("signet_scan_duration_seconds not emitted")
	}
	durSample := findSample(durFam, map[string]string{"subnet": subnet, "scanner": "arp"})
	if durSample == nil {
		t.Fatal("no scan_duration sample for subnet/scanner")
	}
	if durSample.GetGauge().GetValue() != 1.5 {
		t.Errorf("scan_duration = %v, want 1.5", durSample.GetGauge().GetValue())
	}

	tsFam := findMetric(families, "signet_last_scan_timestamp")
	if tsFam == nil {
		t.Fatal("signet_last_scan_timestamp not emitted")
	}
	tsSample := findSample(tsFam, map[string]string{"subnet": subnet})
	if tsSample == nil {
		t.Fatal("no last_scan_timestamp sample for subnet")
	}
	if tsSample.GetGauge().GetValue() != float64(scanTime.Unix()) {
		t.Errorf("last_scan_timestamp = %v, want %v", tsSample.GetGauge().GetValue(), float64(scanTime.Unix()))
	}
}

func TestCollect_DNSMismatch(t *testing.T) {
	ctx := context.Background()
	store := state.NewMemoryStore()
	subnet := "10.0.8.0/24"

	rec := makeHost("10.0.8.1", "aa:bb:cc:dd:ee:01", func(r *state.HostRecord) {
		r.DNSMismatches = []string{"bad.example.com"}
	})
	if _, err := store.UpdateHost(ctx, rec); err != nil {
		t.Fatal(err)
	}

	c := newTestCollector(store, subnet)
	families := collectMetrics(c)

	fam := findMetric(families, "signet_dns_forward_reverse_mismatch")
	if fam == nil {
		t.Fatal("signet_dns_forward_reverse_mismatch not emitted")
	}
	s := findSample(fam, map[string]string{
		"ip":       "10.0.8.1",
		"hostname": "bad.example.com",
		"subnet":   subnet,
	})
	if s == nil {
		t.Fatal("no sample for ip/hostname/subnet")
	}
	if s.GetGauge().GetValue() != 1.0 {
		t.Errorf("dns_mismatch value = %v, want 1", s.GetGauge().GetValue())
	}
}

func TestCollect_DNSNoMismatch(t *testing.T) {
	ctx := context.Background()
	store := state.NewMemoryStore()
	subnet := "10.0.9.0/24"

	// DNSMismatches is non-nil but empty: host was checked, no mismatches found.
	rec := makeHost("10.0.9.1", "aa:bb:cc:dd:ee:01", func(r *state.HostRecord) {
		r.DNSMismatches = []string{}
	})
	if _, err := store.UpdateHost(ctx, rec); err != nil {
		t.Fatal(err)
	}

	c := newTestCollector(store, subnet)
	families := collectMetrics(c)

	fam := findMetric(families, "signet_dns_forward_reverse_mismatch")
	if fam == nil {
		return // no family at all — correct
	}
	s := findSample(fam, map[string]string{"ip": "10.0.9.1", "subnet": subnet})
	if s != nil {
		t.Error("signet_dns_forward_reverse_mismatch emitted for host with no mismatches, want no sample")
	}
}

func TestCollect_DuplicateIPDetected(t *testing.T) {
	ctx := context.Background()
	store := state.NewMemoryStore()
	subnet := "10.0.14.0/24"

	dupMAC, _ := net.ParseMAC("ff:ee:dd:cc:bb:aa")

	// Host with a detected duplicate.
	rogue := makeHost("10.0.14.1", "aa:bb:cc:dd:ee:01", func(r *state.HostRecord) {
		r.DuplicateMACs = []net.HardwareAddr{dupMAC}
	})
	// Host without duplicate.
	clean := makeHost("10.0.14.2", "aa:bb:cc:dd:ee:02")

	for _, rec := range []state.HostRecord{rogue, clean} {
		if _, err := store.UpdateHost(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}

	c := newTestCollector(store, subnet)
	families := collectMetrics(c)

	fam := findMetric(families, "signet_duplicate_ip_detected")
	if fam == nil {
		t.Fatal("signet_duplicate_ip_detected not emitted for host with DuplicateMACs")
	}
	// Only the one host with duplicates should produce a sample.
	if len(fam.GetMetric()) != 1 {
		t.Fatalf("expected 1 sample (duplicate host only), got %d", len(fam.GetMetric()))
	}

	// The macs label must contain both the primary and duplicate MAC.
	s := findSample(fam, map[string]string{
		"ip":     "10.0.14.1",
		"subnet": subnet,
	})
	if s == nil {
		t.Fatal("no sample for the duplicate host ip/subnet")
	}
	if s.GetGauge().GetValue() != 1.0 {
		t.Errorf("signet_duplicate_ip_detected value = %v, want 1", s.GetGauge().GetValue())
	}
	// Verify the macs label contains both MACs.
	macsLabel := ""
	for _, lp := range s.GetLabel() {
		if lp.GetName() == "macs" {
			macsLabel = lp.GetValue()
		}
	}
	if macsLabel == "" {
		t.Fatal("macs label is missing or empty")
	}
	if !strings.Contains(macsLabel, "aa:bb:cc:dd:ee:01") {
		t.Errorf("macs label %q does not contain primary MAC", macsLabel)
	}
	if !strings.Contains(macsLabel, "ff:ee:dd:cc:bb:aa") {
		t.Errorf("macs label %q does not contain duplicate MAC", macsLabel)
	}

	// Clean host must not appear in the metric.
	cleanSample := findSample(fam, map[string]string{"ip": "10.0.14.2"})
	if cleanSample != nil {
		t.Error("host without duplicates should not appear in signet_duplicate_ip_detected")
	}
}

func TestCollect_FIPSEnabled(t *testing.T) {
	store := state.NewMemoryStore()
	c := newTestCollector(store)

	families := collectMetrics(c)

	fam := findMetric(families, "signet_exporter_fips_enabled")
	if fam == nil {
		t.Fatal("signet_exporter_fips_enabled not emitted")
	}
	if len(fam.GetMetric()) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(fam.GetMetric()))
	}
	val := fam.GetMetric()[0].GetGauge().GetValue()
	wantVal := 0.0
	if fips.Enabled() {
		wantVal = 1.0
	}
	if val != wantVal {
		t.Errorf("signet_exporter_fips_enabled = %v, want %v (fips.Enabled=%v)", val, wantVal, fips.Enabled())
	}
}

func TestCollect_NoScanMeta_NoEmission(t *testing.T) {
	store := state.NewMemoryStore()
	subnet := "10.0.7.0/24"

	c := newTestCollector(store, subnet)
	families := collectMetrics(c)

	if fam := findMetric(families, "signet_scan_duration_seconds"); fam != nil && len(fam.GetMetric()) > 0 {
		t.Errorf("signet_scan_duration_seconds should not be emitted without scan metadata, got %d samples", len(fam.GetMetric()))
	}
	if fam := findMetric(families, "signet_last_scan_timestamp"); fam != nil && len(fam.GetMetric()) > 0 {
		t.Errorf("signet_last_scan_timestamp should not be emitted without scan metadata, got %d samples", len(fam.GetMetric()))
	}
}

// --- Step 18: Info metric split tests ---

func TestHostInfoEmittedForDownHost(t *testing.T) {
	ctx := context.Background()
	store := state.NewMemoryStore()
	subnet := "10.0.20.0/24"

	// Host is stale (last seen 10 minutes ago, so host_up = 0).
	rec := makeHost("10.0.20.1", "aa:bb:cc:dd:ee:01", func(r *state.HostRecord) {
		r.LastSeen = time.Now().Add(-10 * time.Minute)
		r.Vendor = "DownVendor"
	})
	if _, err := store.UpdateHost(ctx, rec); err != nil {
		t.Fatal(err)
	}

	c := newTestCollector(store, subnet)
	families := collectMetrics(c)

	// host_up must be 0.
	upFam := findMetric(families, "signet_host_up")
	if upFam == nil {
		t.Fatal("signet_host_up not emitted for down host")
	}
	upSample := findSample(upFam, map[string]string{"ip": "10.0.20.1", "subnet": subnet})
	if upSample == nil {
		t.Fatal("no host_up sample for down host")
	}
	if upSample.GetGauge().GetValue() != 0.0 {
		t.Errorf("down host: host_up = %v, want 0", upSample.GetGauge().GetValue())
	}

	// host_info must still be emitted even though host is down.
	infoFam := findMetric(families, "signet_host_info")
	if infoFam == nil {
		t.Fatal("signet_host_info not emitted for down host")
	}
	infoSample := findSample(infoFam, map[string]string{"ip": "10.0.20.1", "subnet": subnet})
	if infoSample == nil {
		t.Fatal("no host_info sample for down host")
	}
	if infoSample.GetGauge().GetValue() != 1.0 {
		t.Errorf("host_info value = %v, want 1", infoSample.GetGauge().GetValue())
	}
}

func TestHostInfoLabels(t *testing.T) {
	ctx := context.Background()
	store := state.NewMemoryStore()
	subnet := "10.0.21.0/24"

	rec := makeHost("10.0.21.1", "aa:bb:cc:dd:ee:01", func(r *state.HostRecord) {
		r.Vendor = "ACME Corp"
		r.Hostnames = []string{"acme.example.com"}
	})
	if _, err := store.UpdateHost(ctx, rec); err != nil {
		t.Fatal(err)
	}

	c := newTestCollector(store, subnet)
	families := collectMetrics(c)

	// host_info must carry mac, vendor, hostname, ip, subnet.
	infoFam := findMetric(families, "signet_host_info")
	if infoFam == nil {
		t.Fatal("signet_host_info not emitted")
	}
	infoSample := findSample(infoFam, map[string]string{
		"ip":       "10.0.21.1",
		"mac":      "aa:bb:cc:dd:ee:01",
		"vendor":   "ACME Corp",
		"hostname": "acme.example.com",
		"subnet":   subnet,
	})
	if infoSample == nil {
		t.Fatal("host_info sample missing expected labels")
	}
}

func TestHostUpLabelsReduced(t *testing.T) {
	ctx := context.Background()
	store := state.NewMemoryStore()
	subnet := "10.0.22.0/24"

	rec := makeHost("10.0.22.1", "aa:bb:cc:dd:ee:01", func(r *state.HostRecord) {
		r.Vendor = "SomeVendor"
		r.Hostnames = []string{"somehost.example.com"}
	})
	if _, err := store.UpdateHost(ctx, rec); err != nil {
		t.Fatal(err)
	}

	c := newTestCollector(store, subnet)
	families := collectMetrics(c)

	upFam := findMetric(families, "signet_host_up")
	if upFam == nil {
		t.Fatal("signet_host_up not emitted")
	}
	if len(upFam.GetMetric()) == 0 {
		t.Fatal("no host_up samples")
	}
	m := upFam.GetMetric()[0]

	// host_up must NOT carry mac, vendor, hostname.
	for _, forbidden := range []string{"mac", "vendor", "hostname"} {
		if hasLabel(m, forbidden) {
			t.Errorf("host_up carries forbidden label %q", forbidden)
		}
	}
	// host_up must carry ip and subnet.
	for _, required := range []string{"ip", "subnet"} {
		if !hasLabel(m, required) {
			t.Errorf("host_up missing required label %q", required)
		}
	}
}

func TestHostInfoUnknownFallback(t *testing.T) {
	ctx := context.Background()
	store := state.NewMemoryStore()
	subnet := "10.0.23.0/24"

	// Host with nil MAC, empty vendor, no hostnames.
	rec := state.HostRecord{
		IP:       netip.MustParseAddr("10.0.23.1"),
		MAC:      nil, // nil MAC
		Vendor:   "",  // empty vendor
		LastSeen: time.Now(),
		Alive:    true,
	}
	if _, err := store.UpdateHost(ctx, rec); err != nil {
		t.Fatal(err)
	}

	c := newTestCollector(store, subnet)
	families := collectMetrics(c)

	infoFam := findMetric(families, "signet_host_info")
	if infoFam == nil {
		t.Fatal("signet_host_info not emitted")
	}
	infoSample := findSample(infoFam, map[string]string{
		"ip":       "10.0.23.1",
		"mac":      "unknown",
		"vendor":   "unknown",
		"hostname": "unknown",
		"subnet":   subnet,
	})
	if infoSample == nil {
		t.Fatal("host_info must use 'unknown' for nil MAC, empty vendor, and empty hostname")
	}
}

func TestBothMetricsEmittedPerHost(t *testing.T) {
	ctx := context.Background()
	store := state.NewMemoryStore()
	subnet := "10.0.24.0/24"

	const N = 5
	for i := 1; i <= N; i++ {
		ip := netip.AddrFrom4([4]byte{10, 0, 24, byte(i)}).String()
		mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, byte(i)}.String()
		if _, err := store.UpdateHost(ctx, makeHost(ip, mac)); err != nil {
			t.Fatal(err)
		}
	}

	c := newTestCollector(store, subnet)
	families := collectMetrics(c)

	upFam := findMetric(families, "signet_host_up")
	if upFam == nil || len(upFam.GetMetric()) != N {
		t.Errorf("expected %d host_up samples, got %d", N, len(upFam.GetMetric()))
	}

	infoFam := findMetric(families, "signet_host_info")
	if infoFam == nil || len(infoFam.GetMetric()) != N {
		t.Errorf("expected %d host_info samples, got %d", N, len(infoFam.GetMetric()))
	}
}

// --- Step 19: Active series estimate tests ---

func TestActiveSeriesEstimateZeroHosts(t *testing.T) {
	store := state.NewMemoryStore()
	// No subnets, no hosts.
	c := NewSignetCollector(store, nil, nil)
	families := collectMetrics(c)

	fam := findMetric(families, "signet_active_series_estimate")
	if fam == nil {
		t.Fatal("signet_active_series_estimate not emitted")
	}
	val := fam.GetMetric()[0].GetGauge().GetValue()
	if val != 0.0 {
		t.Errorf("estimate with no hosts and no subnets = %v, want 0", val)
	}
}

func TestActiveSeriesEstimateScalesWithPorts(t *testing.T) {
	ctx := context.Background()
	subnet := "10.0.30.0/24"
	const hostCount = 10

	storeA := state.NewMemoryStore()
	storeB := state.NewMemoryStore()
	for i := 1; i <= hostCount; i++ {
		ip := netip.AddrFrom4([4]byte{10, 0, 30, byte(i)}).String()
		mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, byte(i)}.String()
		rec := makeHost(ip, mac)
		if _, err := storeA.UpdateHost(ctx, rec); err != nil {
			t.Fatal(err)
		}
		if _, err := storeB.UpdateHost(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}

	// Collector with 1 port.
	cA := newTestCollector(storeA, subnet)
	cA.SetPortCount(1)

	// Collector with 5 ports.
	cB := newTestCollector(storeB, subnet)
	cB.SetPortCount(5)

	famA := findMetric(collectMetrics(cA), "signet_active_series_estimate")
	famB := findMetric(collectMetrics(cB), "signet_active_series_estimate")

	if famA == nil || famB == nil {
		t.Fatal("signet_active_series_estimate not emitted")
	}

	estA := famA.GetMetric()[0].GetGauge().GetValue()
	estB := famB.GetMetric()[0].GetGauge().GetValue()

	if estB <= estA {
		t.Errorf("estimate with 5 ports (%v) should be greater than with 1 port (%v)", estB, estA)
	}
}

func TestActiveSeriesEstimateScalesWithHosts(t *testing.T) {
	ctx := context.Background()
	subnet := "10.0.31.0/24"

	storeSmall := state.NewMemoryStore()
	storeLarge := state.NewMemoryStore()

	// 10 hosts in small, 100 hosts in large.
	for i := 1; i <= 100; i++ {
		ip := netip.AddrFrom4([4]byte{10, 0, 31, byte(i)}).String()
		mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, byte(i)}.String()
		rec := makeHost(ip, mac)
		if i <= 10 {
			if _, err := storeSmall.UpdateHost(ctx, rec); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := storeLarge.UpdateHost(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}

	cSmall := newTestCollector(storeSmall, subnet)
	cSmall.SetPortCount(3)
	cLarge := newTestCollector(storeLarge, subnet)
	cLarge.SetPortCount(3)

	famSmall := findMetric(collectMetrics(cSmall), "signet_active_series_estimate")
	famLarge := findMetric(collectMetrics(cLarge), "signet_active_series_estimate")

	if famSmall == nil || famLarge == nil {
		t.Fatal("signet_active_series_estimate not emitted")
	}

	estSmall := famSmall.GetMetric()[0].GetGauge().GetValue()
	estLarge := famLarge.GetMetric()[0].GetGauge().GetValue()

	if estLarge <= estSmall {
		t.Errorf("estimate with 100 hosts (%v) should be greater than with 10 hosts (%v)", estLarge, estSmall)
	}
}

func TestActiveSeriesEstimatePresent(t *testing.T) {
	ctx := context.Background()
	store := state.NewMemoryStore()
	subnet := "10.0.32.0/24"

	rec := makeHost("10.0.32.1", "aa:bb:cc:dd:ee:01")
	if _, err := store.UpdateHost(ctx, rec); err != nil {
		t.Fatal(err)
	}

	c := newTestCollector(store, subnet)
	c.SetPortCount(3)
	families := collectMetrics(c)

	fam := findMetric(families, "signet_active_series_estimate")
	if fam == nil {
		t.Fatal("signet_active_series_estimate not present in gathered output")
	}
	if len(fam.GetMetric()) != 1 {
		t.Fatalf("expected 1 sample, got %d", len(fam.GetMetric()))
	}
	val := fam.GetMetric()[0].GetGauge().GetValue()
	if val <= 0 {
		t.Errorf("signet_active_series_estimate = %v, want > 0 with hosts and ports", val)
	}
}

// TestCollect_HostUp_HostnameLabel_Populated verifies hostname appears on host_info, not host_up.
func TestCollect_HostUp_HostnameLabel_Populated(t *testing.T) {
	ctx := context.Background()
	store := state.NewMemoryStore()
	subnet := "10.0.12.0/24"

	rec := makeHost("10.0.12.1", "aa:bb:cc:dd:ee:01", func(r *state.HostRecord) {
		r.Hostnames = []string{"host1.example.com", "alias.example.com"}
	})
	if _, err := store.UpdateHost(ctx, rec); err != nil {
		t.Fatal(err)
	}

	c := newTestCollector(store, subnet)
	families := collectMetrics(c)

	// hostname must appear on host_info.
	infoFam := findMetric(families, "signet_host_info")
	if infoFam == nil {
		t.Fatal("signet_host_info not emitted")
	}
	s := findSample(infoFam, map[string]string{
		"ip":       "10.0.12.1",
		"hostname": "host1.example.com",
		"subnet":   subnet,
	})
	if s == nil {
		t.Error("no host_info sample with first hostname label")
	}

	// hostname must NOT appear on host_up.
	upFam := findMetric(families, "signet_host_up")
	if upFam == nil {
		t.Fatal("signet_host_up not emitted")
	}
	for _, m := range upFam.GetMetric() {
		if hasLabel(m, "hostname") {
			t.Error("host_up must not carry hostname label")
		}
	}
}

// TestCollect_HostUp_HostnameLabel_Empty verifies that empty hostname falls back to "unknown" on host_info.
func TestCollect_HostUp_HostnameLabel_Empty(t *testing.T) {
	ctx := context.Background()
	store := state.NewMemoryStore()
	subnet := "10.0.13.0/24"

	rec := makeHost("10.0.13.1", "aa:bb:cc:dd:ee:01", func(r *state.HostRecord) {
		r.Hostnames = nil
	})
	if _, err := store.UpdateHost(ctx, rec); err != nil {
		t.Fatal(err)
	}

	c := newTestCollector(store, subnet)
	families := collectMetrics(c)

	// host_info must use "unknown" for missing hostname.
	infoFam := findMetric(families, "signet_host_info")
	if infoFam == nil {
		t.Fatal("signet_host_info not emitted")
	}
	s := findSample(infoFam, map[string]string{
		"ip":       "10.0.13.1",
		"hostname": "unknown",
		"subnet":   subnet,
	})
	if s == nil {
		t.Error("host_info must use 'unknown' for missing hostname, not empty string")
	}
}
