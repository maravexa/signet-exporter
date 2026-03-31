package state

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// makeTestRecord creates a HostRecord with the given IP and MAC.
func makeTestRecord(ip string, mac string) HostRecord {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		panic("invalid MAC in test: " + err.Error())
	}
	return HostRecord{
		IP:        netip.MustParseAddr(ip),
		MAC:       hw,
		Vendor:    "TestVendor",
		Hostnames: []string{"host-" + ip},
		FirstSeen: time.Time{},
		LastSeen:  time.Now(),
		OpenPorts: []uint16{22, 80},
		Alive:     true,
	}
}

// mustParsePrefix wraps netip.MustParsePrefix for test readability.
func mustParsePrefix(s string) netip.Prefix {
	return netip.MustParsePrefix(s)
}

func TestUpdateHost_NewHost(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()
	rec := makeTestRecord("10.0.1.1", "aa:bb:cc:dd:ee:ff")
	rec.LastSeen = time.Unix(1000, 0)
	rec.FirstSeen = time.Time{} // zero — should be set by store

	if err := m.UpdateHost(ctx, rec); err != nil {
		t.Fatalf("UpdateHost error: %v", err)
	}

	got, err := m.GetHost(ctx, rec.IP)
	if err != nil {
		t.Fatalf("GetHost error: %v", err)
	}
	if got == nil {
		t.Fatal("expected record, got nil")
	}
	if got.IP != rec.IP {
		t.Errorf("IP mismatch: got %v want %v", got.IP, rec.IP)
	}
	if !got.FirstSeen.Equal(rec.LastSeen) {
		t.Errorf("FirstSeen not set from LastSeen: got %v want %v", got.FirstSeen, rec.LastSeen)
	}

	// Appears in ListHosts for correct subnet
	hosts, err := m.ListHosts(ctx, mustParsePrefix("10.0.1.0/24"))
	if err != nil {
		t.Fatalf("ListHosts error: %v", err)
	}
	if len(hosts) != 1 {
		t.Errorf("ListHosts count: got %d want 1", len(hosts))
	}

	// macIndex populated
	ips := m.IPsForMAC(rec.MAC)
	if len(ips) != 1 || ips[0] != rec.IP {
		t.Errorf("IPsForMAC: got %v want [%v]", ips, rec.IP)
	}
}

func TestUpdateHost_SameMAC_UpdatesFields(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()
	rec := makeTestRecord("10.0.1.2", "aa:bb:cc:dd:ee:01")
	rec.LastSeen = time.Unix(1000, 0)
	if err := m.UpdateHost(ctx, rec); err != nil {
		t.Fatal(err)
	}

	got1, _ := m.GetHost(ctx, rec.IP)
	firstSeen := got1.FirstSeen

	// Update with same MAC, different fields
	rec2 := makeTestRecord("10.0.1.2", "aa:bb:cc:dd:ee:01")
	rec2.LastSeen = time.Unix(2000, 0)
	rec2.Hostnames = []string{"updated-host"}
	rec2.OpenPorts = []uint16{443}
	if err := m.UpdateHost(ctx, rec2); err != nil {
		t.Fatal(err)
	}

	got2, _ := m.GetHost(ctx, rec.IP)
	if !got2.LastSeen.Equal(time.Unix(2000, 0)) {
		t.Errorf("LastSeen not updated: got %v", got2.LastSeen)
	}
	if len(got2.Hostnames) != 1 || got2.Hostnames[0] != "updated-host" {
		t.Errorf("Hostnames not updated: got %v", got2.Hostnames)
	}
	if len(got2.OpenPorts) != 1 || got2.OpenPorts[0] != 443 {
		t.Errorf("OpenPorts not updated: got %v", got2.OpenPorts)
	}
	if !got2.FirstSeen.Equal(firstSeen) {
		t.Errorf("FirstSeen was overwritten: was %v now %v", firstSeen, got2.FirstSeen)
	}
}

func TestUpdateHost_DifferentMAC_RecordsChange(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()

	macA := "aa:bb:cc:dd:ee:01"
	macB := "11:22:33:44:55:66"
	ip := "10.0.1.3"

	recA := makeTestRecord(ip, macA)
	recA.LastSeen = time.Unix(1000, 0)
	if err := m.UpdateHost(ctx, recA); err != nil {
		t.Fatal(err)
	}
	got1, _ := m.GetHost(ctx, recA.IP)
	firstSeen := got1.FirstSeen

	recB := makeTestRecord(ip, macB)
	recB.LastSeen = time.Unix(2000, 0)
	if err := m.UpdateHost(ctx, recB); err != nil {
		t.Fatal(err)
	}

	// Host now has MAC-B
	got2, _ := m.GetHost(ctx, recA.IP)
	hwB, _ := net.ParseMAC(macB)
	if got2.MAC.String() != hwB.String() {
		t.Errorf("MAC not updated: got %v want %v", got2.MAC, hwB)
	}

	// MACIPChange recorded
	changes, _ := m.RecentChanges(ctx, time.Unix(0, 0))
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	hwA, _ := net.ParseMAC(macA)
	if changes[0].OldMAC.String() != hwA.String() {
		t.Errorf("OldMAC wrong: got %v want %v", changes[0].OldMAC, hwA)
	}
	if changes[0].NewMAC.String() != hwB.String() {
		t.Errorf("NewMAC wrong: got %v want %v", changes[0].NewMAC, hwB)
	}

	// macIndex: MAC-A no longer maps to this IP
	if ips := m.IPsForMAC(hwA); len(ips) != 0 {
		t.Errorf("old MAC still maps to IP: %v", ips)
	}
	// MAC-B maps to this IP
	if ips := m.IPsForMAC(hwB); len(ips) != 1 || ips[0] != recA.IP {
		t.Errorf("new MAC does not map to IP: %v", ips)
	}

	// FirstSeen not overwritten
	if !got2.FirstSeen.Equal(firstSeen) {
		t.Errorf("FirstSeen overwritten: was %v now %v", firstSeen, got2.FirstSeen)
	}
}

func TestUpdateHost_DifferentMAC_MultipleChanges(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()

	ip := "10.0.1.4"
	macs := []string{
		"aa:00:00:00:00:01",
		"aa:00:00:00:00:02",
		"aa:00:00:00:00:03",
		"aa:00:00:00:00:04",
	}

	for i, mac := range macs {
		rec := makeTestRecord(ip, mac)
		rec.LastSeen = time.Unix(int64(1000+i), 0)
		if err := m.UpdateHost(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}

	// 3 changes (A→B, B→C, C→D)
	changes, _ := m.RecentChanges(ctx, time.Unix(0, 0))
	if len(changes) != 3 {
		t.Fatalf("expected 3 changes, got %d", len(changes))
	}

	// Verify order: A→B, B→C, C→D
	for i := 0; i < 3; i++ {
		hwOld, _ := net.ParseMAC(macs[i])
		hwNew, _ := net.ParseMAC(macs[i+1])
		if changes[i].OldMAC.String() != hwOld.String() {
			t.Errorf("change[%d].OldMAC = %v want %v", i, changes[i].OldMAC, hwOld)
		}
		if changes[i].NewMAC.String() != hwNew.String() {
			t.Errorf("change[%d].NewMAC = %v want %v", i, changes[i].NewMAC, hwNew)
		}
	}

	// macIndex correct at end: only last MAC maps to this IP
	addr := netip.MustParseAddr(ip)
	for i := 0; i < len(macs)-1; i++ {
		hw, _ := net.ParseMAC(macs[i])
		if ips := m.IPsForMAC(hw); len(ips) != 0 {
			t.Errorf("old MAC %s still maps to IPs: %v", macs[i], ips)
		}
	}
	hwLast, _ := net.ParseMAC(macs[len(macs)-1])
	if ips := m.IPsForMAC(hwLast); len(ips) != 1 || ips[0] != addr {
		t.Errorf("final MAC does not map correctly: %v", ips)
	}
}

func TestGetHost_NotFound(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()
	got, err := m.GetHost(ctx, netip.MustParseAddr("1.2.3.4"))
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil record, got %+v", got)
	}
}

func TestGetHost_ReturnsCopy(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()
	rec := makeTestRecord("10.0.1.5", "bb:bb:bb:bb:bb:bb")
	if err := m.UpdateHost(ctx, rec); err != nil {
		t.Fatal(err)
	}

	got1, _ := m.GetHost(ctx, rec.IP)
	// Mutate returned record
	got1.Hostnames = append(got1.Hostnames, "evil-injection")
	got1.OpenPorts = append(got1.OpenPorts, 9999)

	// Internal state should be unaffected
	got2, _ := m.GetHost(ctx, rec.IP)
	for _, h := range got2.Hostnames {
		if h == "evil-injection" {
			t.Error("internal Hostnames was mutated via returned copy")
		}
	}
	for _, p := range got2.OpenPorts {
		if p == 9999 {
			t.Error("internal OpenPorts was mutated via returned copy")
		}
	}
}

func TestListHosts_SubnetFiltering(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()

	hosts1 := []string{"10.0.1.1", "10.0.1.2", "10.0.1.3"}
	hosts2 := []string{"10.0.2.1", "10.0.2.2"}

	mac := "cc:cc:cc:cc:cc:cc"
	for _, ip := range append(hosts1, hosts2...) {
		if err := m.UpdateHost(ctx, makeTestRecord(ip, mac)); err != nil {
			t.Fatal(err)
		}
		// Use distinct MACs to avoid MAC-change events
		mac = incrementMAC(mac)
	}

	// Subnet 10.0.1.0/24 — 3 hosts
	got, _ := m.ListHosts(ctx, mustParsePrefix("10.0.1.0/24"))
	if len(got) != 3 {
		t.Errorf("10.0.1.0/24: got %d hosts want 3", len(got))
	}

	// Broader subnet 10.0.0.0/16 — all 5 hosts
	got, _ = m.ListHosts(ctx, mustParsePrefix("10.0.0.0/16"))
	if len(got) != 5 {
		t.Errorf("10.0.0.0/16: got %d hosts want 5", len(got))
	}

	// Different subnet — 0 hosts
	got, _ = m.ListHosts(ctx, mustParsePrefix("192.168.0.0/24"))
	if len(got) != 0 {
		t.Errorf("192.168.0.0/24: got %d hosts want 0", len(got))
	}
}

func TestListHosts_EmptySubnet(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()
	if err := m.UpdateHost(ctx, makeTestRecord("10.0.1.1", "dd:dd:dd:dd:dd:dd")); err != nil {
		t.Fatal(err)
	}
	got, err := m.ListHosts(ctx, mustParsePrefix("192.168.100.0/24"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Error("ListHosts returned nil slice, want empty slice")
	}
	if len(got) != 0 {
		t.Errorf("expected 0 hosts, got %d", len(got))
	}
}

func TestRecentChanges_TimeFiltering(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()

	t1 := time.Unix(1, 0)
	t2 := time.Unix(2, 0)
	t3 := time.Unix(3, 0)
	t4 := time.Unix(4, 0)

	events := []MACIPChange{
		{IP: netip.MustParseAddr("1.1.1.1"), Timestamp: t1},
		{IP: netip.MustParseAddr("1.1.1.2"), Timestamp: t2},
		{IP: netip.MustParseAddr("1.1.1.3"), Timestamp: t3},
	}
	for _, e := range events {
		if err := m.RecordMACChange(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	// Since T=2 → returns T=2 and T=3
	got, _ := m.RecentChanges(ctx, t2)
	if len(got) != 2 {
		t.Errorf("since T=2: got %d want 2", len(got))
	}

	// Since T=0 → all 3
	got, _ = m.RecentChanges(ctx, time.Unix(0, 0))
	if len(got) != 3 {
		t.Errorf("since T=0: got %d want 3", len(got))
	}

	// Since T=4 → none
	got, _ = m.RecentChanges(ctx, t4)
	if len(got) != 0 {
		t.Errorf("since T=4: got %d want 0", len(got))
	}
}

func TestChangesRingBuffer_Overflow(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore(WithMaxChanges(5))

	for i := 0; i < 8; i++ {
		e := MACIPChange{
			IP:        netip.MustParseAddr("1.1.1.1"),
			Timestamp: time.Unix(int64(i+1), 0),
		}
		if err := m.RecordMACChange(ctx, e); err != nil {
			t.Fatal(err)
		}
	}

	// Only last 5 retained
	got, _ := m.RecentChanges(ctx, time.Unix(0, 0))
	if len(got) != 5 {
		t.Fatalf("expected 5 changes after overflow, got %d", len(got))
	}

	// Verify they are events 4–8 (timestamps 4,5,6,7,8)
	for i, c := range got {
		want := time.Unix(int64(4+i), 0)
		if !c.Timestamp.Equal(want) {
			t.Errorf("change[%d] timestamp = %v want %v", i, c.Timestamp, want)
		}
	}
}

func TestSubnetUtilization(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()

	// Insert 3 hosts in /24
	for _, ip := range []string{"10.1.1.1", "10.1.1.2", "10.1.1.3"} {
		if err := m.UpdateHost(ctx, makeTestRecord(ip, uniqueMAC(ip))); err != nil {
			t.Fatal(err)
		}
	}

	used, total := m.SubnetUtilization(mustParsePrefix("10.1.1.0/24"))
	if used != 3 {
		t.Errorf("used = %d want 3", used)
	}
	if total != 254 {
		t.Errorf("total = %d want 254", total)
	}

	// /32 with host present
	if err := m.UpdateHost(ctx, makeTestRecord("10.1.2.1", "ee:ee:ee:ee:ee:ee")); err != nil {
		t.Fatal(err)
	}
	used, total = m.SubnetUtilization(mustParsePrefix("10.1.2.1/32"))
	if used != 1 {
		t.Errorf("/32 used = %d want 1", used)
	}
	if total != 1 {
		t.Errorf("/32 total = %d want 1", total)
	}

	// Empty /24
	used, total = m.SubnetUtilization(mustParsePrefix("172.16.0.0/24"))
	if used != 0 {
		t.Errorf("empty subnet used = %d want 0", used)
	}
	if total != 254 {
		t.Errorf("empty /24 total = %d want 254", total)
	}
}

func TestIPsForMAC(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()

	sharedMAC := "ff:ee:dd:cc:bb:aa"
	ip1 := "10.2.1.1"
	ip2 := "10.2.1.2"

	rec1 := makeTestRecord(ip1, sharedMAC)
	rec2 := makeTestRecord(ip2, sharedMAC)
	if err := m.UpdateHost(ctx, rec1); err != nil {
		t.Fatal(err)
	}
	if err := m.UpdateHost(ctx, rec2); err != nil {
		t.Fatal(err)
	}

	hw, _ := net.ParseMAC(sharedMAC)
	ips := m.IPsForMAC(hw)
	if len(ips) != 2 {
		t.Fatalf("IPsForMAC: got %d want 2", len(ips))
	}

	// Move ip1 to a different MAC
	newMAC := "11:11:11:11:11:11"
	rec1b := makeTestRecord(ip1, newMAC)
	rec1b.LastSeen = rec1.LastSeen.Add(time.Second)
	if err := m.UpdateHost(ctx, rec1b); err != nil {
		t.Fatal(err)
	}

	// Old MAC now maps to only ip2
	ips = m.IPsForMAC(hw)
	if len(ips) != 1 {
		t.Fatalf("after update, old MAC should map to 1 IP, got %d", len(ips))
	}
	if ips[0] != netip.MustParseAddr(ip2) {
		t.Errorf("remaining IP for old MAC: got %v want %v", ips[0], ip2)
	}
}

func TestConcurrency(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryStore()

	var wg sync.WaitGroup
	subnet := mustParsePrefix("10.5.0.0/16")

	// 50 writers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := netip.AddrFrom4([4]byte{10, 5, byte(i / 256), byte(i % 256)})
			mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, byte(i >> 8), byte(i)}
			rec := HostRecord{
				IP:       ip,
				MAC:      mac,
				LastSeen: time.Now(),
			}
			_ = m.UpdateHost(ctx, rec)
		}(i)
	}

	// 50 readers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = m.ListHosts(ctx, subnet)
		}()
	}

	wg.Wait()
	// No panic, no race — test passes
}

// --- helpers ---

// incrementMAC returns a trivially different MAC string to avoid collisions in multi-insert tests.
func incrementMAC(mac string) string {
	hw, _ := net.ParseMAC(mac)
	for i := len(hw) - 1; i >= 0; i-- {
		hw[i]++
		if hw[i] != 0 {
			break
		}
	}
	return hw.String()
}

// uniqueMAC generates a unique MAC from an IP string (deterministic, for tests).
func uniqueMAC(ip string) string {
	addr := netip.MustParseAddr(ip)
	b := addr.As4()
	return net.HardwareAddr{0xaa, b[0], b[1], b[2], b[3], 0x01}.String()
}
