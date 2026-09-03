package state

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

type storeFactory struct {
	name string
	new  func(*testing.T) Store
}

func ownershipStores() []storeFactory {
	return []storeFactory{
		{
			name: "memory",
			new:  func(*testing.T) Store { return NewMemoryStore() },
		},
		{
			name: "bolt",
			new: func(t *testing.T) Store {
				path := filepath.Join(t.TempDir(), "state.db")
				s, err := NewBoltStore(path)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = s.Close() })
				return s
			},
		},
	}
}

func observedRecord(ip, mac string, source ObservationSource, at time.Time) HostRecord {
	r := HostRecord{
		IP:         netip.MustParseAddr(ip),
		Source:     source,
		ObservedAt: at,
		LastSeen:   at, // retained for callers built against the pre-observation API
		Alive:      true,
	}
	if mac != "" {
		r.MAC = mustMAC(mac)
	}
	return r
}

func mustMAC(raw string) net.HardwareAddr {
	mac, err := net.ParseMAC(raw)
	if err != nil {
		panic(err)
	}
	return mac
}

func TestUpdateHost_SourceOwnershipAndFreshness(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

	for _, backend := range ownershipStores() {
		t.Run(backend.name, func(t *testing.T) {
			store := backend.new(t)
			ip := "10.10.0.7"
			arp := observedRecord(ip, "00:00:5e:00:53:01", SourceARP, base)
			arp.Vendor = "new-vendor"
			arp.DuplicateChecked = true
			created, err := store.UpdateHost(ctx, arp)
			if err != nil {
				t.Fatal(err)
			}
			if !created.Applied || !created.IsNew {
				t.Fatalf("create result = %+v, want applied new observation", created)
			}

			// A port observation carries the MAC it read from state, but it does not own
			// identity, liveness, vendor, or duplicate detection.
			ports := observedRecord(ip, arp.MAC.String(), SourcePort, base.Add(time.Minute))
			ports.OpenPorts = []uint16{443}
			ports.Alive = false
			if _, err := store.UpdateHost(ctx, ports); err != nil {
				t.Fatal(err)
			}

			got, err := store.GetHost(ctx, netip.MustParseAddr(ip))
			if err != nil || got == nil {
				t.Fatalf("GetHost = %v, %v", got, err)
			}
			if got.MAC.String() != arp.MAC.String() || got.Vendor != arp.Vendor || !got.Alive || !got.LastSeen.Equal(base) {
				t.Fatalf("port update modified non-owned fields: %+v", got)
			}
			if len(got.OpenPorts) != 1 || got.OpenPorts[0] != 443 {
				t.Fatalf("port update did not set owned field: %+v", got.OpenPorts)
			}

			// A later successful empty port scan explicitly clears the owned field.
			clearPorts := observedRecord(ip, "", SourcePort, base.Add(2*time.Minute))
			clearPorts.OpenPorts = []uint16{}
			if _, err := store.UpdateHost(ctx, clearPorts); err != nil {
				t.Fatal(err)
			}
			got, _ = store.GetHost(ctx, netip.MustParseAddr(ip))
			if got.OpenPorts == nil || len(got.OpenPorts) != 0 {
				t.Fatalf("successful empty port result must clear ports, got %#v", got.OpenPorts)
			}
			stalePorts := observedRecord(ip, "", SourcePort, base.Add(time.Minute))
			stalePorts.OpenPorts = []uint16{22}
			staleChange, err := store.UpdateHost(ctx, stalePorts)
			if err != nil {
				t.Fatal(err)
			}
			if staleChange.Applied {
				t.Fatalf("stale observation reported as applied: %+v", staleChange)
			}
			got, _ = store.GetHost(ctx, netip.MustParseAddr(ip))
			if len(got.OpenPorts) != 0 {
				t.Fatalf("stale port observation regressed cleared ports: %#v", got.OpenPorts)
			}

			// An older ARP observation cannot regress an already newer identity.
			freshARP := observedRecord(ip, "00:00:5e:00:53:02", SourceARP, base.Add(3*time.Minute))
			if _, err := store.UpdateHost(ctx, freshARP); err != nil {
				t.Fatal(err)
			}
			staleARP := observedRecord(ip, "00:00:5e:00:53:03", SourceARP, base.Add(2*time.Minute))
			change, err := store.UpdateHost(ctx, staleARP)
			if err != nil {
				t.Fatal(err)
			}
			got, _ = store.GetHost(ctx, netip.MustParseAddr(ip))
			if got.MAC.String() != freshARP.MAC.String() || !got.LastSeen.Equal(freshARP.ObservedAt) || change.MACChanged {
				t.Fatalf("stale ARP observation regressed state: change=%+v record=%+v", change, got)
			}
		})
	}
}

func TestUpdateHost_SourceOwnedDNSAndAuthorization(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 9, 2, 13, 0, 0, 0, time.UTC)

	for _, backend := range ownershipStores() {
		t.Run(backend.name, func(t *testing.T) {
			store := backend.new(t)
			ip := "10.10.0.8"
			arp := observedRecord(ip, "00:00:5e:00:53:11", SourceARP, base)
			if _, err := store.UpdateHost(ctx, arp); err != nil {
				t.Fatal(err)
			}

			dns := observedRecord(ip, "00:00:5e:00:53:ff", SourceDNS, base.Add(time.Minute))
			dns.Hostnames = []string{"router.example"}
			dns.DNSMismatches = []string{"router.example"}
			if _, err := store.UpdateHost(ctx, dns); err != nil {
				t.Fatal(err)
			}
			clearDNS := observedRecord(ip, "", SourceDNS, base.Add(2*time.Minute))
			clearDNS.Hostnames = []string{}
			clearDNS.DNSMismatches = []string{}
			if _, err := store.UpdateHost(ctx, clearDNS); err != nil {
				t.Fatal(err)
			}
			staleDNS := observedRecord(ip, "", SourceDNS, base.Add(time.Minute))
			staleDNS.Hostnames = []string{"stale.example"}
			staleDNS.DNSMismatches = []string{"stale.example"}
			if _, err := store.UpdateHost(ctx, staleDNS); err != nil {
				t.Fatal(err)
			}

			auth := observedRecord(ip, "", SourceAuthorization, base.Add(3*time.Minute))
			auth.AuthorizationChecked = true
			auth.Authorized = true
			auth.AuthorizationScope = "allowlist-a"
			if _, err := store.UpdateHost(ctx, auth); err != nil {
				t.Fatal(err)
			}

			// Changing identity invalidates authorization and DNS until they are
			// checked for the new binding; DNS must not have refreshed LastSeen or
			// identity.
			newARP := observedRecord(ip, "00:00:5e:00:53:12", SourceARP, base.Add(4*time.Minute))
			if _, err := store.UpdateHost(ctx, newARP); err != nil {
				t.Fatal(err)
			}
			got, _ := store.GetHost(ctx, netip.MustParseAddr(ip))
			if len(got.Hostnames) != 0 || len(got.DNSMismatches) != 0 || !got.DNSObservedAt.IsZero() {
				t.Fatalf("MAC change did not invalidate DNS state: %+v", got)
			}
			if got.AuthorizationChecked || got.Authorized || got.AuthorizationScope != "" {
				t.Fatalf("MAC change did not invalidate authorization: %+v", got)
			}
			if !got.LastSeen.Equal(newARP.ObservedAt) {
				t.Fatalf("LastSeen = %v, want ARP liveness time %v", got.LastSeen, newARP.ObservedAt)
			}
		})
	}
}

func TestUpdateHost_AuthorizationSourceCanExplicitlyClearPolicy(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 9, 2, 15, 0, 0, 0, time.UTC)
	for _, backend := range ownershipStores() {
		t.Run(backend.name, func(t *testing.T) {
			store := backend.new(t)
			ip := "10.10.0.11"
			if _, err := store.UpdateHost(ctx, observedRecord(ip, "00:00:5e:00:53:41", SourceARP, base)); err != nil {
				t.Fatal(err)
			}
			authorized := observedRecord(ip, "", SourceAuthorization, base.Add(time.Minute))
			authorized.AuthorizationChecked = true
			authorized.Authorized = true
			authorized.AuthorizationScope = "allowlist-a"
			if _, err := store.UpdateHost(ctx, authorized); err != nil {
				t.Fatal(err)
			}
			clear := observedRecord(ip, "", SourceAuthorization, base.Add(2*time.Minute))
			if _, err := store.UpdateHost(ctx, clear); err != nil {
				t.Fatal(err)
			}
			got, _ := store.GetHost(ctx, netip.MustParseAddr(ip))
			if got.AuthorizationChecked || got.Authorized || got.AuthorizationScope != "" {
				t.Fatalf("explicit authorization clear failed: %+v", got)
			}
		})
	}
}

func TestUpdateHost_EnrichmentRejectsStaleIdentitySnapshot(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 9, 2, 16, 0, 0, 0, time.UTC)
	for _, backend := range ownershipStores() {
		t.Run(backend.name, func(t *testing.T) {
			store := backend.new(t)
			ip := "10.10.0.12"
			oldARP := observedRecord(ip, "00:00:5e:00:53:51", SourceARP, base)
			if _, err := store.UpdateHost(ctx, oldARP); err != nil {
				t.Fatal(err)
			}
			newARP := observedRecord(ip, "00:00:5e:00:53:52", SourceARP, base.Add(time.Minute))
			if _, err := store.UpdateHost(ctx, newARP); err != nil {
				t.Fatal(err)
			}

			// These observations were derived from the old MAC snapshot but arrived
			// after ARP bound the IP to a different identity. None may attach data
			// to the new host generation.
			staleDNS := observedRecord(ip, oldARP.MAC.String(), SourceDNS, base.Add(2*time.Minute))
			staleDNS.Hostnames = []string{"old.example"}
			staleDNS.DNSMismatches = []string{"old.example"}
			stalePort := observedRecord(ip, oldARP.MAC.String(), SourcePort, base.Add(2*time.Minute))
			stalePort.OpenPorts = []uint16{22}
			staleAuth := observedRecord(ip, oldARP.MAC.String(), SourceAuthorization, base.Add(2*time.Minute))
			staleAuth.AuthorizationChecked = true
			staleAuth.Authorized = true
			staleAuth.AuthorizationScope = "old-allowlist"
			for _, stale := range []HostRecord{staleDNS, stalePort, staleAuth} {
				if _, err := store.UpdateHost(ctx, stale); err != nil {
					t.Fatal(err)
				}
			}

			got, err := store.GetHost(ctx, netip.MustParseAddr(ip))
			if err != nil || got == nil {
				t.Fatalf("GetHost = %v, %v", got, err)
			}
			if got.MAC.String() != newARP.MAC.String() || len(got.Hostnames) != 0 || len(got.DNSMismatches) != 0 || len(got.OpenPorts) != 0 || got.AuthorizationChecked || got.Authorized || got.AuthorizationScope != "" {
				t.Fatalf("stale identity snapshot mutated new host generation: %+v", got)
			}
			if !got.DNSObservedAt.IsZero() || !got.PortsObservedAt.IsZero() || !got.AuthorizationObservedAt.IsZero() {
				t.Fatalf("stale identity snapshot advanced freshness watermarks: %+v", got)
			}
		})
	}
}

func TestUpdateHost_PortAndAuthorizationRejectOlderConfigGeneration(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 9, 2, 17, 0, 0, 0, time.UTC)
	for _, backend := range ownershipStores() {
		t.Run(backend.name, func(t *testing.T) {
			store := backend.new(t)
			ip := "10.10.0.13"
			arp := observedRecord(ip, "00:00:5e:00:53:61", SourceARP, base)
			if _, err := store.UpdateHost(ctx, arp); err != nil {
				t.Fatal(err)
			}

			portsV1 := observedRecord(ip, arp.MAC.String(), SourcePort, base.Add(time.Minute))
			portsV1.ConfigGeneration = 1
			portsV1.OpenPorts = []uint16{22}
			portsV2 := observedRecord(ip, arp.MAC.String(), SourcePort, base.Add(2*time.Minute))
			portsV2.ConfigGeneration = 2
			portsV2.OpenPorts = []uint16{443}
			latePortsV1 := observedRecord(ip, arp.MAC.String(), SourcePort, base.Add(3*time.Minute))
			latePortsV1.ConfigGeneration = 1
			latePortsV1.OpenPorts = []uint16{22}
			lateLegacyPorts := observedRecord(ip, arp.MAC.String(), SourcePort, base.Add(4*time.Minute))
			lateLegacyPorts.OpenPorts = []uint16{22}
			for _, record := range []HostRecord{portsV1, portsV2, latePortsV1, lateLegacyPorts} {
				if _, err := store.UpdateHost(ctx, record); err != nil {
					t.Fatal(err)
				}
			}

			authV1 := observedRecord(ip, arp.MAC.String(), SourceAuthorization, base.Add(time.Minute))
			authV1.ConfigGeneration = 1
			authV1.AuthorizationChecked = true
			authV1.Authorized = true
			authV1.AuthorizationScope = "allowlist-v1"
			authV2 := observedRecord(ip, arp.MAC.String(), SourceAuthorization, base.Add(2*time.Minute))
			authV2.ConfigGeneration = 2
			authV2.AuthorizationChecked = true
			authV2.Authorized = false
			authV2.AuthorizationScope = "allowlist-v2"
			lateAuthV1 := observedRecord(ip, arp.MAC.String(), SourceAuthorization, base.Add(3*time.Minute))
			lateAuthV1.ConfigGeneration = 1
			lateAuthV1.AuthorizationChecked = true
			lateAuthV1.Authorized = true
			lateAuthV1.AuthorizationScope = "allowlist-v1"
			lateLegacyAuth := observedRecord(ip, arp.MAC.String(), SourceAuthorization, base.Add(4*time.Minute))
			lateLegacyAuth.AuthorizationChecked = true
			lateLegacyAuth.Authorized = true
			lateLegacyAuth.AuthorizationScope = "legacy-allowlist"
			for _, record := range []HostRecord{authV1, authV2, lateAuthV1, lateLegacyAuth} {
				if _, err := store.UpdateHost(ctx, record); err != nil {
					t.Fatal(err)
				}
			}

			got, err := store.GetHost(ctx, netip.MustParseAddr(ip))
			if err != nil || got == nil {
				t.Fatalf("GetHost = %+v, %v", got, err)
			}
			if len(got.OpenPorts) != 1 || got.OpenPorts[0] != 443 || got.PortsGeneration != 2 {
				t.Fatalf("older port generation regressed state: %+v", got)
			}
			if !got.AuthorizationChecked || got.Authorized || got.AuthorizationScope != "allowlist-v2" || got.AuthorizationGeneration != 2 {
				t.Fatalf("older authorization generation regressed state: %+v", got)
			}
		})
	}
}

func TestUpdateHost_MACRebindInvalidatesIdentityBoundEnrichment(t *testing.T) {
	ctx := context.Background()
	base := time.Date(2026, 9, 2, 19, 0, 0, 0, time.UTC)
	for _, backend := range ownershipStores() {
		t.Run(backend.name, func(t *testing.T) {
			store := backend.new(t)
			ip := "10.10.0.15"
			arpA := observedRecord(ip, "00:00:5e:00:53:71", SourceARP, base)
			if _, err := store.UpdateHost(ctx, arpA); err != nil {
				t.Fatal(err)
			}
			dnsA := observedRecord(ip, arpA.MAC.String(), SourceDNS, base.Add(time.Minute))
			dnsA.Hostnames = []string{"host-a.example"}
			dnsA.DNSMismatches = []string{"host-a.example"}
			portsA := observedRecord(ip, arpA.MAC.String(), SourcePort, base.Add(time.Minute))
			portsA.ConfigGeneration = 1
			portsA.OpenPorts = []uint16{22}
			authA := observedRecord(ip, arpA.MAC.String(), SourceAuthorization, base.Add(time.Minute))
			authA.ConfigGeneration = 1
			authA.AuthorizationChecked = true
			authA.Authorized = true
			authA.AuthorizationScope = "allowlist-a"
			for _, record := range []HostRecord{dnsA, portsA, authA} {
				if _, err := store.UpdateHost(ctx, record); err != nil {
					t.Fatal(err)
				}
			}

			arpB := observedRecord(ip, "00:00:5e:00:53:72", SourceARP, base.Add(2*time.Minute))
			if _, err := store.UpdateHost(ctx, arpB); err != nil {
				t.Fatal(err)
			}
			got, err := store.GetHost(ctx, netip.MustParseAddr(ip))
			if err != nil || got == nil {
				t.Fatalf("GetHost = %+v, %v", got, err)
			}
			if got.MAC.String() != arpB.MAC.String() || got.Hostnames != nil || got.DNSMismatches != nil || !got.DNSObservedAt.IsZero() || got.OpenPorts != nil || !got.PortsObservedAt.IsZero() || got.PortsGeneration != 0 || got.AuthorizationChecked || got.Authorized || got.AuthorizationScope != "" || !got.AuthorizationObservedAt.IsZero() || got.AuthorizationGeneration != 0 {
				t.Fatalf("MAC rebind retained identity-bound enrichment: %+v", got)
			}
		})
	}
}

func TestBoltStore_PersistsSourceFreshnessAcrossRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	base := time.Date(2026, 9, 2, 14, 0, 0, 0, time.UTC)
	ip := netip.MustParseAddr("10.10.0.9")

	s, err := NewBoltStore(path)
	if err != nil {
		t.Fatal(err)
	}
	newer := observedRecord(ip.String(), "00:00:5e:00:53:21", SourceARP, base.Add(time.Minute))
	if _, err := s.UpdateHost(ctx, newer); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = NewBoltStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	older := observedRecord(ip.String(), "00:00:5e:00:53:22", SourceARP, base)
	if _, err := s.UpdateHost(ctx, older); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetHost(ctx, ip)
	if got.MAC.String() != newer.MAC.String() || !got.LastSeen.Equal(newer.ObservedAt) {
		t.Fatalf("restart lost freshness guard: %+v", got)
	}
}

func TestBoltStoreResetsConfigGenerationFloorsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	base := time.Date(2026, 9, 2, 18, 0, 0, 0, time.UTC)
	ip := "10.10.0.14"

	s, err := NewBoltStore(path)
	if err != nil {
		t.Fatal(err)
	}
	arp := observedRecord(ip, "00:00:5e:00:53:62", SourceARP, base)
	portsV2 := observedRecord(ip, arp.MAC.String(), SourcePort, base.Add(time.Minute))
	portsV2.ConfigGeneration = 10
	portsV2.OpenPorts = []uint16{443}
	authV2 := observedRecord(ip, arp.MAC.String(), SourceAuthorization, base.Add(time.Minute))
	authV2.ConfigGeneration = 10
	authV2.AuthorizationChecked = true
	authV2.AuthorizationScope = "allowlist-v2"
	for _, record := range []HostRecord{arp, portsV2, authV2} {
		if _, err := s.UpdateHost(ctx, record); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = NewBoltStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	latePortsV1 := observedRecord(ip, arp.MAC.String(), SourcePort, base.Add(2*time.Minute))
	latePortsV1.ConfigGeneration = 1
	latePortsV1.OpenPorts = []uint16{22}
	lateAuthV1 := observedRecord(ip, arp.MAC.String(), SourceAuthorization, base.Add(2*time.Minute))
	lateAuthV1.ConfigGeneration = 1
	lateAuthV1.AuthorizationChecked = true
	lateAuthV1.Authorized = true
	lateAuthV1.AuthorizationScope = "allowlist-v1"
	for _, record := range []HostRecord{latePortsV1, lateAuthV1} {
		if _, err := s.UpdateHost(ctx, record); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.GetHost(ctx, netip.MustParseAddr(ip))
	if err != nil || got == nil {
		t.Fatalf("GetHost = %+v, %v", got, err)
	}
	if len(got.OpenPorts) != 1 || got.OpenPorts[0] != 22 || got.PortsGeneration != 1 || !got.Authorized || got.AuthorizationScope != "allowlist-v1" || got.AuthorizationGeneration != 1 {
		t.Fatalf("restart did not reset process-local generation floors: %+v", got)
	}
}

func TestEnrichmentObservationCannotRediscoverPrunedHost(t *testing.T) {
	ctx := context.Background()
	base := time.Now().Add(-2 * time.Hour)
	for _, backend := range ownershipStores() {
		t.Run(backend.name, func(t *testing.T) {
			store := backend.new(t)
			arp := observedRecord("10.10.0.10", "00:00:5e:00:53:31", SourceARP, base)
			if _, err := store.UpdateHost(ctx, arp); err != nil {
				t.Fatal(err)
			}
			if _, err := store.PruneStale(time.Hour); err != nil {
				t.Fatal(err)
			}
			port := observedRecord("10.10.0.10", arp.MAC.String(), SourcePort, time.Now())
			port.OpenPorts = []uint16{22}
			if _, err := store.UpdateHost(ctx, port); err != nil {
				t.Fatal(err)
			}
			got, err := store.GetHost(ctx, arp.IP)
			if err != nil || got != nil {
				t.Fatalf("enrichment resurrected pruned host: record=%+v err=%v", got, err)
			}
		})
	}
}
