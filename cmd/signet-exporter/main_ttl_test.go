package main

import (
	"testing"
	"time"

	"github.com/maravexa/signet-exporter/internal/config"
)

func TestEffectiveHostTTL(t *testing.T) {
	base := config.ReloadableConfig{Subnets: []config.ReloadableSubnet{
		{CIDR: "10.0.1.0/24", ScanInterval: time.Minute},
		{CIDR: "10.0.2.0/24", ScanInterval: 5 * time.Minute},
	}}
	if got, want := effectiveHostTTL(base), 15*time.Minute; got != want {
		t.Fatalf("omitted host_ttl = %s, want %s", got, want)
	}
	explicitZero := base
	explicitZero.HostTTLSet = true
	if got := effectiveHostTTL(explicitZero); got != 0 {
		t.Fatalf("explicit zero host_ttl = %s, want disabled (0)", got)
	}
	explicit := base
	explicit.HostTTLSet = true
	explicit.HostTTL = 42 * time.Second
	if got := effectiveHostTTL(explicit); got != explicit.HostTTL {
		t.Fatalf("explicit host_ttl = %s, want %s", got, explicit.HostTTL)
	}
}
