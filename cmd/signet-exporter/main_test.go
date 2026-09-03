package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/maravexa/signet-exporter/internal/config"
)

func TestMaxConfiguredPortCount(t *testing.T) {
	got := maxConfiguredPortCount([]config.SubnetConfig{
		{Ports: []uint16{22, 443}},
		{Ports: []uint16{53, 80, 8080, 8443}},
		{},
	})
	if got != 4 {
		t.Fatalf("maxConfiguredPortCount = %d, want 4", got)
	}
}

func TestImmutableConfigChanges(t *testing.T) {
	base := config.DefaultConfig()
	base.ListenAddress = "127.0.0.1:9420"
	base.DNS.Servers = []string{"127.0.0.1"}
	base.Scanner.ICMPTimeout = time.Second

	if got := immutableConfigChanges(base, base); len(got) != 0 {
		t.Fatalf("same config reported immutable changes: %v", got)
	}

	candidate := *base
	candidate.DNS.Servers = []string{"127.0.0.2"}
	candidate.Scanner.PortTimeout = 2 * time.Second
	candidate.Audit.Enabled = !base.Audit.Enabled
	if got, want := immutableConfigChanges(base, &candidate), []string{"dns", "scanner", "audit"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("immutableConfigChanges = %v, want %v", got, want)
	}
}
