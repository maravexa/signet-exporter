package state

import (
	"net"
	"net/netip"
	"time"
)

// HostRecord represents the observed state of a single host on the network.
type HostRecord struct {
	IP         netip.Addr
	MAC        net.HardwareAddr
	Vendor     string
	Hostnames  []string
	FirstSeen  time.Time
	LastSeen   time.Time
	OpenPorts  []uint16
	Alive      bool // true if the host responded during the last scan
	Authorized bool // true if MAC is in the configured allowlist
}

// MACIPChange records when a MAC address changes for a given IP.
type MACIPChange struct {
	IP        netip.Addr
	OldMAC    net.HardwareAddr
	NewMAC    net.HardwareAddr
	Timestamp time.Time
}

// BindingEvent records when a MAC-IP binding is first observed or updated.
type BindingEvent struct {
	IP        netip.Addr
	MAC       net.HardwareAddr
	EventType string // "new", "updated", "removed"
	Timestamp time.Time
}
