package state

import (
	"net"
	"net/netip"
	"time"
)

// HostRecord represents the observed state of a single host on the network.
type HostRecord struct {
	IP                   netip.Addr
	MAC                  net.HardwareAddr
	Vendor               string
	Hostnames            []string
	DNSMismatches        []string // hostnames where reverse→forward lookup doesn't resolve back to this IP
	FirstSeen            time.Time
	LastSeen             time.Time
	OpenPorts            []uint16
	DuplicateMACs        []net.HardwareAddr // other MACs that claimed this IP in the last ARP scan; nil means none
	Alive                bool               // true if the host responded during the last scan
	Authorized           bool               // true if MAC is in the configured allowlist
	AuthorizationChecked bool               // true if allowlist enforcement was applied this cycle
	DuplicateChecked     bool               // true if the ARP scanner authoratively set DuplicateMACs this cycle
	MACChangeCount       uint64             // cumulative count of MAC address changes for this IP
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

// ScanMeta holds timing information for the most recent scan of a subnet.
type ScanMeta struct {
	Subnet     netip.Prefix
	Scanner    string
	Duration   time.Duration
	Timestamp  time.Time
	Error      bool   // true if the scan ended with an error
	ErrorCount uint64 // cumulative count of scan errors for this subnet/scanner pair (never resets)
}
