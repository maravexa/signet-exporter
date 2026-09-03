package state

import (
	"net"
	"net/netip"
	"time"
)

// ObservationSource identifies the scanner or policy component that owns an
// observed subset of a HostRecord. A source must never be inferred from which
// fields happen to be non-zero: enrichment scanners intentionally carry a MAC
// copied from the current host while not owning the MAC binding.
type ObservationSource string

const (
	// SourceARP owns L2 identity, vendor, duplicate detection, and liveness.
	SourceARP ObservationSource = "arp"
	// SourceICMP owns L3 liveness only.
	SourceICMP ObservationSource = "icmp"
	// SourceDNS owns hostname and DNS-mismatch enrichment only.
	SourceDNS ObservationSource = "dns"
	// SourcePort owns the current successful TCP port observation only.
	SourcePort ObservationSource = "port"
	// SourceAuthorization owns allowlist authorization for one identity/scope.
	SourceAuthorization ObservationSource = "authorization"
)

// HostRecord represents the observed state of a single host on the network.
type HostRecord struct {
	IP netip.Addr
	// Source and ObservedAt describe the incoming observation passed to
	// UpdateHost. Source is empty only for backward-compatible legacy callers.
	Source     ObservationSource
	ObservedAt time.Time
	// ConfigGeneration identifies the scheduler configuration snapshot that
	// produced this observation. Zero is legacy/unknown and uses timestamp-only
	// ordering for compatibility.
	ConfigGeneration     uint64
	MAC                  net.HardwareAddr
	Vendor               string
	Hostnames            []string
	DNSMismatches        []string // hostnames where reverse→forward lookup doesn't resolve back to this IP
	FirstSeen            time.Time
	LastSeen             time.Time // last successful ARP or ICMP observation; DNS/port/auth never refresh it
	OpenPorts            []uint16
	DuplicateMACs        []net.HardwareAddr // other MACs that claimed this IP in the last ARP scan; nil means none
	Alive                bool               // true if the most recent successful ARP or ICMP observation responded
	Authorized           bool               // true if MAC is in the configured allowlist
	AuthorizationChecked bool               // true if allowlist enforcement was applied this cycle
	AuthorizationScope   string             // deterministic allowlist/config generation used for AuthorizationChecked
	DuplicateChecked     bool               // true if the ARP scanner authoratively set DuplicateMACs this cycle
	MACChangeCount       uint64             // cumulative count of MAC address changes for this IP
	// Per-source freshness watermarks prevent late observations from regressing
	// data owned by that source. They are persisted by durable stores.
	MACObservedAt           time.Time
	DNSObservedAt           time.Time
	PortsObservedAt         time.Time
	AuthorizationObservedAt time.Time
	PortsGeneration         uint64
	AuthorizationGeneration uint64
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
