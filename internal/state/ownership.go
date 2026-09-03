package state

import (
	"bytes"
	"net"
	"time"
)

// validObservationSource permits the empty source for compatibility with
// callers compiled against the original UpdateHost snapshot contract.
func validObservationSource(source ObservationSource) bool {
	switch source {
	case "", SourceARP, SourceICMP, SourceDNS, SourcePort, SourceAuthorization:
		return true
	default:
		return false
	}
}

func observationTime(record HostRecord) time.Time {
	if !record.ObservedAt.IsZero() {
		return record.ObservedAt
	}
	return record.LastSeen
}

func copyStrings(values []string) []string {
	if values == nil {
		return nil
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}

func copyPorts(values []uint16) []uint16 {
	if values == nil {
		return nil
	}
	out := make([]uint16, len(values))
	copy(out, values)
	return out
}

func newObservedHost(record HostRecord) HostRecord {
	at := observationTime(record)
	if record.Source == "" {
		r := copyHostRecord(&record)
		r.ObservedAt = at
		if r.FirstSeen.IsZero() {
			r.FirstSeen = at
		}
		return r
	}
	r := HostRecord{IP: record.IP, Source: record.Source, ObservedAt: at, FirstSeen: at}
	switch record.Source {
	case SourceARP:
		r.MAC = append(net.HardwareAddr(nil), record.MAC...)
		r.Vendor = record.Vendor
		r.DuplicateChecked = record.DuplicateChecked
		r.DuplicateMACs = copyDuplicateMACs(record.DuplicateMACs)
		r.Alive = record.Alive
		r.LastSeen = at
		r.MACObservedAt = at
	case SourceICMP:
		r.Alive = record.Alive
		r.LastSeen = at
	}
	return r
}

func sourceCanCreateHost(source ObservationSource) bool {
	return source == "" || source == SourceARP || source == SourceICMP
}

func canApply(at, watermark time.Time) bool {
	return watermark.IsZero() || !at.Before(watermark)
}

// compareGeneration orders configuration generations. Both-zero is
// legacy/unknown and falls back to timestamp ordering for compatibility, but
// once a known generation is stored it forms a floor: an unknown incoming
// generation cannot overwrite that established configuration state.
func compareGeneration(incoming, current uint64) int {
	if incoming == 0 && current == 0 {
		return 0
	}
	if incoming == 0 {
		return -1
	}
	if current == 0 {
		return 1
	}
	if incoming < current {
		return -1
	}
	if incoming > current {
		return 1
	}
	return 0
}

func setLastObservation(existing *HostRecord, record HostRecord, at time.Time) {
	existing.Source = record.Source
	existing.ObservedAt = at
}

func applyLiveness(existing *HostRecord, record HostRecord, at time.Time) bool {
	if !canApply(at, existing.LastSeen) {
		return false
	}
	existing.LastSeen = at
	existing.Alive = record.Alive
	return true
}

// matchesExpectedIdentity prevents an enrichment result calculated from an old
// host snapshot from being attached after ARP has rebound the IP to a new MAC.
// An empty expected MAC is intentionally unguarded: ICMP-only hosts have no L2
// identity against which an enrichment caller can safely compare.
func matchesExpectedIdentity(existing *HostRecord, record HostRecord) bool {
	return len(record.MAC) == 0 || bytes.Equal(existing.MAC, record.MAC)
}

// invalidateIdentityBoundState clears observations that were derived from a
// known prior MAC binding. A→B at one IP is a new host generation: old port,
// DNS, and authorization data must not be emitted for B while waiting for
// fresh source-owned observations. This is intentionally not used for an
// ICMP-only host gaining its first MAC, where IP-derived DNS may remain valid.
func invalidateIdentityBoundState(existing *HostRecord) {
	existing.Hostnames = nil
	existing.DNSMismatches = nil
	existing.DNSObservedAt = time.Time{}
	existing.OpenPorts = nil
	existing.PortsObservedAt = time.Time{}
	existing.PortsGeneration = 0
	existing.Authorized = false
	existing.AuthorizationChecked = false
	existing.AuthorizationScope = ""
	existing.AuthorizationObservedAt = time.Time{}
	existing.AuthorizationGeneration = 0
}

// applyHostObservation applies a source-owned, timestamp-guarded mutation to
// an existing host. The returned MACIPChange must be recorded atomically with
// the host write by the backend. The empty source keeps the previous broad
// snapshot behavior for compatibility, but still refuses older snapshots.
func applyHostObservation(existing *HostRecord, record HostRecord) (HostChange, *MACIPChange, bool) {
	at := observationTime(record)

	switch record.Source {
	case SourceARP:
		if !canApply(at, existing.MACObservedAt) {
			return HostChange{}, nil, false
		}
		change := HostChange{}
		var macChange *MACIPChange
		if len(record.MAC) > 0 && !bytes.Equal(existing.MAC, record.MAC) {
			if len(existing.MAC) > 0 {
				change.MACChanged = true
				change.OldMAC = append(net.HardwareAddr(nil), existing.MAC...)
				change.OldVendor = existing.Vendor
				macChange = &MACIPChange{
					IP:        record.IP,
					OldMAC:    append(net.HardwareAddr(nil), existing.MAC...),
					NewMAC:    append(net.HardwareAddr(nil), record.MAC...),
					Timestamp: at,
				}
				existing.MACChangeCount++
				invalidateIdentityBoundState(existing)
			}
			existing.MAC = append(net.HardwareAddr(nil), record.MAC...)
		}
		existing.MACObservedAt = at
		existing.Vendor = record.Vendor
		if record.DuplicateChecked {
			existing.DuplicateChecked = true
			existing.DuplicateMACs = copyDuplicateMACs(record.DuplicateMACs)
			change.DuplicateDetected = len(record.DuplicateMACs) > 0
		}
		applyLiveness(existing, record, at)
		setLastObservation(existing, record, at)
		return change, macChange, true

	case SourceICMP:
		if !applyLiveness(existing, record, at) {
			return HostChange{}, nil, false
		}
		setLastObservation(existing, record, at)
		return HostChange{}, nil, true

	case SourceDNS:
		if !matchesExpectedIdentity(existing, record) || !canApply(at, existing.DNSObservedAt) {
			return HostChange{}, nil, false
		}
		if record.Hostnames == nil && record.DNSMismatches == nil {
			return HostChange{}, nil, false
		}
		if record.Hostnames != nil {
			existing.Hostnames = copyStrings(record.Hostnames)
		}
		if record.DNSMismatches != nil {
			existing.DNSMismatches = copyStrings(record.DNSMismatches)
		}
		existing.DNSObservedAt = at
		setLastObservation(existing, record, at)
		return HostChange{}, nil, true

	case SourcePort:
		generationOrder := compareGeneration(record.ConfigGeneration, existing.PortsGeneration)
		if !matchesExpectedIdentity(existing, record) || generationOrder < 0 || (generationOrder == 0 && !canApply(at, existing.PortsObservedAt)) || record.OpenPorts == nil {
			return HostChange{}, nil, false
		}
		existing.OpenPorts = copyPorts(record.OpenPorts)
		existing.PortsObservedAt = at
		if record.ConfigGeneration != 0 {
			existing.PortsGeneration = record.ConfigGeneration
		}
		setLastObservation(existing, record, at)
		return HostChange{}, nil, true

	case SourceAuthorization:
		generationOrder := compareGeneration(record.ConfigGeneration, existing.AuthorizationGeneration)
		if !matchesExpectedIdentity(existing, record) || generationOrder < 0 || (generationOrder == 0 && !canApply(at, existing.AuthorizationObservedAt)) {
			return HostChange{}, nil, false
		}
		if !record.AuthorizationChecked {
			// SourceAuthorization is itself an explicit authorization mutation. A
			// false Checked value deliberately clears policy state when an
			// allowlist is removed or its scope becomes unavailable.
			existing.AuthorizationChecked = false
			existing.Authorized = false
			existing.AuthorizationScope = ""
			existing.AuthorizationObservedAt = at
			if record.ConfigGeneration != 0 {
				existing.AuthorizationGeneration = record.ConfigGeneration
			}
			setLastObservation(existing, record, at)
			return HostChange{}, nil, true
		}
		existing.AuthorizationChecked = true
		existing.Authorized = record.Authorized
		existing.AuthorizationScope = record.AuthorizationScope
		existing.AuthorizationObservedAt = at
		if record.ConfigGeneration != 0 {
			existing.AuthorizationGeneration = record.ConfigGeneration
		}
		setLastObservation(existing, record, at)
		return HostChange{}, nil, true

	default: // legacy full-snapshot compatibility
		if !canApply(at, existing.LastSeen) {
			return HostChange{}, nil, false
		}
		change := HostChange{}
		var macChange *MACIPChange
		if len(record.MAC) == 0 {
			applyLiveness(existing, record, at)
			if len(record.Hostnames) > 0 {
				existing.Hostnames = copyStrings(record.Hostnames)
			}
			if record.DNSMismatches != nil {
				existing.DNSMismatches = copyStrings(record.DNSMismatches)
			}
			if len(record.OpenPorts) > 0 {
				existing.OpenPorts = copyPorts(record.OpenPorts)
			}
			return change, nil, true
		}
		if !bytes.Equal(existing.MAC, record.MAC) {
			if len(existing.MAC) > 0 {
				change.MACChanged = true
				change.OldMAC = append(net.HardwareAddr(nil), existing.MAC...)
				change.OldVendor = existing.Vendor
				macChange = &MACIPChange{IP: record.IP, OldMAC: append(net.HardwareAddr(nil), existing.MAC...), NewMAC: append(net.HardwareAddr(nil), record.MAC...), Timestamp: at}
				existing.MACChangeCount++
				invalidateIdentityBoundState(existing)
			}
			existing.MAC = append(net.HardwareAddr(nil), record.MAC...)
		}
		applyLiveness(existing, record, at)
		if len(record.Hostnames) > 0 {
			existing.Hostnames = copyStrings(record.Hostnames)
		}
		if record.DNSMismatches != nil {
			existing.DNSMismatches = copyStrings(record.DNSMismatches)
		}
		if len(record.OpenPorts) > 0 {
			existing.OpenPorts = copyPorts(record.OpenPorts)
		}
		existing.Vendor = record.Vendor
		if record.AuthorizationChecked {
			existing.AuthorizationChecked = true
			existing.Authorized = record.Authorized
		}
		if record.DuplicateChecked {
			existing.DuplicateChecked = true
			existing.DuplicateMACs = copyDuplicateMACs(record.DuplicateMACs)
			change.DuplicateDetected = len(record.DuplicateMACs) > 0
		}
		return change, macChange, true
	}
}
