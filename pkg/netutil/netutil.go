// Package netutil provides shared network utility functions for subnet iteration and IP math.
package netutil

import (
	"net/netip"
)

// IterateSubnet returns a channel that yields every host address in prefix
// (excluding the network address and broadcast address for IPv4 /31 and larger).
func IterateSubnet(prefix netip.Prefix) <-chan netip.Addr {
	ch := make(chan netip.Addr)
	go func() {
		defer close(ch)
		addr := prefix.Addr()
		for prefix.Contains(addr) {
			ch <- addr
			addr = addr.Next()
		}
	}()
	return ch
}

// SubnetSize returns the number of usable host addresses in an IPv4 prefix.
// For a /32 this is 1; for a /31 this is 2; for all others it is 2^(32-bits)-2.
func SubnetSize(prefix netip.Prefix) uint64 {
	bits := prefix.Bits()
	addrBits := prefix.Addr().BitLen()
	hostBits := addrBits - bits

	if hostBits <= 0 {
		return 1
	}
	total := uint64(1) << uint(hostBits)
	if hostBits == 1 {
		// /31 — point-to-point, both addresses are usable (RFC 3021)
		return total
	}
	// Subtract network and broadcast addresses.
	return total - 2
}

// ContainsAddr reports whether ip is a host address (not the network or broadcast)
// within prefix.
func ContainsAddr(prefix netip.Prefix, ip netip.Addr) bool {
	if !prefix.Contains(ip) {
		return false
	}
	// Network address check.
	if ip == prefix.Masked().Addr() {
		return false
	}
	return true
}
