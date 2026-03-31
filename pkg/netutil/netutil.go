// Package netutil provides shared network utility functions for subnet iteration and IP math.
package netutil

import (
	"context"
	"net/netip"
)

// SubnetAddrs returns a channel that yields every usable host address in a prefix.
// For IPv4 prefixes /30 and smaller: skips network address (first) and broadcast (last).
// For /31 (point-to-point): yields both addresses per RFC 3021.
// For /32: yields the single address.
// The channel is closed when iteration is complete or ctx is cancelled.
func SubnetAddrs(ctx context.Context, prefix netip.Prefix) <-chan netip.Addr {
	ch := make(chan netip.Addr)
	go func() {
		defer close(ch)
		masked := prefix.Masked()
		bits := masked.Bits()
		addrBits := masked.Addr().BitLen()
		hostBits := addrBits - bits

		send := func(addr netip.Addr) bool {
			select {
			case ch <- addr:
				return true
			case <-ctx.Done():
				return false
			}
		}

		switch hostBits {
		case 0:
			// /32 or /128: single address
			send(masked.Addr())

		case 1:
			// /31 or /127: yield both addresses (RFC 3021)
			addr := masked.Addr()
			for prefix.Contains(addr) {
				if !send(addr) {
					return
				}
				addr = addr.Next()
			}

		default:
			// Skip network address (first); skip broadcast (last).
			// Use lookahead: yield addr only if addr.Next() is still in the prefix.
			addr := masked.Addr().Next() // skip network address
			for prefix.Contains(addr) {
				next := addr.Next()
				if !prefix.Contains(next) {
					// addr is the broadcast address — stop without yielding it
					return
				}
				if !send(addr) {
					return
				}
				addr = next
			}
		}
	}()
	return ch
}

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
