// Package scanner implements network probe scanners.
// This file implements the DNS enrichment scanner, which performs forward and
// reverse DNS lookups for hosts already in the state store and records any
// forward/reverse inconsistencies (split-horizon, stale PTR records, etc.).
package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/maravexa/signet-exporter/internal/state"
)

// dnsLookup abstracts the subset of net.Resolver used by DNSScanner,
// allowing test injection of a mock resolver.
type dnsLookup interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// DNSScanner performs forward and reverse DNS lookups to detect mismatches.
// It is an enrichment scanner — it operates on hosts already in the state
// store rather than discovering new ones.
type DNSScanner struct {
	store   state.Store
	lookup  dnsLookup
	timeout time.Duration
	logger  *slog.Logger
}

// NewDNSScanner creates a DNS enrichment scanner.
// If servers is non-empty, a custom resolver is created using those addresses
// (UDP, round-robin through the first server). If servers is empty, the
// system resolver is used.
// If logger is nil, slog.Default() is used.
func NewDNSScanner(store state.Store, servers []string, timeout time.Duration, logger *slog.Logger) *DNSScanner {
	if logger == nil {
		logger = slog.Default()
	}

	var lookup dnsLookup
	if len(servers) > 0 {
		lookup = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(ctx, "udp", servers[0])
			},
		}
	} else {
		lookup = net.DefaultResolver
	}

	return &DNSScanner{
		store:   store,
		lookup:  lookup,
		timeout: timeout,
		logger:  logger,
	}
}

// Name returns the scanner identifier.
func (d *DNSScanner) Name() string { return "dns" }

// Scan performs reverse DNS lookups for all known hosts in subnet, then
// validates each returned hostname with a forward lookup. Hosts where the
// forward lookup does not resolve back to the original IP are flagged as
// mismatches. Results include populated Hostnames and DNSMismatches fields;
// no new hosts are discovered.
func (d *DNSScanner) Scan(ctx context.Context, subnet netip.Prefix) ([]ScanResult, error) {
	hosts, err := d.store.ListHosts(ctx, subnet)
	if err != nil {
		return nil, fmt.Errorf("listing hosts for DNS enrichment: %w", err)
	}

	var results []ScanResult

	for _, host := range hosts {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}

		revCtx, revCancel := context.WithTimeout(ctx, d.timeout)
		names, err := d.lookup.LookupAddr(revCtx, host.IP.String())
		revCancel()

		if err != nil {
			// Missing PTR records are common and not an error worth logging at WARN.
			d.logger.Debug("reverse DNS lookup failed",
				"ip", host.IP.String(),
				"error", err,
			)
			continue
		}

		// LookupAddr returns FQDNs with a trailing dot — strip it.
		cleanNames := make([]string, 0, len(names))
		for _, name := range names {
			cleanNames = append(cleanNames, strings.TrimSuffix(name, "."))
		}

		// Forward lookup consistency check.
		mismatches := make([]string, 0)
		for _, name := range cleanNames {
			fwdCtx, fwdCancel := context.WithTimeout(ctx, d.timeout)
			addrs, err := d.lookup.LookupHost(fwdCtx, name)
			fwdCancel()

			if err != nil {
				// Cannot verify forward → treat as mismatch.
				mismatches = append(mismatches, name)
				continue
			}

			found := false
			for _, addr := range addrs {
				parsed, parseErr := netip.ParseAddr(addr)
				if parseErr != nil {
					continue
				}
				if parsed == host.IP {
					found = true
					break
				}
			}
			if !found {
				mismatches = append(mismatches, name)
			}
		}

		results = append(results, ScanResult{
			IP:            host.IP,
			MAC:           host.MAC, // preserve existing MAC binding
			Alive:         true,
			Source:        "dns",
			Timestamp:     time.Now(),
			Hostnames:     cleanNames,
			DNSMismatches: mismatches, // empty slice = checked, no mismatches
		})
	}

	return results, nil
}
