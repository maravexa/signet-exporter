// Package scanner implements network probe scanners.
// This file implements the DNS enrichment scanner, which performs forward and
// reverse DNS lookups for hosts already in the state store and records any
// forward/reverse inconsistencies (split-horizon, stale PTR records, etc.).
package scanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync/atomic"
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
// (UDP, round-robin across the configured list). If servers is empty, the
// system resolver is used.
// If logger is nil, slog.Default() is used.
func NewDNSScanner(store state.Store, servers []string, timeout time.Duration, logger *slog.Logger) *DNSScanner {
	if logger == nil {
		logger = slog.Default()
	}

	var lookup dnsLookup
	if len(servers) > 0 {
		serverList := append([]string(nil), servers...)
		var nextServer atomic.Uint64
		lookup = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				index := (nextServer.Add(1) - 1) % uint64(len(serverList))
				return d.DialContext(ctx, "udp", serverList[index])
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
// mismatches. A successful lookup with no PTR returns an explicit empty
// enrichment result so previously recorded DNS data can be cleared. DNS never
// asserts liveness: every result preserves the host's existing observation
// timestamp and Alive value.
func (d *DNSScanner) Scan(ctx context.Context, subnet netip.Prefix) ([]ScanResult, error) {
	hosts, err := d.store.ListHosts(ctx, subnet)
	if err != nil {
		return nil, fmt.Errorf("listing hosts for DNS enrichment: %w", err)
	}

	var results []ScanResult

	for _, host := range hosts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		revCtx, revCancel := context.WithTimeout(ctx, d.timeout)
		names, err := d.lookup.LookupAddr(revCtx, host.IP.String())
		revCancel()

		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err != nil && !isNotFound(err) {
			// Transport and resolver failures cannot safely clear prior data.
			d.logger.Debug("reverse DNS lookup failed",
				"ip", host.IP.String(),
				"error", err,
			)
			continue
		}

		// LookupAddr returns FQDNs with a trailing dot — strip it.
		nameSet := make(map[string]struct{}, len(names))
		for _, name := range names {
			if clean := strings.TrimSuffix(name, "."); clean != "" {
				nameSet[clean] = struct{}{}
			}
		}
		cleanNames := make([]string, 0, len(nameSet))
		for name := range nameSet {
			cleanNames = append(cleanNames, name)
		}
		sort.Strings(cleanNames)
		truncated := false
		if len(cleanNames) > maxDNSNamesPerHost {
			cleanNames = cleanNames[:maxDNSNamesPerHost]
			truncated = true
		}

		// Forward lookup consistency check.
		mismatches := make([]string, 0)
		verificationFailed := false
		for _, name := range cleanNames {
			fwdCtx, fwdCancel := context.WithTimeout(ctx, d.timeout)
			addrs, err := d.lookup.LookupHost(fwdCtx, name)
			fwdCancel()

			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if err != nil {
				if isNotFound(err) {
					// A definitive NXDOMAIN after PTR is a mismatch.
					mismatches = append(mismatches, name)
					continue
				}
				// A timeout or transport failure is unknown, not a DNS mismatch.
				// Preserve the previous source-owned DNS observation for this host.
				d.logger.Warn("forward DNS lookup could not be verified; preserving prior DNS observation",
					"ip", host.IP.String(), "hostname", name, "error", err)
				verificationFailed = true
				break
			}

			if len(addrs) == 0 {
				// A successful empty answer is a definitive mismatch.
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
		if verificationFailed {
			continue
		}

		metadata := map[string]string(nil)
		if truncated {
			metadata = map[string]string{"dns_results_truncated": "true"}
		}
		results = append(results, ScanResult{
			IP:  host.IP,
			MAC: host.MAC, // preserve existing MAC binding
			// DNS is enrichment, not a reachability probe. State uses Source to
			// retain discovery liveness; this timestamp is DNS freshness only.
			Alive:         host.Alive,
			Source:        "dns",
			Timestamp:     time.Now(),
			Hostnames:     cleanNames,
			DNSMismatches: mismatches, // empty slice = checked, no mismatches
			Metadata:      metadata,
		})
	}

	return results, nil
}

func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}
