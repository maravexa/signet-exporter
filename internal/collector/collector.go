// Package collector implements the Prometheus metrics collector for signet-exporter.
package collector

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"strings"
	"time"

	"github.com/maravexa/signet-exporter/internal/state"
	"github.com/maravexa/signet-exporter/internal/version"
	"github.com/maravexa/signet-exporter/pkg/netutil"
	"github.com/prometheus/client_golang/prometheus"
)

// stalenessThreshold is the duration after which a host is considered stale.
// TODO: use per-subnet scan interval for staleness once the scheduler exposes it.
const stalenessThreshold = 5 * time.Minute

// SignetCollector implements prometheus.Collector by reading from a state.Store.
type SignetCollector struct {
	store   state.Store
	subnets []netip.Prefix
	logger  *slog.Logger

	// Metric descriptors — created once in the constructor, reused on every Collect.
	hostUp                    *prometheus.Desc
	scanDuration              *prometheus.Desc
	lastScanTimestamp         *prometheus.Desc
	duplicateIP               *prometheus.Desc
	dnsForwardReverseMismatch *prometheus.Desc
	macIPBindingChanges       *prometheus.Desc
	subnetAddressesUsed       *prometheus.Desc
	subnetAddressesTotal      *prometheus.Desc
	unauthorizedDevice        *prometheus.Desc
	portOpen                  *prometheus.Desc
	scanErrors                *prometheus.Desc
	buildInfo                 *prometheus.Desc
}

// NewSignetCollector creates a collector wired to the given state store, subnet list, and logger.
// If logger is nil, slog.Default() is used.
func NewSignetCollector(store state.Store, subnets []netip.Prefix, logger *slog.Logger) *SignetCollector {
	if logger == nil {
		logger = slog.Default()
	}
	return &SignetCollector{
		store:   store,
		subnets: subnets,
		logger:  logger,

		hostUp: prometheus.NewDesc(
			"signet_host_up",
			"1 if the host responded during the most recent scan, 0 otherwise.",
			[]string{"ip", "mac", "vendor", "hostname", "subnet"}, nil,
		),
		scanDuration: prometheus.NewDesc(
			"signet_scan_duration_seconds",
			"Duration of the most recent scan cycle for a subnet/scanner pair.",
			[]string{"subnet", "scanner"}, nil,
		),
		lastScanTimestamp: prometheus.NewDesc(
			"signet_last_scan_timestamp",
			"Unix timestamp of the most recent completed scan for a subnet.",
			[]string{"subnet"}, nil,
		),
		duplicateIP: prometheus.NewDesc(
			"signet_duplicate_ip_detected",
			"1 if multiple MACs claimed the same IP during the last ARP scan. Absent when no duplicate is detected.",
			[]string{"ip", "macs", "subnet"}, nil,
		),
		dnsForwardReverseMismatch: prometheus.NewDesc(
			"signet_dns_forward_reverse_mismatch",
			"1 if the forward and reverse DNS records for this host are inconsistent.",
			[]string{"ip", "hostname", "subnet"}, nil,
		),
		macIPBindingChanges: prometheus.NewDesc(
			"signet_mac_ip_binding_changes_total",
			"Cumulative count of MAC address changes observed for an IP.",
			[]string{"ip", "subnet"}, nil,
		),
		subnetAddressesUsed: prometheus.NewDesc(
			"signet_subnet_addresses_used",
			"Number of hosts detected in the subnet.",
			[]string{"subnet"}, nil,
		),
		subnetAddressesTotal: prometheus.NewDesc(
			"signet_subnet_addresses_total",
			"Total number of usable addresses in the subnet.",
			[]string{"subnet"}, nil,
		),
		unauthorizedDevice: prometheus.NewDesc(
			"signet_unauthorized_device_detected",
			"1 if a device whose MAC is not in the allowlist has been detected, 0 otherwise.",
			[]string{"ip", "mac", "vendor", "subnet"}, nil,
		),
		portOpen: prometheus.NewDesc(
			"signet_port_open",
			"1 if the TCP port responded during the most recent scan.",
			[]string{"ip", "port", "subnet"}, nil,
		),
		scanErrors: prometheus.NewDesc(
			"signet_scan_errors_total",
			"Cumulative number of errors encountered during scans.",
			[]string{"subnet", "scanner"}, nil,
		),
		buildInfo: prometheus.NewDesc(
			"signet_exporter_build_info",
			"Always 1. Carries build metadata as labels.",
			[]string{"version", "commit", "goversion"}, nil,
		),
	}
}

// Describe sends all metric descriptors to ch. Called once at registration time.
func (c *SignetCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.hostUp
	ch <- c.scanDuration
	ch <- c.lastScanTimestamp
	ch <- c.duplicateIP
	ch <- c.dnsForwardReverseMismatch
	ch <- c.macIPBindingChanges
	ch <- c.subnetAddressesUsed
	ch <- c.subnetAddressesTotal
	ch <- c.unauthorizedDevice
	ch <- c.portOpen
	ch <- c.scanErrors
	ch <- c.buildInfo
}

// Collect reads the current state and emits metrics. Called on every Prometheus scrape.
// It must be fast and must never block on network I/O — all reads are in-memory.
func (c *SignetCollector) Collect(ch chan<- prometheus.Metric) {
	// context.Background() is appropriate here: these are in-memory reads that
	// return in microseconds, so no timeout or cancellation is needed.
	ctx := context.Background()

	// Build info is always emitted regardless of store contents.
	ch <- prometheus.MustNewConstMetric(
		c.buildInfo,
		prometheus.GaugeValue,
		1,
		version.Version, version.Commit, runtime.Version(),
	)

	now := time.Now()

	for _, subnet := range c.subnets {
		subnetStr := subnet.String()

		hosts, err := c.store.ListHosts(ctx, subnet)
		if err != nil {
			c.logger.Warn("collector: ListHosts failed", "subnet", subnetStr, "err", err)
			continue
		}

		// Subnet utilization.
		ch <- prometheus.MustNewConstMetric(
			c.subnetAddressesUsed,
			prometheus.GaugeValue,
			float64(len(hosts)),
			subnetStr,
		)
		ch <- prometheus.MustNewConstMetric(
			c.subnetAddressesTotal,
			prometheus.GaugeValue,
			float64(netutil.SubnetSize(subnet)),
			subnetStr,
		)

		// Per-host metrics.
		for _, host := range hosts {
			ipStr := host.IP.String()
			macStr := host.MAC.String()
			vendor := host.Vendor
			if vendor == "" {
				vendor = "unknown"
			}

			// signet_host_up: 0 if the host hasn't been seen within the staleness window.
			// TODO: use per-subnet scan interval for staleness once the scheduler exposes it.
			upVal := 1.0
			if now.Sub(host.LastSeen) > stalenessThreshold {
				upVal = 0.0
			}
			hostname := ""
			if len(host.Hostnames) > 0 {
				hostname = host.Hostnames[0]
			}
			ch <- prometheus.MustNewConstMetric(
				c.hostUp,
				prometheus.GaugeValue,
				upVal,
				ipStr, macStr, vendor, hostname, subnetStr,
			)

			// signet_unauthorized_device_detected: only emitted for hosts whose
			// allowlist check has been applied and whose MAC is not authorized.
			if host.AuthorizationChecked && !host.Authorized {
				ch <- prometheus.MustNewConstMetric(
					c.unauthorizedDevice,
					prometheus.GaugeValue,
					1,
					ipStr, macStr, vendor, subnetStr,
				)
			}

			// signet_port_open: one metric per open port.
			for _, port := range host.OpenPorts {
				ch <- prometheus.MustNewConstMetric(
					c.portOpen,
					prometheus.GaugeValue,
					1,
					ipStr, fmt.Sprintf("%d", port), subnetStr,
				)
			}

			// signet_mac_ip_binding_changes_total: read cumulative count from the record.
			if host.MACChangeCount > 0 {
				ch <- prometheus.MustNewConstMetric(
					c.macIPBindingChanges,
					prometheus.CounterValue,
					float64(host.MACChangeCount),
					ipStr, subnetStr,
				)
			}

			// signet_dns_forward_reverse_mismatch: one sample per mismatched hostname.
			for _, hostname := range host.DNSMismatches {
				ch <- prometheus.MustNewConstMetric(
					c.dnsForwardReverseMismatch,
					prometheus.GaugeValue,
					1,
					ipStr, hostname, subnetStr,
				)
			}

			// signet_duplicate_ip_detected: only emitted when ARP saw multiple MACs for this IP.
			// The macs label contains all claimants (primary first) as a comma-separated string.
			if len(host.DuplicateMACs) > 0 {
				allMACs := make([]string, 0, 1+len(host.DuplicateMACs))
				allMACs = append(allMACs, macStr)
				for _, dm := range host.DuplicateMACs {
					allMACs = append(allMACs, dm.String())
				}
				ch <- prometheus.MustNewConstMetric(
					c.duplicateIP,
					prometheus.GaugeValue,
					1,
					ipStr, strings.Join(allMACs, ","), subnetStr,
				)
			}
		}

		// Scan timing metadata — emitted only when the scheduler has recorded data.
		metas, err := c.store.GetScanMeta(ctx, subnet)
		if err != nil {
			c.logger.Warn("collector: GetScanMeta failed", "subnet", subnetStr, "err", err)
			continue
		}

		// signet_last_scan_timestamp has only a `subnet` label, so emit the
		// most-recent timestamp across all scanners to avoid duplicate label sets.
		var latestTimestamp time.Time
		for _, meta := range metas {
			ch <- prometheus.MustNewConstMetric(
				c.scanDuration,
				prometheus.GaugeValue,
				meta.Duration.Seconds(),
				subnetStr, meta.Scanner,
			)
			if meta.Timestamp.After(latestTimestamp) {
				latestTimestamp = meta.Timestamp
			}
			if meta.ErrorCount > 0 {
				ch <- prometheus.MustNewConstMetric(
					c.scanErrors,
					prometheus.CounterValue,
					float64(meta.ErrorCount),
					subnetStr, meta.Scanner,
				)
			}
		}
		if !latestTimestamp.IsZero() {
			ch <- prometheus.MustNewConstMetric(
				c.lastScanTimestamp,
				prometheus.GaugeValue,
				float64(latestTimestamp.Unix()),
				subnetStr,
			)
		}
	}
}
