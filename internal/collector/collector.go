// Package collector implements the Prometheus metrics collector for signet-exporter.
package collector

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/maravexa/signet-exporter/internal/fips"
	"github.com/maravexa/signet-exporter/internal/state"
	"github.com/maravexa/signet-exporter/internal/version"
	"github.com/maravexa/signet-exporter/pkg/netutil"
	"github.com/prometheus/client_golang/prometheus"
)

const defaultScanInterval = time.Minute

// SubnetConfig is the collector's immutable per-subnet scrape configuration.
// ScanInterval is used solely to derive the presence freshness window; it does
// not control scheduling.
type SubnetConfig struct {
	Prefix             netip.Prefix
	ScanInterval       time.Duration
	AuthorizationScope string // empty means no inventory/compliance allowlist is active
}

// Config is a collector snapshot published after a scheduler configuration
// generation has committed. Generation gates enrichment owned by mutable scan
// configuration (ports and inventory/compliance authorization), so retained
// observations from an older generation cannot be emitted as current.
type Config struct {
	Generation uint64
	Subnets    []SubnetConfig
}

// SignetCollector implements prometheus.Collector by reading from a state.Store.
type SignetCollector struct {
	store  state.Store
	logger *slog.Logger

	// config is an immutable snapshot published by ApplyConfig. A scrape reads
	// it exactly once, so it never mixes removed/added subnet membership with
	// a different freshness policy during a hot reload.
	config atomic.Pointer[collectorConfig]

	// Metric descriptors — created once in the constructor, reused on every Collect.
	hostUp                    *prometheus.Desc
	hostInfo                  *prometheus.Desc
	activeSeriesEstimate      *prometheus.Desc
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
	fipsEnabled               *prometheus.Desc
}

type collectorConfig struct {
	generation uint64
	subnets    []SubnetConfig
}

// NewSignetCollector creates a collector wired to the given state store, subnet list, and logger.
// If logger is nil, slog.Default() is used.
// NewSignetCollector creates a collector with a compatibility default scan
// interval. Runtime construction should immediately call ApplyConfig with the
// configured per-subnet intervals.
func NewSignetCollector(store state.Store, subnets []netip.Prefix, logger *slog.Logger) *SignetCollector {
	if logger == nil {
		logger = slog.Default()
	}
	c := &SignetCollector{
		store:  store,
		logger: logger,

		// hostUp: low-cardinality, high-query. ip and subnet only.
		// Breaking change from v0.4.0: mac, vendor, hostname removed; see signet_host_info.
		hostUp: prometheus.NewDesc(
			"signet_host_up",
			"1 if a successful ARP or ICMP presence observation is no older than three times this subnet's scan interval, 0 otherwise.",
			[]string{"ip", "subnet"}, nil,
		),
		// hostInfo: enrichment labels, always value 1. Join with signet_host_up in PromQL.
		hostInfo: prometheus.NewDesc(
			"signet_host_info",
			"Last-known enrichment metadata for a known host. Value is always 1. Join with signet_host_up on (ip, subnet). "+
				"mac, vendor, hostname labels can change as observations are refreshed.",
			[]string{"ip", "mac", "vendor", "hostname", "subnet"}, nil,
		),
		activeSeriesEstimate: prometheus.NewDesc(
			"signet_active_series_estimate",
			"Number of Signet series emitted by the current collector gather.",
			nil, nil,
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
			"1 if an observed MAC is absent from the configured inventory/compliance allowlist. This is not network-access authentication.",
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
		fipsEnabled: prometheus.NewDesc(
			"signet_exporter_fips_enabled",
			"1 if BoringCrypto handles supported crypto operations, 0 otherwise; not a certification indicator.",
			nil, nil,
		),
	}
	collectorSubnets := make([]SubnetConfig, 0, len(subnets))
	for _, prefix := range subnets {
		collectorSubnets = append(collectorSubnets, SubnetConfig{Prefix: prefix, ScanInterval: defaultScanInterval})
	}
	c.ApplyConfig(Config{Subnets: collectorSubnets})
	return c
}

// ApplyConfig atomically replaces the committed scheduler generation, subnet
// membership, and per-subnet freshness/authorization policy. A non-positive
// ScanInterval uses the compatibility default. The input slice is copied so
// callers may reuse it after this method returns.
func (c *SignetCollector) ApplyConfig(config Config) {
	copySubnets := make([]SubnetConfig, len(config.Subnets))
	copy(copySubnets, config.Subnets)
	for i := range copySubnets {
		if copySubnets[i].ScanInterval <= 0 {
			copySubnets[i].ScanInterval = defaultScanInterval
		}
	}
	c.config.Store(&collectorConfig{generation: config.Generation, subnets: copySubnets})
}

// Describe sends all metric descriptors to ch. Called once at registration time.
func (c *SignetCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.hostUp
	ch <- c.hostInfo
	ch <- c.activeSeriesEstimate
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
	ch <- c.fipsEnabled
}

// Collect reads the current state and emits metrics. Called on every Prometheus scrape.
// It must be fast and must never block on network I/O — all reads are in-memory.
func (c *SignetCollector) Collect(ch chan<- prometheus.Metric) {
	// context.Background is appropriate here because Store's collection reads
	// are local state operations; Collect must not initiate network I/O.
	ctx := context.Background()

	// Build info is always emitted regardless of store contents.
	ch <- prometheus.MustNewConstMetric(
		c.buildInfo,
		prometheus.GaugeValue,
		1,
		version.Version, version.Commit, runtime.Version(),
	)

	fipsVal := 0.0
	if fips.Enabled() {
		fipsVal = 1.0
	}
	ch <- prometheus.MustNewConstMetric(c.fipsEnabled, prometheus.GaugeValue, fipsVal)

	now := time.Now()
	cfg := c.config.Load()
	// build_info, fips_enabled, and this metric itself are always emitted.
	estimate := 3.0

	for _, subnetCfg := range cfg.subnets {
		subnet := subnetCfg.Prefix
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
			// host_up and host_info are emitted for every host. All conditional
			// metrics are counted exactly as they are emitted below.
			estimate += 2
			ipStr := host.IP.String()

			// Resolve label values — never emit empty strings for enrichment labels.
			macStr := labelOrUnknown(host.MAC.String())
			if len(host.MAC) == 0 {
				macStr = "unknown"
			}
			vendor := labelOrUnknown(host.Vendor)
			hostname := ""
			if len(host.Hostnames) > 0 {
				hostname = host.Hostnames[0]
			}
			hostname = labelOrUnknown(hostname)

			// signet_host_up represents recent successful ARP/ICMP presence,
			// never inventory membership or DNS/port enrichment. State guarantees
			// LastSeen is refreshed only by those discovery sources.
			upVal := 0.0
			age := now.Sub(host.LastSeen)
			if host.Alive && !host.LastSeen.IsZero() && age >= 0 && age <= 3*subnetCfg.ScanInterval {
				upVal = 1.0
			}
			ch <- prometheus.MustNewConstMetric(
				c.hostUp,
				prometheus.GaugeValue,
				upVal,
				ipStr, subnetStr,
			)

			// signet_host_info: enrichment labels, always 1.
			// Emitted for every known host regardless of Up status — a host that is
			// down is still known and its metadata is still valid.
			ch <- prometheus.MustNewConstMetric(
				c.hostInfo,
				prometheus.GaugeValue,
				1.0,
				ipStr, macStr, vendor, hostname, subnetStr,
			)

			// signet_unauthorized_device_detected: only emitted for hosts whose
			// allowlist check has been applied and whose MAC is not authorized.
			if cfg.generation == host.AuthorizationGeneration &&
				subnetCfg.AuthorizationScope != "" &&
				host.AuthorizationScope == subnetCfg.AuthorizationScope &&
				host.AuthorizationChecked && !host.Authorized {
				estimate++
				ch <- prometheus.MustNewConstMetric(
					c.unauthorizedDevice,
					prometheus.GaugeValue,
					1,
					ipStr, macStr, vendor, subnetStr,
				)
			}

			// signet_port_open: one metric per open port.
			if cfg.generation == host.PortsGeneration {
				for _, port := range host.OpenPorts {
					estimate++
					ch <- prometheus.MustNewConstMetric(
						c.portOpen,
						prometheus.GaugeValue,
						1,
						ipStr, fmt.Sprintf("%d", port), subnetStr,
					)
				}
			}

			// signet_mac_ip_binding_changes_total: read cumulative count from the record.
			if host.MACChangeCount > 0 {
				estimate++
				ch <- prometheus.MustNewConstMetric(
					c.macIPBindingChanges,
					prometheus.CounterValue,
					float64(host.MACChangeCount),
					ipStr, subnetStr,
				)
			}

			// signet_dns_forward_reverse_mismatch: one sample per mismatched hostname.
			for _, hn := range host.DNSMismatches {
				estimate++
				ch <- prometheus.MustNewConstMetric(
					c.dnsForwardReverseMismatch,
					prometheus.GaugeValue,
					1,
					ipStr, hn, subnetStr,
				)
			}

			// signet_duplicate_ip_detected: only emitted when ARP saw multiple MACs for this IP.
			// The macs label contains all claimants (primary first) as a comma-separated string.
			if len(host.DuplicateMACs) > 0 {
				estimate++
				allMACs := make([]string, 0, 1+len(host.DuplicateMACs))
				allMACs = append(allMACs, host.MAC.String())
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

		// Utilization is emitted for every configured subnet.
		estimate += 2

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
			estimate++
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
				estimate++
				ch <- prometheus.MustNewConstMetric(
					c.scanErrors,
					prometheus.CounterValue,
					float64(meta.ErrorCount),
					subnetStr, meta.Scanner,
				)
			}
		}
		if !latestTimestamp.IsZero() {
			estimate++
			ch <- prometheus.MustNewConstMetric(
				c.lastScanTimestamp,
				prometheus.GaugeValue,
				float64(latestTimestamp.Unix()),
				subnetStr,
			)
		}
	}

	ch <- prometheus.MustNewConstMetric(c.activeSeriesEstimate, prometheus.GaugeValue, estimate)
}

// labelOrUnknown returns s if non-empty, otherwise "unknown".
// Prevents empty label values in Prometheus which create ambiguous time series.
func labelOrUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
