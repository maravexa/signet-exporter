package collector

import (
	"context"
	"log/slog"
	"runtime"

	"github.com/maravexa/signet-exporter/internal/config"
	"github.com/maravexa/signet-exporter/internal/state"
	"github.com/maravexa/signet-exporter/internal/version"
	"github.com/prometheus/client_golang/prometheus"
)

// SignetCollector implements prometheus.Collector by reading from a state.Store.
type SignetCollector struct {
	store state.Store
	cfg   *config.Config
	log   *slog.Logger
	descs map[string]*prometheus.Desc
}

// NewSignetCollector creates a collector wired to the given state store and config.
func NewSignetCollector(store state.Store, cfg *config.Config, log *slog.Logger) *SignetCollector {
	labels := func(keys ...string) []string { return keys }

	descs := map[string]*prometheus.Desc{
		"host_up": prometheus.NewDesc(
			"signet_host_up",
			"1 if the host responded during the last scan, 0 otherwise.",
			labels("ip", "mac", "vendor", "subnet"), nil,
		),
		"scan_duration_seconds": prometheus.NewDesc(
			"signet_scan_duration_seconds",
			"Duration of the most recent scan for a subnet/scanner pair.",
			labels("subnet", "scanner"), nil,
		),
		"last_scan_timestamp": prometheus.NewDesc(
			"signet_last_scan_timestamp",
			"Unix timestamp of the most recent completed scan for a subnet.",
			labels("subnet"), nil,
		),
		"duplicate_ip_detected": prometheus.NewDesc(
			"signet_duplicate_ip_detected",
			"1 if more than one MAC address has been observed for this IP.",
			labels("ip", "subnet"), nil,
		),
		"dns_forward_reverse_mismatch": prometheus.NewDesc(
			"signet_dns_forward_reverse_mismatch",
			"1 if forward and reverse DNS records for this host are inconsistent.",
			labels("ip", "hostname", "subnet"), nil,
		),
		"mac_ip_binding_changes_total": prometheus.NewDesc(
			"signet_mac_ip_binding_changes_total",
			"Total number of MAC-IP binding changes observed for this IP.",
			labels("ip", "subnet"), nil,
		),
		"subnet_addresses_used": prometheus.NewDesc(
			"signet_subnet_addresses_used",
			"Number of IP addresses currently observed as active in the subnet.",
			labels("subnet"), nil,
		),
		"subnet_addresses_total": prometheus.NewDesc(
			"signet_subnet_addresses_total",
			"Total number of usable host addresses in the subnet.",
			labels("subnet"), nil,
		),
		"unauthorized_device_detected": prometheus.NewDesc(
			"signet_unauthorized_device_detected",
			"1 if a device whose MAC is not in the allowlist has been observed.",
			labels("ip", "mac", "vendor", "subnet"), nil,
		),
		"port_open": prometheus.NewDesc(
			"signet_port_open",
			"1 if the TCP port was observed open during the last scan.",
			labels("ip", "port", "subnet"), nil,
		),
		"scan_errors_total": prometheus.NewDesc(
			"signet_scan_errors_total",
			"Total number of errors encountered during scans.",
			labels("subnet", "scanner"), nil,
		),
		"build_info": prometheus.NewDesc(
			"signet_exporter_build_info",
			"Build metadata for this signet-exporter instance.",
			labels("version", "commit", "goversion"), nil,
		),
	}

	return &SignetCollector{
		store: store,
		cfg:   cfg,
		log:   log,
		descs: descs,
	}
}

// Describe sends all metric descriptors to the channel.
func (c *SignetCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range c.descs {
		ch <- d
	}
}

// Collect reads current state and emits metrics for each registered descriptor.
func (c *SignetCollector) Collect(ch chan<- prometheus.Metric) {
	ctx := context.Background()

	// Emit build info metric.
	ch <- prometheus.MustNewConstMetric(
		c.descs["build_info"],
		prometheus.GaugeValue,
		1,
		version.Version, version.Commit, runtime.Version(),
	)

	// Collect per-subnet host metrics.
	for _, sub := range c.cfg.Subnets {
		// TODO: parse subnet prefix and emit host_up, port_open, unauthorized_device_detected,
		//       duplicate_ip_detected, dns_forward_reverse_mismatch, mac_ip_binding_changes_total,
		//       subnet_addresses_used, subnet_addresses_total by reading from c.store.
		_ = sub
		_ = ctx
	}

	// TODO: emit scan_duration_seconds, last_scan_timestamp, scan_errors_total
	//       once the scheduler exposes timing telemetry.
}
