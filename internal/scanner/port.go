package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/maravexa/signet-exporter/internal/state"
)

// PortScanner performs lightweight TCP connect probes on a configured set of ports.
// It is an enrichment scanner — it operates on hosts already in the state store.
// No raw sockets are required; it uses standard net.Dial (TCP connect scan).
type PortScanner struct {
	store        state.Store
	ports        map[string][]uint16 // subnet CIDR string → ports to scan
	defaultPorts []uint16            // fallback if subnet has no specific port list
	timeout      time.Duration
	maxWorkers   int
	logger       *slog.Logger
}

// NewPortScanner creates a TCP port prober.
//
// subnetPorts maps subnet CIDR strings to the port list to scan for that subnet.
// defaultPorts is used for subnets not listed in subnetPorts; if nil or empty,
// those subnets are skipped entirely.
// timeout is the per-connection dial timeout; if zero, defaults to 1 second.
// maxWorkers limits concurrent TCP dials; if zero, defaults to 32.
func NewPortScanner(
	store state.Store,
	subnetPorts map[string][]uint16,
	defaultPorts []uint16,
	timeout time.Duration,
	maxWorkers int,
	logger *slog.Logger,
) *PortScanner {
	if timeout <= 0 {
		timeout = 1 * time.Second
	}
	if maxWorkers <= 0 {
		maxWorkers = 32
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &PortScanner{
		store:        store,
		ports:        subnetPorts,
		defaultPorts: defaultPorts,
		timeout:      timeout,
		maxWorkers:   maxWorkers,
		logger:       logger,
	}
}

// Name returns the scanner identifier.
func (p *PortScanner) Name() string { return "port" }

// Scan probes each configured port on every known host in subnet.
// Returns one ScanResult per host that has at least one open port.
// If no ports are configured for this subnet, returns nil, nil.
func (p *PortScanner) Scan(ctx context.Context, subnet netip.Prefix) ([]ScanResult, error) {
	// Determine which ports to scan for this subnet.
	ports := p.ports[subnet.String()]
	if len(ports) == 0 {
		ports = p.defaultPorts
	}
	if len(ports) == 0 {
		return nil, nil
	}

	hosts, err := p.store.ListHosts(ctx, subnet)
	if err != nil {
		return nil, fmt.Errorf("listing hosts for port scan: %w", err)
	}
	if len(hosts) == 0 {
		return nil, nil
	}

	type workItem struct {
		ip   netip.Addr
		mac  net.HardwareAddr
		port uint16
	}

	work := make([]workItem, 0, len(hosts)*len(ports))
	for _, host := range hosts {
		for _, port := range ports {
			work = append(work, workItem{ip: host.IP, mac: host.MAC, port: port})
		}
	}

	type portResult struct {
		ip   netip.Addr
		mac  net.HardwareAddr
		port uint16
		open bool
	}

	resultsCh := make(chan portResult, len(work))

	sem := make(chan struct{}, p.maxWorkers)
	var wg sync.WaitGroup

workLoop:
	for _, w := range work {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		w := w

		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			wg.Done()
			break workLoop
		}

		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			open := p.checkPort(ctx, w.ip, w.port)
			resultsCh <- portResult{ip: w.ip, mac: w.mac, port: w.port, open: open}
		}()
	}

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	// Aggregate open ports per host.
	hostResults := make(map[netip.Addr]*ScanResult)

	for pr := range resultsCh {
		if !pr.open {
			continue
		}

		result, exists := hostResults[pr.ip]
		if !exists {
			result = &ScanResult{
				IP:        pr.ip,
				MAC:       pr.mac,
				Alive:     true,
				Source:    "port",
				Timestamp: time.Now(),
				Metadata:  map[string]string{},
			}
			hostResults[pr.ip] = result
		}
		result.OpenPorts = append(result.OpenPorts, pr.port)
	}

	results := make([]ScanResult, 0, len(hostResults))
	for _, result := range hostResults {
		sort.Slice(result.OpenPorts, func(i, j int) bool {
			return result.OpenPorts[i] < result.OpenPorts[j]
		})
		results = append(results, *result)
	}

	return results, nil
}

// checkPort attempts a TCP connection to ip:port and returns true if the
// connection succeeds (port open). Connection refused and timeout both return false.
func (p *PortScanner) checkPort(ctx context.Context, ip netip.Addr, port uint16) bool {
	addr := net.JoinHostPort(ip.String(), strconv.FormatUint(uint64(port), 10))
	d := net.Dialer{Timeout: p.timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
