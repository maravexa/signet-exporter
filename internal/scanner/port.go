package scanner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/maravexa/signet-exporter/internal/state"
)

type portProbeStatus uint8

const (
	portProbeUnknown portProbeStatus = iota
	portProbeOpen
	portProbeClosed
)

// PortScanner performs lightweight TCP connect probes on a configured set of ports.
// It is an enrichment scanner — it operates on hosts already in the state store.
// No raw sockets are required; it uses standard net.Dial (TCP connect scan).
type PortScanner struct {
	store        state.Store
	mu           sync.RWMutex        // protects ports; allows hot-reload via UpdatePorts
	ports        map[string][]uint16 // subnet CIDR string → ports to scan
	defaultPorts []uint16            // fallback if subnet has no specific port list
	timeout      time.Duration
	maxWorkers   int
	logger       *slog.Logger
}

type portSnapshotContextKey struct{}

// withPortSnapshot attaches a scheduler-owned immutable port configuration to
// a single scan cycle. It is intentionally package-private: only Scheduler
// constructs a generation and PortScanner consumes it.
func withPortSnapshot(ctx context.Context, ports map[string][]uint16) context.Context {
	if ports == nil {
		return ctx
	}
	return context.WithValue(ctx, portSnapshotContextKey{}, ports)
}

func portSnapshotFromContext(ctx context.Context) (map[string][]uint16, bool) {
	ports, ok := ctx.Value(portSnapshotContextKey{}).(map[string][]uint16)
	return ports, ok
}

func cloneSubnetPorts(ports map[string][]uint16) map[string][]uint16 {
	if ports == nil {
		return nil
	}
	cloned := make(map[string][]uint16, len(ports))
	for subnet, values := range ports {
		cloned[subnet] = append([]uint16(nil), values...)
	}
	return cloned
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
		ports:        cloneSubnetPorts(subnetPorts),
		defaultPorts: append([]uint16(nil), defaultPorts...),
		timeout:      timeout,
		maxWorkers:   maxWorkers,
		logger:       logger,
	}
}

// Name returns the scanner identifier.
func (p *PortScanner) Name() string { return "port" }

// UpdatePorts atomically replaces the per-subnet port map.
// Safe to call from a SIGHUP handler while Scan is running concurrently.
func (p *PortScanner) UpdatePorts(ports map[string][]uint16) {
	p.mu.Lock()
	p.ports = cloneSubnetPorts(ports)
	p.mu.Unlock()
}

// Scan probes each configured port on every known host in subnet.
// Returns one ScanResult per host that has at least one open port.
// If no ports are configured for this subnet, returns nil, nil.
func (p *PortScanner) Scan(ctx context.Context, subnet netip.Prefix) ([]ScanResult, error) {
	// Determine which ports to scan for this subnet — read under lock for hot-reload safety.
	var ports []uint16
	snapshotConfigured := false
	if snapshot, ok := portSnapshotFromContext(ctx); ok {
		snapshotConfigured = true
		ports = append([]uint16(nil), snapshot[subnet.String()]...)
	} else {
		p.mu.RLock()
		ports = append([]uint16(nil), p.ports[subnet.String()]...)
		if len(ports) == 0 {
			ports = append([]uint16(nil), p.defaultPorts...)
		}
		p.mu.RUnlock()
	}
	if len(ports) == 0 && !snapshotConfigured {
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
		ip       netip.Addr
		mac      net.HardwareAddr
		alive    bool
		lastSeen time.Time
		port     uint16
	}

	work := make([]workItem, 0, len(hosts)*len(ports))
	for _, host := range hosts {
		for _, port := range ports {
			work = append(work, workItem{ip: host.IP, mac: host.MAC, alive: host.Alive, lastSeen: host.LastSeen, port: port})
		}
	}

	type portResult struct {
		ip       netip.Addr
		mac      net.HardwareAddr
		alive    bool
		lastSeen time.Time
		port     uint16
		status   portProbeStatus
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

			status := p.probePort(ctx, w.ip, w.port)
			resultsCh <- portResult{ip: w.ip, mac: w.mac, alive: w.alive, lastSeen: w.lastSeen, port: w.port, status: status}
		}()
	}

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	// Start with every scanned host, not just hosts with open ports. A completed
	// scan with no open ports is an explicit empty port observation and must be
	// able to clear stale source-owned port data.
	hostResults := make(map[netip.Addr]*ScanResult)
	definitive := make(map[netip.Addr]bool, len(hosts))
	for _, host := range hosts {
		definitive[host.IP] = true
		hostResults[host.IP] = &ScanResult{
			IP:     host.IP,
			MAC:    host.MAC,
			Alive:  host.Alive,
			Source: "port",
			// State uses Source to retain discovery liveness; this timestamp is
			// the freshness of the port observation only.
			Timestamp: time.Now(),
			OpenPorts: make([]uint16, 0),
		}
	}

	for pr := range resultsCh {
		if pr.status == portProbeUnknown {
			definitive[pr.ip] = false
			continue
		}
		if pr.status != portProbeOpen {
			continue
		}

		result := hostResults[pr.ip]
		result.OpenPorts = append(result.OpenPorts, pr.port)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	results := make([]ScanResult, 0, len(hostResults))
	for ip, result := range hostResults {
		if !definitive[ip] {
			p.logger.Warn("port scan incomplete; preserving prior port observation", "ip", ip, "subnet", subnet)
			continue
		}
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
	return p.probePort(ctx, ip, port) == portProbeOpen
}

// probePort distinguishes a confirmed closed port (connection refused) from
// an unknown result (timeout, cancellation, or transport failure). Unknown
// must not clear a previous successful port observation.
func (p *PortScanner) probePort(ctx context.Context, ip netip.Addr, port uint16) portProbeStatus {
	addr := net.JoinHostPort(ip.String(), strconv.FormatUint(uint64(port), 10))
	d := net.Dialer{Timeout: p.timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) {
			return portProbeClosed
		}
		return portProbeUnknown
	}
	_ = conn.Close()
	return portProbeOpen
}
