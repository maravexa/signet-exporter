package scanner

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/maravexa/signet-exporter/internal/audit"
	"github.com/maravexa/signet-exporter/internal/oui"
	"github.com/maravexa/signet-exporter/internal/state"
)

// SubnetConfig describes a single subnet to scan and its timing parameters.
type SubnetConfig struct {
	Prefix       netip.Prefix
	ScanInterval time.Duration
}

// Scheduler drives periodic subnet scans with a configurable concurrency limit.
type Scheduler struct {
	scanners   []Scanner
	store      state.Store
	ouiDB      *oui.Database         // may be nil when no OUI file is configured
	auditLog   *audit.Logger         // never nil after construction; disabled logger used as no-op
	allowlists map[string]*Allowlist // key: subnet prefix string; nil map = no allowlists configured
	subnets    []SubnetConfig
	semaphore  chan struct{} // limits the number of concurrent subnet scans in flight
	logger     *slog.Logger
	readyCh    chan struct{} // closed after every configured subnet completes its first scan
	readyOnce  sync.Once
}

// NewScheduler creates a Scheduler.
// maxParallel controls how many subnet scans may run concurrently; if <= 0, defaults to 1.
// If scanners is empty, no scanning occurs but the scheduler is otherwise valid.
// ouiDB may be nil; when nil, vendor enrichment is skipped silently.
// auditLog may be nil; when nil, a no-op disabled logger is used.
// allowlists may be nil; when nil, no authorization checks are performed.
func NewScheduler(
	scanners []Scanner,
	store state.Store,
	subnets []SubnetConfig,
	maxParallel int,
	logger *slog.Logger,
	ouiDB *oui.Database,
	auditLog *audit.Logger,
	allowlists map[string]*Allowlist,
) *Scheduler {
	if maxParallel <= 0 {
		maxParallel = 1
	}
	if logger == nil {
		logger = slog.Default()
	}
	if auditLog == nil {
		auditLog = audit.Disabled()
	}
	if len(scanners) == 0 {
		logger.Warn("scheduler: no scanners registered — no hosts will be discovered")
	}
	return &Scheduler{
		scanners:   scanners,
		store:      store,
		ouiDB:      ouiDB,
		auditLog:   auditLog,
		allowlists: allowlists,
		subnets:    subnets,
		semaphore:  make(chan struct{}, maxParallel),
		logger:     logger,
		readyCh:    make(chan struct{}),
	}
}

// Ready returns a channel that is closed after every configured subnet has completed
// at least one full scan cycle. Used for readiness probes — Prometheus should not
// scrape an exporter that has not yet scanned (metrics would be empty).
func (s *Scheduler) Ready() <-chan struct{} {
	return s.readyCh
}

// Run starts a per-subnet goroutine for each configured subnet and blocks until
// ctx is cancelled. On cancellation, all goroutines drain and Run returns nil.
func (s *Scheduler) Run(ctx context.Context) error {
	if len(s.subnets) == 0 {
		// No subnets configured — signal ready immediately and wait for shutdown.
		s.readyOnce.Do(func() { close(s.readyCh) })
		<-ctx.Done()
		return nil
	}

	var wg sync.WaitGroup
	firstScans := make([]chan struct{}, len(s.subnets))

	for i := range s.subnets {
		firstScans[i] = make(chan struct{})
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s.runSubnet(ctx, s.subnets[i], firstScans[i])
		}(i)
	}

	// Readiness waiter: closes readyCh once every subnet has finished its first scan.
	go func() {
		for _, ch := range firstScans {
			select {
			case <-ch:
			case <-ctx.Done():
				return
			}
		}
		s.readyOnce.Do(func() { close(s.readyCh) })
	}()

	wg.Wait()
	return nil
}

// runSubnet runs an immediate first scan, signals completion, then ticks periodically.
func (s *Scheduler) runSubnet(ctx context.Context, sc SubnetConfig, firstScanDone chan<- struct{}) {
	// Immediate first scan — don't wait for the first tick.
	s.scanSubnet(ctx, sc)

	// Signal first scan completion regardless of whether it succeeded or ctx was cancelled.
	// This unblocks the readiness waiter and avoids a deadlock on shutdown.
	close(firstScanDone)

	ticker := time.NewTicker(sc.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.scanSubnet(ctx, sc)
		}
	}
}

// scanSubnet acquires the concurrency semaphore, runs all scanners against the subnet,
// and writes results and metadata to the state store.
func (s *Scheduler) scanSubnet(ctx context.Context, sc SubnetConfig) {
	// Acquire concurrency slot; respect cancellation while waiting.
	select {
	case s.semaphore <- struct{}{}:
		defer func() { <-s.semaphore }()
	case <-ctx.Done():
		return
	}

	subnetStr := sc.Prefix.String()
	cycleStart := time.Now()
	var totalHosts int
	scannersRun := make([]string, 0, len(s.scanners))

	for _, scanner := range s.scanners {
		if ctx.Err() != nil {
			return
		}

		start := time.Now()
		results, err := scanner.Scan(ctx, sc.Prefix)
		duration := time.Since(start)

		if err != nil {
			s.logger.Warn("scan failed",
				"scanner", scanner.Name(),
				"subnet", subnetStr,
				"err", err,
				"duration", duration,
			)
			_ = s.store.RecordScanMeta(ctx, state.ScanMeta{
				Subnet:    sc.Prefix,
				Scanner:   scanner.Name(),
				Duration:  duration,
				Timestamp: time.Now(),
				Error:     true,
			})
			continue
		}

		scannersRun = append(scannersRun, scanner.Name())
		totalHosts += len(results)

		for _, r := range results {
			record := state.HostRecord{
				IP:            r.IP,
				MAC:           r.MAC,
				Alive:         r.Alive,
				LastSeen:      r.Timestamp,
				Hostnames:     r.Hostnames,
				DNSMismatches: r.DNSMismatches,
				OpenPorts:     r.OpenPorts,
			}
			if s.ouiDB != nil && len(r.MAC) >= 3 {
				record.Vendor = s.ouiDB.Lookup(r.MAC)
			}
			change, err := s.store.UpdateHost(ctx, record)
			if err != nil {
				s.logger.Warn("failed to update host",
					"ip", r.IP.String(),
					"err", err,
				)
				continue
			}

			// Emit audit events based on what changed.
			ip := net.ParseIP(r.IP.String())
			if change.IsNew {
				hostname := ""
				if len(r.Hostnames) > 0 {
					hostname = r.Hostnames[0]
				}
				s.auditLog.NewHost(ip, subnetStr, r.MAC, record.Vendor, hostname)
			} else if change.MACChanged {
				s.auditLog.MACIPChange(ip, subnetStr, change.OldMAC, r.MAC, change.OldVendor, record.Vendor)
			}
		}

		_ = s.store.RecordScanMeta(ctx, state.ScanMeta{
			Subnet:    sc.Prefix,
			Scanner:   scanner.Name(),
			Duration:  duration,
			Timestamp: time.Now(),
			Error:     false,
		})

		s.logger.Info("scan complete",
			"scanner", scanner.Name(),
			"subnet", subnetStr,
			"hosts_found", len(results),
			"duration", duration,
		)
	}

	s.auditLog.ScanCycleComplete(subnetStr, totalHosts, time.Since(cycleStart), scannersRun)

	// Authorization check: run after all scanners so every discovered host is present.
	if al, ok := s.allowlists[subnetStr]; ok && al != nil {
		s.checkAuthorization(ctx, sc, al)
	}
}

// checkAuthorization checks each known host in the subnet against the MAC allowlist,
// updates authorization state in the store, and emits audit events for rogue devices.
func (s *Scheduler) checkAuthorization(ctx context.Context, sc SubnetConfig, al *Allowlist) {
	hosts, err := s.store.ListHosts(ctx, sc.Prefix)
	if err != nil {
		s.logger.Warn("checkAuthorization: ListHosts failed", "subnet", sc.Prefix, "err", err)
		return
	}
	subnetStr := sc.Prefix.String()
	for _, host := range hosts {
		if len(host.MAC) == 0 {
			continue
		}
		authorized := al.Contains(host.MAC)
		host.AuthorizationChecked = true
		host.Authorized = authorized
		if _, err := s.store.UpdateHost(ctx, host); err != nil {
			s.logger.Warn("checkAuthorization: UpdateHost failed", "ip", host.IP, "err", err)
			continue
		}
		if !authorized {
			ip := net.ParseIP(host.IP.String())
			s.auditLog.UnauthorizedDevice(ip, subnetStr, host.MAC, host.Vendor)
		}
	}
}
