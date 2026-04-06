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

// ApplyConfigParams carries mutable configuration for a live config reload.
// Passed to Scheduler.ApplyConfig from the SIGHUP handler.
type ApplyConfigParams struct {
	Subnets    []SubnetConfig        // updated subnet list (Prefix + ScanInterval)
	Allowlists map[string]*Allowlist // prefix string → allowlist; nil entry = no auth check
	HostTTL    time.Duration         // duration after which unseen hosts are pruned; 0 disables eviction
}

// Scheduler drives periodic subnet scans with a configurable concurrency limit.
type Scheduler struct {
	// Immutable after construction — no lock required.
	scanners  []Scanner
	store     state.Store
	ouiDB     *oui.Database // may be nil when no OUI file is configured
	auditLog  *audit.Logger // never nil after construction; disabled logger used as no-op
	semaphore chan struct{} // limits the number of concurrent subnet scans in flight
	logger    *slog.Logger
	readyCh   chan struct{} // closed after every configured subnet completes its first scan
	readyOnce sync.Once
	wg        sync.WaitGroup // tracks all active per-subnet goroutines

	// Mutable — protected by mu. Written by ApplyConfig (SIGHUP goroutine),
	// read by per-subnet scan goroutines. Lock is held for microseconds only.
	mu         sync.RWMutex
	subnets    []SubnetConfig        // current subnet list
	allowlists map[string]*Allowlist // key: subnet prefix string; nil map = no allowlists
	hostTTL    time.Duration         // 0 means disabled

	// runCtx is set by Run() and used by ApplyConfig to start goroutines for new subnets.
	// Written once by Run() under mu before any goroutines read it; safe to read without lock
	// after Run() starts.
	runCtx context.Context //nolint:containedctx
}

// NewScheduler creates a Scheduler.
// maxParallel controls how many subnet scans may run concurrently; if <= 0, defaults to 1.
// If scanners is empty, no scanning occurs but the scheduler is otherwise valid.
// ouiDB may be nil; when nil, vendor enrichment is skipped silently.
// auditLog may be nil; when nil, a no-op disabled logger is used.
// allowlists may be nil; when nil, no authorization checks are performed.
// hostTTL is the duration after which unseen hosts are pruned; 0 disables eviction.
func NewScheduler(
	scanners []Scanner,
	store state.Store,
	subnets []SubnetConfig,
	maxParallel int,
	logger *slog.Logger,
	ouiDB *oui.Database,
	auditLog *audit.Logger,
	allowlists map[string]*Allowlist,
	hostTTL time.Duration,
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
		hostTTL:    hostTTL,
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

// ApplyConfig atomically replaces the mutable configuration snapshot.
// Changes take effect on the next scan cycle for each subnet — in-progress scans
// are never interrupted.
//
// New subnets in params.Subnets that were not present before are started immediately.
// Subnets removed from params.Subnets will exit after their current scan cycle completes.
// Safe to call from the SIGHUP goroutine while scan goroutines are running.
func (s *Scheduler) ApplyConfig(params ApplyConfigParams) {
	s.mu.Lock()
	oldSubnets := s.subnets
	s.subnets = params.Subnets
	s.allowlists = params.Allowlists
	s.hostTTL = params.HostTTL
	runCtx := s.runCtx
	s.mu.Unlock()

	if runCtx == nil {
		// Run() has not been called yet; new subnets will be started by Run().
		return
	}

	// Start goroutines for newly-added subnets.
	oldPrefixes := make(map[netip.Prefix]bool, len(oldSubnets))
	for _, sc := range oldSubnets {
		oldPrefixes[sc.Prefix] = true
	}
	for _, sc := range params.Subnets {
		if !oldPrefixes[sc.Prefix] {
			s.wg.Add(1)
			prefix := sc.Prefix
			go func() {
				defer s.wg.Done()
				firstDone := make(chan struct{})
				s.runSubnet(runCtx, prefix, firstDone)
			}()
		}
	}
}

// subnetByPrefix returns the SubnetConfig for the given prefix.
// Caller must hold mu for reading (mu.RLock).
func (s *Scheduler) subnetByPrefix(prefix netip.Prefix) (SubnetConfig, bool) {
	for _, sc := range s.subnets {
		if sc.Prefix == prefix {
			return sc, true
		}
	}
	return SubnetConfig{}, false
}

// Run starts a per-subnet goroutine for each configured subnet and blocks until
// ctx is cancelled. On cancellation, all goroutines drain and Run returns nil.
func (s *Scheduler) Run(ctx context.Context) error {
	// Record run context and snapshot initial subnet list under a single lock.
	s.mu.Lock()
	s.runCtx = ctx
	subnets := append([]SubnetConfig{}, s.subnets...)
	s.mu.Unlock()

	// Start the TTL prune goroutine if eviction is enabled.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.runPrune(ctx)
	}()

	if len(subnets) == 0 {
		// No subnets configured — signal ready immediately and wait for shutdown.
		s.readyOnce.Do(func() { close(s.readyCh) })
		<-ctx.Done()
		s.wg.Wait()
		return nil
	}

	firstScans := make([]chan struct{}, len(subnets))
	for i, sc := range subnets {
		firstScans[i] = make(chan struct{})
		s.wg.Add(1)
		prefix := sc.Prefix
		i := i
		go func() {
			defer s.wg.Done()
			s.runSubnet(ctx, prefix, firstScans[i])
		}()
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

	<-ctx.Done()
	s.wg.Wait()
	return nil
}

// runPrune runs the TTL eviction loop. It ticks at TTL/2 and prunes hosts whose
// LastSeen exceeds the current TTL. If TTL is zero, the loop sleeps until context
// cancellation (eviction disabled). TTL changes via ApplyConfig take effect on
// the next tick.
func (s *Scheduler) runPrune(ctx context.Context) {
	for {
		s.mu.RLock()
		ttl := s.hostTTL
		s.mu.RUnlock()

		if ttl <= 0 {
			// Eviction disabled — wait for context cancellation or a config change.
			// Poll infrequently to pick up TTL changes applied via ApplyConfig.
			t := time.NewTimer(30 * time.Second)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C:
				continue
			}
		}

		interval := ttl / 2
		t := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}

		// Re-read TTL after the timer fires; it may have changed via ApplyConfig.
		s.mu.RLock()
		ttl = s.hostTTL
		s.mu.RUnlock()
		if ttl <= 0 {
			continue
		}

		removed, err := s.store.PruneStale(ttl)
		if err != nil {
			s.logger.Warn("scheduler: PruneStale failed", "err", err)
			continue
		}

		if len(removed) == 0 {
			continue
		}

		// Snapshot the current subnet list to resolve subnet membership.
		s.mu.RLock()
		subnets := append([]SubnetConfig{}, s.subnets...)
		s.mu.RUnlock()

		pruneTime := time.Now()
		for _, ipStr := range removed {
			s.logger.Info("scheduler: host expired by TTL", "ip", ipStr)
			subnet := subnetForIP(ipStr, subnets)
			s.auditLog.HostExpired(ipStr, subnet, pruneTime)
		}
	}
}

// runSubnet runs an immediate first scan, signals completion, then waits the current
// scan interval (re-read from the config snapshot each cycle) before scanning again.
// Exits when ctx is cancelled or the subnet is removed from the config snapshot.
func (s *Scheduler) runSubnet(ctx context.Context, prefix netip.Prefix, firstScanDone chan<- struct{}) {
	// Read initial config.
	s.mu.RLock()
	sc, found := s.subnetByPrefix(prefix)
	s.mu.RUnlock()
	if !found {
		// Subnet was removed before first scan (race between ApplyConfig and goroutine start).
		close(firstScanDone)
		return
	}

	// Immediate first scan — don't wait for the first tick.
	s.scanSubnet(ctx, sc)

	// Signal first scan completion regardless of whether it succeeded or ctx was cancelled.
	// This unblocks the readiness waiter and avoids a deadlock on shutdown.
	close(firstScanDone)

	for {
		// Re-read config at the start of each wait cycle.
		// This picks up interval changes and detects subnet removal.
		s.mu.RLock()
		sc, found = s.subnetByPrefix(prefix)
		s.mu.RUnlock()
		if !found {
			return // subnet removed by ApplyConfig
		}

		t := time.NewTimer(sc.ScanInterval)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}

		// Re-read after the timer fires — config may have changed while we waited.
		s.mu.RLock()
		sc, found = s.subnetByPrefix(prefix)
		s.mu.RUnlock()
		if !found {
			return
		}

		s.scanSubnet(ctx, sc)
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
			s.auditLog.ScanError(subnetStr, scanner.Name(), err)
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
				IP:               r.IP,
				MAC:              r.MAC,
				Alive:            r.Alive,
				LastSeen:         r.Timestamp,
				Hostnames:        r.Hostnames,
				DNSMismatches:    r.DNSMismatches,
				OpenPorts:        r.OpenPorts,
				DuplicateMACs:    r.DuplicateMACs,
				DuplicateChecked: r.DuplicateChecked,
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
			if change.DuplicateDetected {
				s.auditLog.DuplicateIP(ip, subnetStr, r.MAC, r.DuplicateMACs)
			}
		}

		s.auditLog.ScanCompleted(subnetStr, scanner.Name(), duration, len(results))
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

	// Authorization check: read allowlist under lock for hot-reload safety.
	s.mu.RLock()
	al := s.allowlists[subnetStr]
	s.mu.RUnlock()
	if al != nil {
		s.checkAuthorization(ctx, sc, al)
	}
}

// subnetForIP returns the string representation of the first configured subnet that contains
// the given IP string. Returns an empty string if the IP cannot be parsed or no subnet matches.
func subnetForIP(ipStr string, subnets []SubnetConfig) string {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return ""
	}
	for _, sc := range subnets {
		if sc.Prefix.Contains(ip) {
			return sc.Prefix.String()
		}
	}
	return ""
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
