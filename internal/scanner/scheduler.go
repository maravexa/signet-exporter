package scanner

import (
	"context"
	"fmt"
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
	// Ports is the immutable per-subnet port snapshot for this generation.
	// A non-nil empty map explicitly means no ports are configured.
	Ports   map[string][]uint16
	HostTTL time.Duration // duration after which unseen hosts are pruned; 0 disables eviction
}

// Scheduler drives periodic subnet scans with a configurable concurrency limit.
type Scheduler struct {
	// Immutable after construction — no lock required.
	scanners    []Scanner
	store       state.Store
	ouiDB       *oui.Database // may be nil when no OUI file is configured
	auditLog    *audit.Logger // never nil after construction; disabled logger used as no-op
	semaphore   chan struct{} // limits the number of concurrent subnet scans in flight
	logger      *slog.Logger
	readyCh     chan struct{} // closed after every configured subnet completes its first scan
	readyOnce   sync.Once
	prepareOnce sync.Once
	wg          sync.WaitGroup // tracks all active per-subnet goroutines

	// Mutable — protected by mu. Written by ApplyConfig (SIGHUP goroutine),
	// read by per-subnet scan goroutines. Lock is held for microseconds only.
	mu         sync.RWMutex
	subnets    []SubnetConfig        // current subnet list
	allowlists map[string]*Allowlist // key: subnet prefix string; nil map = no allowlists
	hostTTL    time.Duration         // 0 means disabled
	ports      map[string][]uint16   // immutable snapshot consumed by PortScanner via scan context
	configWake chan struct{}         // closed and replaced on each committed generation

	// Runtime lifecycle and configuration generation state. All are protected by
	// mu. workers prevents duplicate per-prefix loops across concurrent reloads.
	runCtx     context.Context //nolint:containedctx
	running    bool
	starting   bool
	generation uint64
	workers    map[netip.Prefix]bool
}

// scanCycle is an immutable configuration snapshot for exactly one subnet
// cycle. In-flight work must use its allowlist rather than a newer reload.
type scanCycle struct {
	subnet     SubnetConfig
	allowlist  *Allowlist
	ports      map[string][]uint16
	configWake <-chan struct{}
	generation uint64
}

// PrepareStartup synchronously prunes already-expired persisted hosts. Call it
// before exposing inventory to scrapes or remote write; Run calls it as a
// fallback for direct Scheduler users.
func (s *Scheduler) PrepareStartup() {
	s.prepareOnce.Do(func() {
		s.mu.RLock()
		ttl := s.hostTTL
		s.mu.RUnlock()
		s.pruneOnce(ttl)
	})
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
		allowlists: cloneAllowlists(allowlists),
		subnets:    normalizeSubnets(subnets, logger),
		hostTTL:    hostTTL,
		semaphore:  make(chan struct{}, maxParallel),
		logger:     logger,
		readyCh:    make(chan struct{}),
		workers:    make(map[netip.Prefix]bool),
		configWake: make(chan struct{}),
	}
}

func cloneAllowlists(allowlists map[string]*Allowlist) map[string]*Allowlist {
	if allowlists == nil {
		return nil
	}
	cloned := make(map[string]*Allowlist, len(allowlists))
	for prefix, allowlist := range allowlists {
		cloned[prefix] = allowlist
	}
	return cloned
}

func cloneSubnets(subnets []SubnetConfig) []SubnetConfig {
	return append([]SubnetConfig(nil), subnets...)
}

func clonePorts(ports map[string][]uint16) map[string][]uint16 {
	if ports == nil {
		return nil
	}
	cloned := make(map[string][]uint16, len(ports))
	for prefix, values := range ports {
		cloned[prefix] = append([]uint16(nil), values...)
	}
	return cloned
}

// normalizeSubnets defends direct Scheduler users as well as config-file users:
// config validation rejects bad declarations, while the scheduler never starts
// duplicate or overlapping work if an unchecked caller supplies one.
func normalizeSubnets(subnets []SubnetConfig, logger *slog.Logger) []SubnetConfig {
	normalized := make([]SubnetConfig, 0, len(subnets))
	for _, sc := range subnets {
		prefix := sc.Prefix.Masked()
		if !prefix.IsValid() || !prefix.Addr().Is4() {
			logger.Warn("scheduler: ignoring unsupported subnet", "subnet", sc.Prefix)
			continue
		}
		sc.Prefix = prefix
		overlaps := false
		for _, existing := range normalized {
			if existing.Prefix.Contains(prefix.Addr()) || prefix.Contains(existing.Prefix.Addr()) {
				overlaps = true
				break
			}
		}
		if overlaps {
			logger.Warn("scheduler: ignoring duplicate or overlapping subnet", "subnet", prefix)
			continue
		}
		normalized = append(normalized, sc)
	}
	return normalized
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
func (s *Scheduler) ApplyConfig(params ApplyConfigParams) uint64 {
	return s.ApplyConfigWithHook(params, nil)
}

// ApplyConfigWithHook commits a fully-built generation and invokes activated
// while the scheduler lock is held, before new workers can observe it. The hook
// must be fast and non-blocking; it exists for peer runtime components (such as
// collector visibility) that must switch at the same activation boundary.
func (s *Scheduler) ApplyConfigWithHook(params ApplyConfigParams, activated func(generation uint64)) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subnets = normalizeSubnets(params.Subnets, s.logger)
	s.allowlists = cloneAllowlists(params.Allowlists)
	if params.Ports != nil {
		s.ports = clonePorts(params.Ports)
	}
	s.hostTTL = params.HostTTL
	s.generation++
	close(s.configWake)
	s.configWake = make(chan struct{})
	if activated != nil {
		activated(s.generation)
	}
	if s.running && !s.starting && s.runCtx != nil && s.runCtx.Err() == nil {
		for _, sc := range s.subnets {
			if !s.workers[sc.Prefix] {
				s.startSubnetWorkerLocked(s.runCtx, sc.Prefix, nil)
			}
		}
	}
	return s.generation
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

// cycleForPrefix snapshots all mutable policy used by a single scan cycle.
func (s *Scheduler) cycleForPrefix(prefix netip.Prefix) (scanCycle, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sc, found := s.subnetByPrefix(prefix)
	if !found {
		return scanCycle{}, false
	}
	return scanCycle{
		subnet:     sc,
		allowlist:  s.allowlists[sc.Prefix.String()],
		ports:      s.ports,
		configWake: s.configWake,
		generation: s.generation,
	}, true
}

// startSubnetWorkerLocked starts one prefix loop. Caller must hold mu.
func (s *Scheduler) startSubnetWorkerLocked(ctx context.Context, prefix netip.Prefix, firstDone chan<- struct{}) {
	if s.workers[prefix] {
		return
	}
	s.workers[prefix] = true
	s.wg.Add(1)
	go func() {
		defer func() {
			s.finishSubnetWorker(ctx, prefix)
			s.wg.Done()
		}()
		s.runSubnet(ctx, prefix, firstDone)
	}()
}

// finishSubnetWorker removes a completed loop. If a remove/re-add race made a
// configured prefix disappear just as its prior worker exited, restart it
// while the wait-group remains non-zero so a running scheduler cannot lose it.
func (s *Scheduler) finishSubnetWorker(ctx context.Context, prefix netip.Prefix) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.workers, prefix)
	if s.running && s.runCtx == ctx && ctx.Err() == nil {
		if _, found := s.subnetByPrefix(prefix); found {
			s.startSubnetWorkerLocked(ctx, prefix, nil)
		}
	}
}

// Run starts a per-subnet goroutine for each configured subnet and blocks until
// ctx is cancelled. On cancellation, all goroutines drain and Run returns nil.
func (s *Scheduler) Run(ctx context.Context) error {
	// Mark startup in progress before pruning. ApplyConfig may safely replace the
	// immutable next generation during this window, but it cannot start workers
	// before already-expired persisted state is removed.
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("scheduler is already running")
	}
	s.runCtx = ctx
	s.running = true
	s.starting = true
	s.mu.Unlock()

	s.PrepareStartup()

	// Start workers from the current configuration after startup pruning; a
	// concurrent reload during pruning is therefore included atomically here.
	s.mu.Lock()
	if ctx.Err() != nil {
		s.starting = false
		s.running = false
		s.runCtx = nil
		s.mu.Unlock()
		return nil
	}
	s.starting = false
	subnets := cloneSubnets(s.subnets)
	firstScans := make([]chan struct{}, len(subnets))
	for i, sc := range subnets {
		firstScans[i] = make(chan struct{})
		s.startSubnetWorkerLocked(ctx, sc.Prefix, firstScans[i])
	}
	// The prune loop is joined before Run returns.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.runPrune(ctx)
	}()
	s.mu.Unlock()

	if len(subnets) == 0 {
		// No subnets configured — signal ready immediately and wait for shutdown.
		s.readyOnce.Do(func() { close(s.readyCh) })
		<-ctx.Done()
		s.mu.Lock()
		s.running = false
		s.starting = false
		s.runCtx = nil
		s.mu.Unlock()
		s.wg.Wait()
		return nil
	}

	// Readiness waiter: closes readyCh once every startup subnet has a successful
	// ARP or ICMP discovery cycle. It is tracked so shutdown joins it too.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
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
	s.mu.Lock()
	s.running = false
	s.starting = false
	s.runCtx = nil
	s.mu.Unlock()
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
		wake := s.configWake
		s.mu.RUnlock()

		if ttl <= 0 {
			// Eviction disabled — wait for context cancellation or a config change.
			// Poll infrequently to pick up TTL changes applied via ApplyConfig.
			t := time.NewTimer(30 * time.Second)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-wake:
				t.Stop()
				continue
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
		case <-wake:
			t.Stop()
			continue
		case <-t.C:
		}

		// Re-read TTL after the timer fires; it may have changed via ApplyConfig.
		s.mu.RLock()
		ttl = s.hostTTL
		s.mu.RUnlock()
		if ttl <= 0 {
			continue
		}

		s.pruneOnce(ttl)
	}
}

// pruneOnce evicts expired hosts and emits their audit events. It is called
// before worker startup as well as by the periodic loop so a process restart
// cannot briefly serve inventory that was already expired on disk.
func (s *Scheduler) pruneOnce(ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	removed, err := s.store.PruneStaleHosts(ttl)
	if err != nil {
		s.logger.Warn("scheduler: PruneStale failed", "err", err)
		return
	}
	if len(removed) == 0 {
		return
	}

	s.mu.RLock()
	subnets := cloneSubnets(s.subnets)
	s.mu.RUnlock()

	for _, host := range removed {
		ipStr := host.IP.String()
		s.logger.Info("scheduler: host expired by TTL", "ip", ipStr)
		s.auditLog.HostExpired(ipStr, subnetForIP(ipStr, subnets), host.LastSeen)
	}
}

// runSubnet runs an immediate first scan, then waits the interval from the
// immutable cycle configuration before scanning again. Readiness is signalled
// only after a successful discovery path; cancellation and failed scans never
// masquerade as a usable inventory observation.
func (s *Scheduler) runSubnet(ctx context.Context, prefix netip.Prefix, firstScanDone chan<- struct{}) {
	readySignalled := false
	signalReady := func() {
		if firstScanDone != nil && !readySignalled {
			close(firstScanDone)
			readySignalled = true
		}
	}
	defer func() {
		if readySignalled || firstScanDone == nil || ctx.Err() != nil {
			return
		}
		// A startup subnet removed before it ever obtains a discovery path is
		// no longer part of the configured readiness set. A cancellation or a
		// remove/re-add race must not be mistaken for discovery success.
		if _, stillConfigured := s.cycleForPrefix(prefix); !stillConfigured {
			signalReady()
		}
	}()
	for {
		cycle, found := s.cycleForPrefix(prefix)
		if !found {
			return
		}

		if s.scanSubnet(ctx, cycle) {
			signalReady()
		}
		if ctx.Err() != nil {
			return
		}

		t := time.NewTimer(cycle.subnet.ScanInterval)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-cycle.configWake:
			t.Stop()
			continue
		case <-t.C:
		}
	}
}

// scanSubnet acquires the concurrency semaphore, runs all scanners against the subnet,
// and writes results and metadata to the state store. It returns true only if
// an ARP or ICMP scanner successfully completed, which is the readiness policy.
func (s *Scheduler) scanSubnet(ctx context.Context, cycle scanCycle) bool {
	// Acquire concurrency slot; respect cancellation while waiting.
	select {
	case s.semaphore <- struct{}{}:
		defer func() { <-s.semaphore }()
	case <-ctx.Done():
		return false
	}

	sc := cycle.subnet
	subnetStr := sc.Prefix.String()
	cycleStart := time.Now()
	var totalHosts int
	scannersRun := make([]string, 0, len(s.scanners))
	discoverySucceeded := false

	for _, scanner := range s.scanners {
		if ctx.Err() != nil {
			return false
		}

		start := time.Now()
		results, err := scanner.Scan(withPortSnapshot(ctx, cycle.ports), sc.Prefix)
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
		if isDiscoveryScanner(scanner.Name()) {
			discoverySucceeded = true
		}

		scannersRun = append(scannersRun, scanner.Name())
		totalHosts += len(results)

		for _, r := range results {
			if r.Metadata["duplicate_claimants_truncated"] == "true" {
				s.logger.Warn("ARP duplicate claimant evidence truncated", "ip", r.IP, "cap", maxDuplicateMACsPerIP)
			}
			if r.Metadata["dns_results_truncated"] == "true" {
				s.logger.Warn("DNS hostname evidence truncated", "ip", r.IP, "cap", maxDNSNamesPerHost)
			}
			source, validSource := observationSource(r.Source)
			if !validSource {
				s.logger.Warn("scanner returned unsupported observation source; dropping result", "scanner", scanner.Name(), "source", r.Source, "ip", r.IP)
				continue
			}
			record := state.HostRecord{
				Source:           source,
				ObservedAt:       r.Timestamp,
				ConfigGeneration: cycle.generation,
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

	// Use the allowlist that was snapshotted with the cycle. A reload must not
	// apply a newer authorization policy to old discovery observations.
	s.checkAuthorization(ctx, sc, cycle.allowlist, cycle.generation)
	return discoverySucceeded
}

func isDiscoveryScanner(name string) bool {
	return name == "arp" || name == "icmp"
}

func observationSource(source string) (state.ObservationSource, bool) {
	switch state.ObservationSource(source) {
	case state.SourceARP, state.SourceICMP, state.SourceDNS, state.SourcePort:
		return state.ObservationSource(source), true
	default:
		return "", false
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
// A nil allowlist is an explicit policy removal and clears prior authorization
// state rather than leaving stale approvals or denials attached to a host.
func (s *Scheduler) checkAuthorization(ctx context.Context, sc SubnetConfig, al *Allowlist, generation uint64) {
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
		authorized := false
		host.AuthorizationChecked = al != nil
		if al != nil {
			authorized = al.Contains(host.MAC)
		}
		host.Authorized = authorized
		host.Source = state.SourceAuthorization
		host.ObservedAt = time.Now()
		host.ConfigGeneration = generation
		if al != nil {
			host.AuthorizationScope = al.Scope()
		} else {
			host.AuthorizationScope = ""
		}
		if change, err := s.store.UpdateHost(ctx, host); err != nil {
			s.logger.Warn("checkAuthorization: UpdateHost failed", "ip", host.IP, "err", err)
			continue
		} else if !change.Applied {
			// The host expired, rebound, or was superseded after ListHosts.
			// Do not emit a policy event for an observation the store rejected.
			continue
		}
		if al != nil && !authorized {
			ip := net.ParseIP(host.IP.String())
			s.auditLog.UnauthorizedDevice(ip, subnetStr, host.MAC, host.Vendor)
		}
	}
}
