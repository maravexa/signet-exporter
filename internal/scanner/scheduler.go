package scanner

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/maravexa/signet-exporter/internal/state"
)

// SubnetConfig describes a single subnet to scan and its timing parameters.
type SubnetConfig struct {
	Prefix       netip.Prefix
	ScanInterval time.Duration
}

// Scheduler drives periodic subnet scans with a configurable concurrency limit.
type Scheduler struct {
	scanners  []Scanner
	store     state.Store
	subnets   []SubnetConfig
	semaphore chan struct{} // limits the number of concurrent subnet scans in flight
	logger    *slog.Logger
	readyCh   chan struct{} // closed after every configured subnet completes its first scan
	readyOnce sync.Once
}

// NewScheduler creates a Scheduler.
// maxParallel controls how many subnet scans may run concurrently; if <= 0, defaults to 1.
// If scanners is empty, no scanning occurs but the scheduler is otherwise valid.
func NewScheduler(
	scanners []Scanner,
	store state.Store,
	subnets []SubnetConfig,
	maxParallel int,
	logger *slog.Logger,
) *Scheduler {
	if maxParallel <= 0 {
		maxParallel = 1
	}
	if logger == nil {
		logger = slog.Default()
	}
	if len(scanners) == 0 {
		logger.Warn("scheduler: no scanners registered — no hosts will be discovered")
	}
	return &Scheduler{
		scanners:  scanners,
		store:     store,
		subnets:   subnets,
		semaphore: make(chan struct{}, maxParallel),
		logger:    logger,
		readyCh:   make(chan struct{}),
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
				"subnet", sc.Prefix.String(),
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

		for _, r := range results {
			record := state.HostRecord{
				IP:       r.IP,
				MAC:      r.MAC,
				Alive:    r.Alive,
				LastSeen: r.Timestamp,
			}
			if err := s.store.UpdateHost(ctx, record); err != nil {
				s.logger.Warn("failed to update host",
					"ip", r.IP.String(),
					"err", err,
				)
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
			"subnet", sc.Prefix.String(),
			"hosts_found", len(results),
			"duration", duration,
		)
	}
}
