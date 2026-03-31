package scanner

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/maravexa/signet-exporter/internal/config"
	"github.com/maravexa/signet-exporter/internal/state"
)

// Scheduler drives periodic subnet scans with a configurable concurrency limit.
type Scheduler struct {
	subnets  []config.SubnetConfig
	scanners []Scanner
	store    state.StateStore
	// semaphore limits the number of concurrent subnet scans in flight.
	semaphore chan struct{}
	log       *slog.Logger
}

// NewScheduler creates a Scheduler.
// maxParallel controls how many subnet scans may run concurrently.
func NewScheduler(
	subnets []config.SubnetConfig,
	scanners []Scanner,
	store state.StateStore,
	maxParallel int,
	log *slog.Logger,
) *Scheduler {
	return &Scheduler{
		subnets:   subnets,
		scanners:  scanners,
		store:     store,
		semaphore: make(chan struct{}, maxParallel),
		log:       log,
	}
}

// Run starts a per-subnet ticker goroutine for each configured subnet.
// It blocks until ctx is cancelled, then waits for all in-flight scans to finish.
func (s *Scheduler) Run(ctx context.Context) error {
	var wg sync.WaitGroup

	for _, sub := range s.subnets {
		sub := sub // capture loop variable
		prefix, err := netip.ParsePrefix(sub.CIDR)
		if err != nil {
			s.log.Error("invalid subnet CIDR, skipping", "cidr", sub.CIDR, "err", err)
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			s.runSubnetLoop(ctx, prefix, sub.ScanInterval)
		}()
	}

	wg.Wait()
	return nil
}

// runSubnetLoop fires a scan for the given subnet on every tick until ctx is cancelled.
func (s *Scheduler) runSubnetLoop(ctx context.Context, prefix netip.Prefix, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.dispatch(ctx, prefix)
		}
	}
}

// dispatch acquires the semaphore, runs all scanners against prefix, and releases.
func (s *Scheduler) dispatch(ctx context.Context, prefix netip.Prefix) {
	// Acquire concurrency slot (blocks if max parallel scans are already running).
	select {
	case s.semaphore <- struct{}{}:
	case <-ctx.Done():
		return
	}

	go func() {
		defer func() { <-s.semaphore }()
		s.runScan(ctx, prefix)
	}()
}

// runScan executes every registered scanner against prefix and writes results to the store.
func (s *Scheduler) runScan(ctx context.Context, prefix netip.Prefix) {
	for _, sc := range s.scanners {
		results, err := sc.Scan(ctx, prefix)
		if err != nil {
			s.log.Error("scan error", "scanner", sc.Name(), "subnet", prefix, "err", err)
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
				s.log.Error("state update error", "ip", r.IP, "err", err)
			}
		}
	}
}
