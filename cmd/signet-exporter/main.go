// Package main is the entrypoint for the signet-exporter binary.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/maravexa/signet-exporter/internal/collector"
	"github.com/maravexa/signet-exporter/internal/config"
	"github.com/maravexa/signet-exporter/internal/oui"
	"github.com/maravexa/signet-exporter/internal/scanner"
	"github.com/maravexa/signet-exporter/internal/server"
	"github.com/maravexa/signet-exporter/internal/state"
	"github.com/maravexa/signet-exporter/internal/version"
)

func main() {
	var (
		configPath   = flag.String("config", "/etc/signet/signet.yaml", "path to configuration file")
		validateOnly = flag.Bool("validate", false, "validate configuration and exit")
		showVersion  = flag.Bool("version", false, "print version information and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("signet-exporter %s (commit: %s, built: %s)\n",
			version.Version, version.Commit, version.Date)
		os.Exit(0)
	}

	// Refuse to run as root before loading config: a world-unreadable key file could
	// mask this check if we attempt TLS setup first.
	if os.Getuid() == 0 {
		fmt.Fprintln(os.Stderr, "error: signet-exporter must not run as root — use CAP_NET_RAW capability instead")
		os.Exit(1)
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	if err := config.Validate(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "configuration invalid: %v\n", err)
		os.Exit(1)
	}

	if *validateOnly {
		fmt.Println("configuration is valid")
		os.Exit(0)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	// Initialize state store.
	var store state.Store
	switch cfg.State.Backend {
	case "memory", "":
		store = state.NewMemoryStore()
	case "bolt":
		// TODO: implement bbolt backend in a future phase.
		logger.Error("bolt backend not yet implemented, falling back to memory store")
		store = state.NewMemoryStore()
	default:
		logger.Error("unknown state backend", "backend", cfg.State.Backend)
		os.Exit(1)
	}
	defer func() { _ = store.Close() }()

	// Parse subnet CIDRs into typed prefixes for the scanner and collector.
	subnetConfigs := make([]scanner.SubnetConfig, 0, len(cfg.Subnets))
	prefixes := make([]netip.Prefix, 0, len(cfg.Subnets))
	for _, s := range cfg.Subnets {
		prefix, err := netip.ParsePrefix(s.CIDR)
		if err != nil {
			logger.Error("invalid subnet CIDR", "cidr", s.CIDR, "err", err)
			os.Exit(1)
		}
		interval := s.ScanInterval
		if interval == 0 {
			interval = 60 * time.Second
		}
		subnetConfigs = append(subnetConfigs, scanner.SubnetConfig{
			Prefix:       prefix,
			ScanInterval: interval,
		})
		prefixes = append(prefixes, prefix)
	}

	// Build per-subnet port map from config.
	subnetPorts := make(map[string][]uint16)
	for _, s := range cfg.Subnets {
		if len(s.Ports) > 0 {
			prefix, _ := netip.ParsePrefix(s.CIDR) // already validated above
			subnetPorts[prefix.String()] = s.Ports
		}
	}

	// Build scanner list. ARP and ICMP discover hosts; DNS enriches hostnames;
	// port scanner probes open TCP ports — all run sequentially per scan cycle.
	scanners := []scanner.Scanner{
		scanner.NewARPScanner(cfg.Scanner.ARPTimeout, cfg.Scanner.ARPRateLimit, logger),
		scanner.NewICMPScanner(cfg.Scanner.ICMPTimeout, cfg.Scanner.ICMPRateLimit, logger),
		scanner.NewDNSScanner(store, cfg.DNS.Servers, cfg.DNS.Timeout, logger),
		scanner.NewPortScanner(store, subnetPorts, nil, cfg.Scanner.PortTimeout, cfg.Scanner.PortMaxWorkers, logger),
	}

	// Load OUI vendor database if configured; failure is non-fatal (degraded mode).
	var ouiDB *oui.Database
	if cfg.OUIDatabase != "" {
		var ouiErr error
		ouiDB, ouiErr = oui.LoadDatabase(cfg.OUIDatabase)
		if ouiErr != nil {
			logger.Warn("OUI database unavailable — vendor labels will be empty",
				"path", cfg.OUIDatabase,
				"err", ouiErr,
			)
			ouiDB = nil
		} else {
			logger.Info("OUI database loaded", "path", cfg.OUIDatabase, "entries", ouiDB.Len())
		}
	}

	signetCollector := collector.NewSignetCollector(store, prefixes, logger)
	sched := scanner.NewScheduler(scanners, store, subnetConfigs, cfg.Scanner.MaxParallelScans, logger, ouiDB)

	if cfg.TLS.CertFile == "" {
		logger.Warn("TLS not configured — serving metrics over plaintext HTTP; not recommended for production")
	}

	srv, err := server.NewServer(cfg, signetCollector, sched.Ready())
	if err != nil {
		logger.Error("failed to create server", "err", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Start the scheduler in the background.
	go func() {
		if err := sched.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("scheduler exited unexpectedly", "err", err)
		}
	}()

	logger.Info("starting signet-exporter",
		"version", version.Version,
		"commit", version.Commit,
		"address", cfg.ListenAddress,
		"tls", srv.TLSEnabled(),
		"subnets", len(cfg.Subnets),
		"scanners", len(scanners),
	)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Start()
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-serverErr:
		if err != nil && err != http.ErrServerClosed {
			logger.Error("server error", "err", err)
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("server shutdown error", "err", err)
	}

	logger.Info("signet-exporter stopped")
}
