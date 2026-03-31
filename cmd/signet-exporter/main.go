package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/maravexa/signet-exporter/internal/config"
	"github.com/maravexa/signet-exporter/internal/version"
)

func main() {
	var (
		configPath   = flag.String("config", "/etc/signet/signet.yaml", "path to configuration file")
		validateOnly = flag.Bool("validate", false, "validate configuration and exit")
		showVersion  = flag.Bool("version", false, "print version information and exit")
	)
	flag.Parse()

	// Structured JSON logging to stderr.
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(log)

	if *showVersion {
		fmt.Printf("signet-exporter version=%s commit=%s date=%s\n",
			version.Version, version.Commit, version.Date)
		os.Exit(0)
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Error("failed to load configuration", "path", *configPath, "err", err)
		os.Exit(1)
	}

	if err := config.Validate(cfg); err != nil {
		log.Error("configuration validation failed", "err", err)
		os.Exit(1)
	}

	if *validateOnly {
		fmt.Println("configuration OK")
		os.Exit(0)
	}

	// Refuse to run as root to enforce least-privilege operation.
	// (--version and --validate are exempt as they are diagnostic-only.)
	if os.Getuid() == 0 {
		log.Error("refusing to run as root; create a dedicated service user (see deploy/signet.sysusers)")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown on SIGINT or SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Info("received shutdown signal", "signal", sig)
		cancel()
	}()

	log.Info("starting signet-exporter",
		"version", version.Version,
		"commit", version.Commit,
		"listen", cfg.ListenAddress,
	)

	if err := run(ctx, cfg, log); err != nil {
		log.Error("fatal error", "err", err)
		os.Exit(1)
	}
}

// run is the application entry point after flags and config are resolved.
// The startup sequence is outlined here; each step will be fleshed out in
// subsequent development phases.
func run(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	// Step 1: Initialize state store (memory or bbolt).
	// store, err := initStateStore(cfg)

	// Step 2: Initialize OUI database for vendor enrichment.
	// ouiDB, err := oui.LoadFile(cfg.OUIDatabase)

	// Step 3: Build scanner implementations (ARP, ICMP, DNS, port).
	// scanners := buildScanners(cfg)

	// Step 4: Start the scheduler (per-subnet ticker goroutines).
	// scheduler := scanner.NewScheduler(cfg.Subnets, scanners, store, cfg.Scanner.MaxParallelScans, log)
	// go scheduler.Run(ctx)

	// Step 5: Initialize the Prometheus collector backed by the state store.
	// collector := collector.NewSignetCollector(store, cfg, log)

	// Step 6: Start the mTLS metrics server.
	// srv, err := server.NewServer(cfg, collector)
	// srv.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)

	log.Info("signet-exporter scaffold ready — no scanners active yet")

	// Block until context is cancelled.
	<-ctx.Done()
	log.Info("shutting down")
	return nil
}
