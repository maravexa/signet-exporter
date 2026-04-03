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

	"github.com/maravexa/signet-exporter/internal/audit"
	"github.com/maravexa/signet-exporter/internal/collector"
	"github.com/maravexa/signet-exporter/internal/config"
	"github.com/maravexa/signet-exporter/internal/fips"
	"github.com/maravexa/signet-exporter/internal/oui"
	"github.com/maravexa/signet-exporter/internal/scanner"
	"github.com/maravexa/signet-exporter/internal/server"
	"github.com/maravexa/signet-exporter/internal/state"
	"github.com/maravexa/signet-exporter/internal/tlsutil"
	"github.com/maravexa/signet-exporter/internal/version"
)

func main() {
	var (
		configPath    = flag.String("config", "/etc/signet/signet.yaml", "path to configuration file")
		validateOnly  = flag.Bool("validate", false, "validate configuration and exit")
		showVersion   = flag.Bool("version", false, "print version information and exit")
		generateCerts = flag.String("generate-certs", "", "generate a dev CA + server + client cert chain in the given directory and exit")
		compactDB     = flag.String("compact-db", "", "compact the bbolt state database at the given path and exit (exporter must not be running)")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("signet-exporter %s (commit: %s, built: %s, fips=%v)\n",
			version.Version, version.Commit, version.Date, fips.Enabled())
		os.Exit(0)
	}

	if *compactDB != "" {
		if err := CompactDB(*compactDB); err != nil {
			fmt.Fprintf(os.Stderr, "error: compact-db: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *generateCerts != "" {
		if err := tlsutil.GenerateCerts(*generateCerts); err != nil {
			fmt.Fprintf(os.Stderr, "error: generate-certs: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Generated TLS certificates in %s/\n\n", *generateCerts)
		fmt.Printf("  CA cert:        %s/ca.pem\n", *generateCerts)
		fmt.Printf("  CA key:         %s/ca-key.pem\n", *generateCerts)
		fmt.Printf("  Server cert:    %s/server.pem\n", *generateCerts)
		fmt.Printf("  Server key:     %s/server-key.pem\n", *generateCerts)
		fmt.Printf("  Client cert:    %s/client.pem\n", *generateCerts)
		fmt.Printf("  Client key:     %s/client-key.pem\n\n", *generateCerts)
		fmt.Printf("Add the following to your signet.yaml to enable mTLS:\n\n")
		fmt.Printf("  tls:\n")
		fmt.Printf("    cert_file: \"%s/server.pem\"\n", *generateCerts)
		fmt.Printf("    key_file: \"%s/server-key.pem\"\n", *generateCerts)
		fmt.Printf("    client_ca_file: \"%s/ca.pem\"\n", *generateCerts)
		fmt.Printf("    client_auth_policy: \"require_and_verify\"\n\n")
		fmt.Printf("Configure Prometheus to present the client cert when scraping:\n\n")
		fmt.Printf("  scrape_configs:\n")
		fmt.Printf("    - job_name: \"signet\"\n")
		fmt.Printf("      scheme: https\n")
		fmt.Printf("      tls_config:\n")
		fmt.Printf("        ca_file: \"%s/ca.pem\"\n", *generateCerts)
		fmt.Printf("        cert_file: \"%s/client.pem\"\n", *generateCerts)
		fmt.Printf("        key_file: \"%s/client-key.pem\"\n", *generateCerts)
		fmt.Printf("      static_configs:\n")
		fmt.Printf("        - targets: [\"127.0.0.1:9420\"]\n")
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
		boltStore, boltErr := state.NewBoltStore(cfg.State.BoltPath)
		if boltErr != nil {
			logger.Error("failed to open bolt state database — is another instance running?",
				"path", cfg.State.BoltPath, "err", boltErr)
			os.Exit(1)
		}
		store = boltStore
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

	// Load per-subnet MAC allowlists. Failure is fatal — a misconfigured allowlist
	// could silently disable rogue device detection.
	allowlists := make(map[string]*scanner.Allowlist)
	for _, s := range cfg.Subnets {
		if s.MACAllowlistFile == "" {
			continue
		}
		prefix, _ := netip.ParsePrefix(s.CIDR) // already validated above
		al, alErr := scanner.LoadAllowlist(s.MACAllowlistFile)
		if alErr != nil {
			logger.Error("failed to load MAC allowlist", "subnet", s.CIDR, "path", s.MACAllowlistFile, "err", alErr)
			os.Exit(1)
		}
		if al != nil {
			logger.Info("MAC allowlist loaded", "subnet", s.CIDR, "path", s.MACAllowlistFile, "entries", al.Len())
			allowlists[prefix.String()] = al
		}
	}

	// Build scanner list. ARP and ICMP discover hosts; DNS enriches hostnames;
	// port scanner probes open TCP ports — all run sequentially per scan cycle.
	portScanner := scanner.NewPortScanner(store, subnetPorts, nil, cfg.Scanner.PortTimeout, cfg.Scanner.PortMaxWorkers, logger)
	scanners := []scanner.Scanner{
		scanner.NewARPScanner(cfg.Scanner.ARPTimeout, cfg.Scanner.ARPRateLimit, logger),
		scanner.NewICMPScanner(cfg.Scanner.ICMPTimeout, cfg.Scanner.ICMPRateLimit, logger),
		scanner.NewDNSScanner(store, cfg.DNS.Servers, cfg.DNS.Timeout, logger),
		portScanner,
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

	// Create structured audit logger. Failure is fatal — don't run without audit if configured.
	auditLogger, err := audit.NewLogger(audit.Config{
		Enabled: cfg.Audit.Enabled,
		Format:  cfg.Audit.Format,
		Output:  cfg.Audit.Output,
		Path:    cfg.Audit.Path,
		Version: version.Version,
	})
	if err != nil {
		logger.Error("failed to create audit logger", "err", err)
		os.Exit(1)
	}
	defer func() { _ = auditLogger.Close() }()

	signetCollector := collector.NewSignetCollector(store, prefixes, logger)
	sched := scanner.NewScheduler(scanners, store, subnetConfigs, cfg.Scanner.MaxParallelScans, logger, ouiDB, auditLogger, allowlists)

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

	// Track the current reloadable config for diffing on subsequent reloads.
	currentRC := config.ExtractReloadable(cfg)

	// SIGHUP handler — reloads both the config file and TLS certificates without restarting.
	// Uses a buffered channel of size 1 so a rapid signal burst doesn't queue.
	{
		sighup := make(chan os.Signal, 1)
		signal.Notify(sighup, syscall.SIGHUP)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-sighup:
					// --- Config hot-reload ---
					newCfg, cfgErr := config.LoadConfig(*configPath)
					if cfgErr != nil {
						logger.Error("SIGHUP: failed to read config file — keeping old config", "err", cfgErr)
					} else {
						newRC := config.ExtractReloadable(newCfg)
						if valErr := config.ValidateReloadable(newRC); valErr != nil {
							logger.Error("SIGHUP: new config failed validation — keeping old config", "err", valErr)
						} else {
							changes := config.Diff(currentRC, newRC)
							if len(changes) > 0 {
								// Load new allowlists from updated file paths.
								newAllowlists := make(map[string]*scanner.Allowlist)
								loadErr := false
								for _, s := range newRC.Subnets {
									if s.MACAllowlistFile == "" {
										continue
									}
									prefix, _ := netip.ParsePrefix(s.CIDR)
									al, alErr := scanner.LoadAllowlist(s.MACAllowlistFile)
									if alErr != nil {
										logger.Error("SIGHUP: failed to load allowlist — keeping old config",
											"subnet", s.CIDR, "path", s.MACAllowlistFile, "err", alErr)
										loadErr = true
										break
									}
									if al != nil {
										newAllowlists[prefix.String()] = al
									}
								}
								if !loadErr {
									// Build updated subnet list for the scheduler.
									newSubnets := make([]scanner.SubnetConfig, 0, len(newRC.Subnets))
									for _, s := range newRC.Subnets {
										prefix, _ := netip.ParsePrefix(s.CIDR)
										interval := s.ScanInterval
										if interval == 0 {
											interval = 60 * time.Second
										}
										newSubnets = append(newSubnets, scanner.SubnetConfig{
											Prefix:       prefix,
											ScanInterval: interval,
										})
									}
									sched.ApplyConfig(scanner.ApplyConfigParams{
										Subnets:    newSubnets,
										Allowlists: newAllowlists,
									})

									// Update port scanner with new per-subnet ports.
									newSubnetPorts := make(map[string][]uint16)
									for _, s := range newRC.Subnets {
										if len(s.Ports) == 0 {
											continue
										}
										prefix, _ := netip.ParsePrefix(s.CIDR)
										ports := make([]uint16, len(s.Ports))
										for i, p := range s.Ports {
											ports[i] = uint16(p) //nolint:gosec // port validated 1–65535
										}
										newSubnetPorts[prefix.String()] = ports
									}
									portScanner.UpdatePorts(newSubnetPorts)

									currentRC = newRC
									auditLogger.ConfigReloaded(changes)
									logger.Info("SIGHUP: config reloaded", "changes", len(changes))
									for _, c := range changes {
										logger.Info("SIGHUP: change", "detail", c)
									}
								}
							} else {
								logger.Info("SIGHUP: config unchanged")
							}
						}
					}

					// --- TLS cert rotation (existing Step 12 behaviour) ---
					if srv.Reloader() != nil {
						reloadErr := srv.Reloader().Reload()
						auditLogger.CertReloaded(cfg.TLS.CertFile, reloadErr)
						if reloadErr != nil {
							logger.Error("TLS certificate reload failed", "err", reloadErr)
						} else {
							logger.Info("TLS certificate reloaded successfully")
						}
					}
				}
			}
		}()
	}

	// Start the scheduler in the background.
	go func() {
		if err := sched.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("scheduler exited unexpectedly", "err", err)
		}
	}()

	if fips.Enabled() {
		logger.Info("FIPS mode enabled")
	} else {
		logger.Info("FIPS mode not enabled (standard crypto)")
	}

	logger.Info("starting signet-exporter",
		"version", version.Version,
		"commit", version.Commit,
		"address", cfg.ListenAddress,
		"tls", srv.TLSEnabled(),
		"fips", fips.Enabled(),
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
