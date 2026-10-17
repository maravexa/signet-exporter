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
	"reflect"
	"sync"
	"syscall"
	"time"

	"github.com/maravexa/signet-exporter/internal/audit"
	"github.com/maravexa/signet-exporter/internal/collector"
	"github.com/maravexa/signet-exporter/internal/config"
	"github.com/maravexa/signet-exporter/internal/fips"
	"github.com/maravexa/signet-exporter/internal/oui"
	"github.com/maravexa/signet-exporter/internal/remotewrite"
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
		// auth=none over https returns a *ConfigWarning. Surface it but do not
		// refuse to start — operators may legitimately terminate TLS upstream.
		if remotewrite.IsWarning(err) {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "configuration invalid: %v\n", err)
			os.Exit(1)
		}
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
	sched := scanner.NewScheduler(scanners, store, subnetConfigs, cfg.Scanner.MaxParallelScans, logger, ouiDB, auditLogger, allowlists, effectiveHostTTL(config.ExtractReloadable(cfg)))
	// Seed the scheduler's cycle-owned port snapshot and prune persisted expiry
	// before any collector scrape or remote-write gather can observe inventory.
	sched.ApplyConfigWithHook(scanner.ApplyConfigParams{Subnets: subnetConfigs, Allowlists: allowlists, Ports: subnetPorts, HostTTL: effectiveHostTTL(config.ExtractReloadable(cfg))}, func(generation uint64) {
		signetCollector.ApplyConfig(collector.Config{Generation: generation, Subnets: collectorSubnets(subnetConfigs, allowlists)})
	})
	sched.PrepareStartup()

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
	var backgroundWG sync.WaitGroup

	// Optional remote write push pipeline. Coexists with the /metrics scrape
	// endpoint — operators in mixed environments may push to a long-term store
	// while still allowing on-demand scraping for debugging.
	var rwSender *remotewrite.Sender
	if cfg.RemoteWrite.Enabled {
		rwMetrics := remotewrite.NewMetrics()
		if rerr := rwMetrics.Register(srv.Registry()); rerr != nil {
			logger.Error("failed to register remote write metrics", "err", rerr)
			os.Exit(1)
		}
		rwSender, err = remotewrite.NewSender(cfg.RemoteWrite, srv.Registry(), rwMetrics, logger, auditLogger, version.Version)
		if err != nil {
			logger.Error("failed to initialize remote write sender", "err", err)
			os.Exit(1)
		}
		backgroundWG.Add(1)
		go func() {
			defer backgroundWG.Done()
			if rerr := rwSender.Run(ctx); rerr != nil && ctx.Err() == nil {
				logger.Error("remote write sender exited unexpectedly", "err", rerr)
			}
		}()
		logger.Info("remote write enabled", "endpoint", cfg.RemoteWrite.Endpoint, "auth_type", cfg.RemoteWrite.Auth.Type)
	}

	// Track the current reloadable config for diffing on subsequent reloads.
	currentRC := config.ExtractReloadable(cfg)

	// SIGHUP handler — reloads both the config file and TLS certificates without restarting.
	// Uses a buffered channel of size 1 so a rapid signal burst doesn't queue.
	{
		sighup := make(chan os.Signal, 1)
		signal.Notify(sighup, syscall.SIGHUP)
		backgroundWG.Add(1)
		go func() {
			defer signal.Stop(sighup)
			defer backgroundWG.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-sighup:
					// --- Config hot-reload ---
					newCfg, cfgErr := config.LoadConfig(*configPath)
					if cfgErr != nil {
						logger.Error("SIGHUP: failed to read config file — keeping old config", "err", cfgErr)
					} else if valErr := config.Validate(newCfg); valErr != nil && !remotewrite.IsWarning(valErr) {
						// Validate the complete candidate before considering its mutable
						// subset. Otherwise an invalid immutable setting could be silently
						// ignored while unrelated mutable settings were activated.
						logger.Error("SIGHUP: new config failed full validation — keeping old config", "err", valErr)
					} else if immutableChanges := immutableConfigChanges(cfg, newCfg); len(immutableChanges) > 0 {
						// TLS key material may rotate at the existing paths below, but
						// changing any TLS setting itself (or another immutable field)
						// needs a restart. Reject the entire application generation.
						logger.Warn("SIGHUP: immutable config changed; restart required — keeping old generation", "fields", immutableChanges)
					} else {
						newRC := config.ExtractReloadable(newCfg)
						if valErr := config.ValidateReloadable(newRC); valErr != nil {
							logger.Error("SIGHUP: new config failed validation — keeping old config", "err", valErr)
						} else {
							changes := config.Diff(currentRC, newRC)
							// Always rebuild and activate a candidate: an allowlist may
							// change contents without its configured path changing.
							{
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
									newSubnetPorts := make(map[string][]uint16)
									for _, s := range newRC.Subnets {
										if len(s.Ports) == 0 {
											continue
										}
										prefix, _ := netip.ParsePrefix(s.CIDR)
										ports := make([]uint16, len(s.Ports))
										for i, p := range s.Ports {
											ports[i] = uint16(p) //nolint:gosec // validated by reload candidate
										}
										newSubnetPorts[prefix.String()] = ports
									}
									// Remote-write must accept the candidate before any other
									// component activates it; otherwise a bad remote candidate
									// could leave a partially applied reload generation.
									remoteAccepted := true
									if rwSender == nil && newCfg.RemoteWrite.Enabled != cfg.RemoteWrite.Enabled {
										logger.Warn("SIGHUP: remote_write enable toggle requires restart; keeping generation")
										remoteAccepted = false
									}
									if rwSender != nil {
										if vErr := newCfg.RemoteWrite.Validate(); vErr != nil && !remotewrite.IsWarning(vErr) {
											logger.Error("SIGHUP: remote_write config invalid — keeping generation", "err", vErr)
											remoteAccepted = false
										}
										if remoteAccepted {
											if rerr := rwSender.Reload(newCfg.RemoteWrite); rerr != nil {
												logger.Error("SIGHUP: remote_write reload failed — keeping generation", "err", rerr)
												remoteAccepted = false
											}
										}
										if remoteAccepted {
											cfg.RemoteWrite = newCfg.RemoteWrite
										}
									}
									if remoteAccepted {
										sched.ApplyConfigWithHook(scanner.ApplyConfigParams{
											Subnets:    newSubnets,
											Allowlists: newAllowlists,
											Ports:      newSubnetPorts,
											HostTTL:    effectiveHostTTL(newRC),
										}, func(generation uint64) {
											signetCollector.ApplyConfig(collector.Config{Generation: generation, Subnets: collectorSubnets(newSubnets, newAllowlists)})
										})

										currentRC = newRC
										auditLogger.ConfigReloaded(changes)
										logger.Info("SIGHUP: config reloaded", "changes", len(changes))
										for _, c := range changes {
											logger.Info("SIGHUP: change", "detail", c)
										}
									}
								}
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
	backgroundWG.Add(1)
	go func() {
		defer backgroundWG.Done()
		if err := sched.Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("scheduler exited unexpectedly", "err", err)
		}
	}()

	if fips.Enabled() {
		logger.Info("BoringCrypto backend enabled (not a certification indicator)")
	} else {
		logger.Info("BoringCrypto backend not enabled")
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
	// Stop all producer loops before closing the store or audit logger. This is
	// also required when the HTTP server, rather than a signal, ended the select.
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("server shutdown error", "err", err)
	}
	backgroundWG.Wait()

	logger.Info("signet-exporter stopped")
}

func collectorSubnets(subnets []scanner.SubnetConfig, allowlists map[string]*scanner.Allowlist) []collector.SubnetConfig {
	out := make([]collector.SubnetConfig, len(subnets))
	for i, subnet := range subnets {
		scope := ""
		if allowlist := allowlists[subnet.Prefix.String()]; allowlist != nil {
			scope = allowlist.Scope()
		}
		out[i] = collector.SubnetConfig{Prefix: subnet.Prefix, ScanInterval: subnet.ScanInterval, AuthorizationScope: scope}
	}
	return out
}

// immutableConfigChanges reports configuration fields that cannot be safely
// applied to a running process. Certificate contents are deliberately not
// compared here: the reloader below handles same-path TLS rotation on every
// SIGHUP.
func immutableConfigChanges(old, candidate *config.Config) []string {
	changes := make([]string, 0, 7)
	if old.ListenAddress != candidate.ListenAddress {
		changes = append(changes, "listen_address")
	}
	if old.TLS != candidate.TLS {
		changes = append(changes, "tls")
	}
	if !reflect.DeepEqual(old.DNS, candidate.DNS) {
		changes = append(changes, "dns")
	}
	if old.Scanner != candidate.Scanner {
		changes = append(changes, "scanner")
	}
	if old.State != candidate.State {
		changes = append(changes, "state")
	}
	if old.OUIDatabase != candidate.OUIDatabase {
		changes = append(changes, "oui_database")
	}
	if old.Audit != candidate.Audit {
		changes = append(changes, "audit")
	}
	return changes
}

// maxConfiguredPortCount remains for compatibility with callers that estimate
// capacity from configuration. Runtime metrics now derive active series from
// the exact collector output instead.
func maxConfiguredPortCount(subnets []config.SubnetConfig) int {
	maxCount := 0
	for _, subnet := range subnets {
		if len(subnet.Ports) > maxCount {
			maxCount = len(subnet.Ports)
		}
	}
	return maxCount
}

// effectiveHostTTL returns an explicitly configured HostTTL, including an
// explicit zero that disables eviction. When host_ttl is omitted, the
// conservative default is 3× the longest configured scan interval: a host on
// a slower subnet must not expire while that subnet is scanning normally.
// Returns 0 only when no subnets are configured.
func effectiveHostTTL(rc config.ReloadableConfig) time.Duration {
	if rc.HostTTLSet {
		return rc.HostTTL
	}
	// Compute 3× the maximum scan interval as the conservative global default.
	var maxInterval time.Duration
	for _, s := range rc.Subnets {
		interval := s.ScanInterval
		if interval == 0 {
			interval = 60 * time.Second
		}
		if interval > maxInterval {
			maxInterval = interval
		}
	}
	if maxInterval == 0 {
		return 0
	}
	return 3 * maxInterval
}
