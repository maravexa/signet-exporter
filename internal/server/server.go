// Package server provides the HTTP(S) server for the /metrics, /health, and /ready endpoints.
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/maravexa/signet-exporter/internal/config"
	"github.com/maravexa/signet-exporter/internal/tlsutil"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server wraps an http.Server and knows whether TLS is configured.
type Server struct {
	httpServer *http.Server
	tlsEnabled bool
	reloader   *tlsutil.KeypairReloader // nil when TLS not configured
	registry   *prometheus.Registry     // exposed so additional collectors (remote write) can self-register
}

// NewHandler creates the HTTP handler with /metrics, /health, and /ready endpoints.
// It can be used directly in tests via httptest.NewServer without TLS setup.
func NewHandler(col prometheus.Collector, ready <-chan struct{}) http.Handler {
	registry := prometheus.NewRegistry()
	registry.MustRegister(col)
	return newHandlerForRegistry(registry, ready)
}

// newHandlerForRegistry builds the mux against an existing registry so that
// the caller (NewServer) can register additional collectors before requests
// are served.
func newHandlerForRegistry(registry *prometheus.Registry, ready <-chan struct{}) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	}))

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		select {
		case <-ready:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ready"}`))
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"not ready","reason":"initial scan not complete"}`))
		}
	})

	return mux
}

// NewServer constructs a Server wired with the /metrics, /health, and /ready endpoints.
// TLS (and optionally mTLS) is configured according to cfg.TLS.
// If no TLS certificate is configured, the server operates in plaintext HTTP mode.
func NewServer(cfg *config.Config, col prometheus.Collector, ready <-chan struct{}) (*Server, error) {
	registry := prometheus.NewRegistry()
	registry.MustRegister(col)
	handler := newHandlerForRegistry(registry, ready)

	httpSrv := &http.Server{
		Addr:    cfg.ListenAddress,
		Handler: handler,
	}

	var reloader *tlsutil.KeypairReloader
	tlsEnabled := false
	if cfg.TLS.CertFile != "" {
		tlsCfg, kr, err := buildTLSConfig(&cfg.TLS)
		if err != nil {
			return nil, fmt.Errorf("server: build TLS config: %w", err)
		}
		httpSrv.TLSConfig = tlsCfg
		reloader = kr
		tlsEnabled = true
	}

	return &Server{httpServer: httpSrv, tlsEnabled: tlsEnabled, reloader: reloader, registry: registry}, nil
}

// Registry returns the prometheus.Registry backing the /metrics endpoint so
// additional collectors (e.g. remote write self-metrics) can register on the
// same target without standing up a parallel registry.
func (s *Server) Registry() *prometheus.Registry { return s.registry }

// Start begins serving. Uses HTTPS when TLS is configured, otherwise plain HTTP.
// Returns http.ErrServerClosed after a successful Shutdown call.
func (s *Server) Start() error {
	if s.tlsEnabled {
		// Certificate is served via GetCertificate; empty strings are intentional.
		return s.httpServer.ListenAndServeTLS("", "")
	}
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the server, waiting for active connections to drain.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// TLSEnabled reports whether the server is configured for HTTPS.
func (s *Server) TLSEnabled() bool { return s.tlsEnabled }

// Reloader returns the KeypairReloader used to serve TLS certificates, or nil
// if TLS is not configured. Call Reloader().Reload() on SIGHUP to rotate certs
// without restarting.
func (s *Server) Reloader() *tlsutil.KeypairReloader { return s.reloader }

// buildTLSConfig constructs a *tls.Config and its associated KeypairReloader
// from the TLS section of the signet configuration. The reloader is stored by
// the Server so it can be triggered on SIGHUP for zero-downtime cert rotation.
func buildTLSConfig(cfg *config.TLSConfig) (*tls.Config, *tlsutil.KeypairReloader, error) {
	reloader, err := tlsutil.NewKeypairReloader(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("load keypair: %w", err)
	}

	// Default to TLS 1.3; allow operator to lower floor to 1.2 for compatibility.
	minVer := uint16(tls.VersionTLS13)
	if cfg.MinVersion == "1.2" {
		minVer = tls.VersionTLS12
	}

	tlsCfg := &tls.Config{ //nolint:gosec // G402: TLS 1.2 is intentional — operator controls min_version; AEAD-only ciphers are enforced below.
		MinVersion:     minVer,
		GetCertificate: reloader.GetCertificate,
		// Restrict TLS 1.2 to AEAD-only cipher suites. TLS 1.3 ciphers are
		// selected automatically by the Go runtime and are not configurable.
		CipherSuites: tlsutil.AEADCipherSuites,
	}

	if cfg.ClientCAFile != "" {
		pool, caErr := tlsutil.LoadClientCA(cfg.ClientCAFile)
		if caErr != nil {
			return nil, nil, fmt.Errorf("load client CA: %w", caErr)
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tlsutil.ParseClientAuthPolicy(cfg.ClientAuthPolicy)
	}

	return tlsCfg, reloader, nil
}
