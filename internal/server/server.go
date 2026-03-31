// Package server provides the HTTP(S) server for the /metrics, /health, and /ready endpoints.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"github.com/maravexa/signet-exporter/internal/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server wraps an http.Server and knows whether TLS is configured.
type Server struct {
	httpServer *http.Server
	tlsEnabled bool
}

// NewHandler creates the HTTP handler with /metrics, /health, and /ready endpoints.
// It can be used directly in tests via httptest.NewServer without TLS setup.
func NewHandler(col prometheus.Collector, ready <-chan struct{}) http.Handler {
	registry := prometheus.NewRegistry()
	registry.MustRegister(col)

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
	handler := NewHandler(col, ready)

	httpSrv := &http.Server{
		Addr:    cfg.ListenAddress,
		Handler: handler,
	}

	tlsEnabled := false
	if cfg.TLS.CertFile != "" {
		tlsCfg, err := buildTLSConfig(&cfg.TLS)
		if err != nil {
			return nil, fmt.Errorf("server: build TLS config: %w", err)
		}
		httpSrv.TLSConfig = tlsCfg
		tlsEnabled = true
	}

	return &Server{httpServer: httpSrv, tlsEnabled: tlsEnabled}, nil
}

// Start begins serving. Uses HTTPS when TLS is configured, otherwise plain HTTP.
// Returns http.ErrServerClosed after a successful Shutdown call.
func (s *Server) Start() error {
	if s.tlsEnabled {
		// Certificate is pre-loaded in TLSConfig.Certificates; empty strings are intentional.
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

func buildTLSConfig(cfg *config.TLSConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	if cfg.MinVersion == "1.2" {
		tlsCfg.MinVersion = tls.VersionTLS12
	}

	// Pre-load the certificate so ListenAndServeTLS("", "") works correctly.
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load certificate pair: %w", err)
	}
	tlsCfg.Certificates = []tls.Certificate{cert}

	if cfg.ClientCAFile != "" {
		pool, err := loadCertPool(cfg.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("load client CA: %w", err)
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsCfg, nil
}

func loadCertPool(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no valid certificates found in %q", caFile)
	}
	return pool, nil
}
