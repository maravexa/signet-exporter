package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"github.com/maravexa/signet-exporter/internal/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewServer constructs an *http.Server wired with the /metrics, /health, and /ready endpoints.
// TLS (and optionally mTLS) is configured according to cfg.TLS.
func NewServer(cfg *config.Config, collector prometheus.Collector) (*http.Server, error) {
	registry := prometheus.NewRegistry()
	if err := registry.Register(collector); err != nil {
		return nil, fmt.Errorf("server: register collector: %w", err)
	}

	mux := http.NewServeMux()

	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	}))

	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) {
		// TODO: gate on first scan completion flag once scheduler exposes it.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:    cfg.ListenAddress,
		Handler: mux,
	}

	// Configure TLS only when a certificate is provided.
	if cfg.TLS.CertFile != "" {
		tlsCfg, err := buildTLSConfig(&cfg.TLS)
		if err != nil {
			return nil, fmt.Errorf("server: build TLS config: %w", err)
		}
		srv.TLSConfig = tlsCfg
	}

	return srv, nil
}

func buildTLSConfig(cfg *config.TLSConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if cfg.MinVersion == "1.2" {
		tlsCfg.MinVersion = tls.VersionTLS12
	}

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
