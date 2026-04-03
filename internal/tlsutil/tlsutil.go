// Package tlsutil provides TLS configuration helpers for signet-exporter.
package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync/atomic"
)

// AEADCipherSuites lists the TLS 1.2 cipher suites permitted by signet.
// Only AEAD constructions (AES-GCM, ChaCha20-Poly1305) are allowed.
// TLS 1.3 cipher selection is handled automatically by the Go runtime.
var AEADCipherSuites = []uint16{
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
}

// BuildTLSConfig constructs a *tls.Config from signet's TLS configuration.
//   - If client_ca_file is set, enables mTLS with the specified auth policy.
//   - Supports three client auth policies: "require_and_verify" (default when CA is set),
//     "verify_if_given", and "no_client_cert".
//   - Sets MinVersion to tls.VersionTLS12, prefers TLS 1.3.
//   - Restricts cipher suites to AEAD-only (AES-GCM, ChaCha20-Poly1305) for TLS 1.2.
func BuildTLSConfig(certFile, keyFile, clientCAFile, clientAuthPolicy string) (*tls.Config, error) {
	reloader, err := NewKeypairReloader(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load keypair: %w", err)
	}

	cfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: reloader.GetCertificate,
		CipherSuites:   AEADCipherSuites,
	}

	if clientCAFile != "" {
		pool, caErr := LoadClientCA(clientCAFile)
		if caErr != nil {
			return nil, fmt.Errorf("load client CA: %w", caErr)
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = ParseClientAuthPolicy(clientAuthPolicy)
	}

	return cfg, nil
}

// ParseClientAuthPolicy maps a policy string to a tls.ClientAuthType.
// The default (empty string or "require_and_verify") requires and verifies a client cert.
func ParseClientAuthPolicy(policy string) tls.ClientAuthType {
	switch policy {
	case "verify_if_given":
		return tls.VerifyClientCertIfGiven
	case "no_client_cert":
		return tls.NoClientCert
	default: // "require_and_verify" or empty
		return tls.RequireAndVerifyClientCert
	}
}

// LoadClientCA reads and parses a PEM CA bundle, returns a *x509.CertPool.
// Returns an error if the file is empty or contains no valid certificates.
func LoadClientCA(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA file %q: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no valid certificates found in %q", path)
	}
	return pool, nil
}

// KeypairReloader manages atomic reload of server certificate keypairs.
// Safe for concurrent access — tls.Config.GetCertificate calls this on every handshake.
type KeypairReloader struct {
	certPath string
	keyPath  string
	cert     atomic.Pointer[tls.Certificate]
}

// NewKeypairReloader loads the initial keypair and returns a reloader.
func NewKeypairReloader(certPath, keyPath string) (*KeypairReloader, error) {
	kr := &KeypairReloader{certPath: certPath, keyPath: keyPath}
	if err := kr.Reload(); err != nil {
		return nil, err
	}
	return kr, nil
}

// Reload re-reads the cert and key files from disk. Called on SIGHUP.
// If the new files are invalid, the old cert remains active and an error is returned.
func (kr *KeypairReloader) Reload() error {
	cert, err := tls.LoadX509KeyPair(kr.certPath, kr.keyPath)
	if err != nil {
		return fmt.Errorf("reload keypair %q + %q: %w", kr.certPath, kr.keyPath, err)
	}
	kr.cert.Store(&cert)
	return nil
}

// GetCertificate is the callback for tls.Config.GetCertificate.
func (kr *KeypairReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return kr.cert.Load(), nil
}
