package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// GenerateCerts creates a self-signed CA, server cert, and client cert for dev/test use.
// Writes to the specified output directory:
//
//	ca.pem, ca-key.pem
//	server.pem, server-key.pem (SAN: localhost, 127.0.0.1, ::1)
//	client.pem, client-key.pem
//
// CA validity: 10 years. Server/client validity: 1 year.
// Key type: ECDSA P-256.
// Returns error if output directory doesn't exist or files can't be written.
func GenerateCerts(outputDir string) error {
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		return fmt.Errorf("output directory %q does not exist", outputDir)
	}

	caKey, caCert, caCertDER, err := generateCA()
	if err != nil {
		return err
	}
	if err := writeCert(filepath.Join(outputDir, "ca.pem"), caCertDER); err != nil {
		return err
	}
	if err := writeKey(filepath.Join(outputDir, "ca-key.pem"), caKey); err != nil {
		return err
	}

	serverKey, serverCertDER, err := generateServerCert(caCert, caKey)
	if err != nil {
		return err
	}
	if err := writeCert(filepath.Join(outputDir, "server.pem"), serverCertDER); err != nil {
		return err
	}
	if err := writeKey(filepath.Join(outputDir, "server-key.pem"), serverKey); err != nil {
		return err
	}

	clientKey, clientCertDER, err := generateClientCert(caCert, caKey)
	if err != nil {
		return err
	}
	if err := writeCert(filepath.Join(outputDir, "client.pem"), clientCertDER); err != nil {
		return err
	}
	if err := writeKey(filepath.Join(outputDir, "client-key.pem"), clientKey); err != nil {
		return err
	}

	return nil
}

func generateCA() (*ecdsa.PrivateKey, *x509.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate CA key: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "signet-dev-ca"},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}
	return key, cert, der, nil
}

func generateServerCert(caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate server key: %w", err)
	}

	dnsNames := []string{"localhost"}
	if hostname, herr := os.Hostname(); herr == nil && hostname != "" && hostname != "localhost" {
		dnsNames = append(dnsNames, hostname)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: "signet-server"},
		NotBefore:    now,
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create server cert: %w", err)
	}
	return key, der, nil
}

func generateClientCert(caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate client key: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: "signet-client"},
		NotBefore:    now,
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create client cert: %w", err)
	}
	return key, der, nil
}

func randomSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(fmt.Sprintf("tlsutil: failed to generate serial number: %v", err))
	}
	return n
}

func writeCert(path string, der []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create cert file %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func writeKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal EC key: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create key file %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}
