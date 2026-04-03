package tlsutil_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/maravexa/signet-exporter/internal/tlsutil"
)

// certPaths holds paths to a generated cert set for a single test.
type certPaths struct {
	dir        string
	caPath     string
	serverCert string
	serverKey  string
	clientCert string
	clientKey  string
}

func generateTestCerts(t *testing.T) certPaths {
	t.Helper()
	dir := t.TempDir()
	if err := tlsutil.GenerateCerts(dir); err != nil {
		t.Fatalf("GenerateCerts: %v", err)
	}
	return certPaths{
		dir:        dir,
		caPath:     filepath.Join(dir, "ca.pem"),
		serverCert: filepath.Join(dir, "server.pem"),
		serverKey:  filepath.Join(dir, "server-key.pem"),
		clientCert: filepath.Join(dir, "client.pem"),
		clientKey:  filepath.Join(dir, "client-key.pem"),
	}
}

// ---- BuildTLSConfig tests ----

func TestBuildTLSConfig_ServerOnly(t *testing.T) {
	cs := generateTestCerts(t)
	cfg, err := tlsutil.BuildTLSConfig(cs.serverCert, cs.serverKey, "", "")
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth = %v, want NoClientCert", cfg.ClientAuth)
	}
}

func TestBuildTLSConfig_mTLS_RequireAndVerify(t *testing.T) {
	cs := generateTestCerts(t)
	cfg, err := tlsutil.BuildTLSConfig(cs.serverCert, cs.serverKey, cs.caPath, "require_and_verify")
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
}

func TestBuildTLSConfig_mTLS_VerifyIfGiven(t *testing.T) {
	cs := generateTestCerts(t)
	cfg, err := tlsutil.BuildTLSConfig(cs.serverCert, cs.serverKey, cs.caPath, "verify_if_given")
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Errorf("ClientAuth = %v, want VerifyClientCertIfGiven", cfg.ClientAuth)
	}
}

func TestBuildTLSConfig_InvalidCertPath(t *testing.T) {
	_, err := tlsutil.BuildTLSConfig("/nonexistent/cert.pem", "/nonexistent/key.pem", "", "")
	if err == nil {
		t.Fatal("expected error for nonexistent cert path, got nil")
	}
}

func TestBuildTLSConfig_InvalidClientCA(t *testing.T) {
	cs := generateTestCerts(t)
	badCA := filepath.Join(t.TempDir(), "bad-ca.pem")
	if err := os.WriteFile(badCA, []byte("not valid PEM"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := tlsutil.BuildTLSConfig(cs.serverCert, cs.serverKey, badCA, "")
	if err == nil {
		t.Fatal("expected error for invalid CA PEM, got nil")
	}
}

func TestBuildTLSConfig_MinVersion(t *testing.T) {
	cs := generateTestCerts(t)
	cfg, err := tlsutil.BuildTLSConfig(cs.serverCert, cs.serverKey, "", "")
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = 0x%04x, want 0x%04x (TLS 1.2)", cfg.MinVersion, tls.VersionTLS12)
	}
}

func TestBuildTLSConfig_CipherSuites(t *testing.T) {
	cs := generateTestCerts(t)
	cfg, err := tlsutil.BuildTLSConfig(cs.serverCert, cs.serverKey, "", "")
	if err != nil {
		t.Fatalf("BuildTLSConfig: %v", err)
	}

	want := map[uint16]bool{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:        true,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:        true,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:      true,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:      true,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   true,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: true,
	}

	if len(cfg.CipherSuites) != len(want) {
		t.Errorf("CipherSuites len = %d, want %d", len(cfg.CipherSuites), len(want))
	}
	for _, suite := range cfg.CipherSuites {
		if !want[suite] {
			t.Errorf("unexpected cipher suite: 0x%04x", suite)
		}
	}
}

// ---- KeypairReloader tests ----

func TestKeypairReloader_InitialLoad(t *testing.T) {
	cs := generateTestCerts(t)
	kr, err := tlsutil.NewKeypairReloader(cs.serverCert, cs.serverKey)
	if err != nil {
		t.Fatalf("NewKeypairReloader: %v", err)
	}
	cert, err := kr.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil {
		t.Fatal("GetCertificate returned nil cert")
	}
}

func TestKeypairReloader_Reload(t *testing.T) {
	cs := generateTestCerts(t)
	kr, err := tlsutil.NewKeypairReloader(cs.serverCert, cs.serverKey)
	if err != nil {
		t.Fatalf("NewKeypairReloader: %v", err)
	}

	cert1, _ := kr.GetCertificate(nil)

	// Generate a fresh cert set and overwrite the files the reloader points at.
	dir2 := t.TempDir()
	if err := tlsutil.GenerateCerts(dir2); err != nil {
		t.Fatalf("GenerateCerts (second): %v", err)
	}
	newCert, err := os.ReadFile(filepath.Join(dir2, "server.pem"))
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := os.ReadFile(filepath.Join(dir2, "server-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cs.serverCert, newCert, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cs.serverKey, newKey, 0600); err != nil {
		t.Fatal(err)
	}

	if err := kr.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	cert2, _ := kr.GetCertificate(nil)
	if cert1 == cert2 {
		t.Error("cert pointer unchanged after Reload — expected new cert to be loaded")
	}
}

func TestKeypairReloader_ReloadInvalid(t *testing.T) {
	cs := generateTestCerts(t)
	kr, err := tlsutil.NewKeypairReloader(cs.serverCert, cs.serverKey)
	if err != nil {
		t.Fatalf("NewKeypairReloader: %v", err)
	}

	certBefore, _ := kr.GetCertificate(nil)

	// Overwrite the cert file with garbage; key is still valid.
	if err := os.WriteFile(cs.serverCert, []byte("this is not a valid certificate"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := kr.Reload(); err == nil {
		t.Fatal("expected error on reload with invalid cert, got nil")
	}

	// Old cert must still be served.
	certAfter, _ := kr.GetCertificate(nil)
	if certBefore != certAfter {
		t.Error("cert pointer changed after failed Reload — old cert should remain active")
	}
}

func TestKeypairReloader_ConcurrentAccess(t *testing.T) {
	cs := generateTestCerts(t)
	kr, err := tlsutil.NewKeypairReloader(cs.serverCert, cs.serverKey)
	if err != nil {
		t.Fatalf("NewKeypairReloader: %v", err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// 100 reader goroutines continuously calling GetCertificate.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					cert, cerr := kr.GetCertificate(nil)
					if cerr != nil || cert == nil {
						t.Errorf("GetCertificate: err=%v cert=%v", cerr, cert)
					}
				}
			}
		}()
	}

	// Reload several times from the main goroutine while readers are active.
	for i := 0; i < 5; i++ {
		_ = kr.Reload()
	}
	close(stop)
	wg.Wait()
}

// ---- GenerateCerts tests ----

func TestGenerateCerts(t *testing.T) {
	dir := t.TempDir()
	if err := tlsutil.GenerateCerts(dir); err != nil {
		t.Fatalf("GenerateCerts: %v", err)
	}

	// All six files must exist.
	for _, name := range []string{"ca.pem", "ca-key.pem", "server.pem", "server-key.pem", "client.pem", "client-key.pem"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected file %q: %v", name, err)
		}
	}

	// Parse the CA cert.
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		t.Fatal("failed to PEM-decode ca.pem")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	// Helper: load and parse a PEM cert file.
	loadCert := func(name string) *x509.Certificate {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			t.Fatalf("PEM decode %s failed", name)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		return cert
	}

	// Verify server cert is signed by the CA.
	serverCert := loadCert("server.pem")
	if err := serverCert.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("server cert not signed by CA: %v", err)
	}

	// Server cert must have localhost SAN.
	foundLocalhost := false
	for _, name := range serverCert.DNSNames {
		if name == "localhost" {
			foundLocalhost = true
		}
	}
	if !foundLocalhost {
		t.Errorf("server cert DNSNames %v missing \"localhost\"", serverCert.DNSNames)
	}

	// Server cert must have 127.0.0.1 SAN.
	found127 := false
	for _, ip := range serverCert.IPAddresses {
		if ip.Equal(net.ParseIP("127.0.0.1")) {
			found127 = true
		}
	}
	if !found127 {
		t.Errorf("server cert IPAddresses %v missing 127.0.0.1", serverCert.IPAddresses)
	}

	// Server cert must carry ExtKeyUsageServerAuth.
	hasServerAuth := false
	for _, u := range serverCert.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
	}
	if !hasServerAuth {
		t.Error("server cert missing ExtKeyUsageServerAuth")
	}

	// Verify client cert is signed by the CA.
	clientCert := loadCert("client.pem")
	if err := clientCert.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("client cert not signed by CA: %v", err)
	}

	// Client cert must carry ExtKeyUsageClientAuth.
	hasClientAuth := false
	for _, u := range clientCert.ExtKeyUsage {
		if u == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasClientAuth {
		t.Error("client cert missing ExtKeyUsageClientAuth")
	}
}

func TestGenerateCerts_BadDir(t *testing.T) {
	err := tlsutil.GenerateCerts("/nonexistent/directory/signet-test")
	if err == nil {
		t.Fatal("expected error for nonexistent output directory, got nil")
	}
}
