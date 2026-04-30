package remotewrite

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func TestValidate_DisabledIsAlwaysValid(t *testing.T) {
	cfg := Config{Enabled: false, Endpoint: "::nonsense::"}
	if err := cfg.Validate(); err != nil {
		t.Errorf("disabled config must validate cleanly, got: %v", err)
	}
}

func TestValidate_EndpointRequired(t *testing.T) {
	cfg := Config{Enabled: true}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing endpoint")
	}
}

func TestValidate_EndpointSchemeMustBeHTTP(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Endpoint = "ftp://example.com"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected scheme error")
	}
}

func TestValidate_TimeoutMustBeLessThanInterval(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Endpoint = "http://example.com"
	cfg.Auth = AuthConfig{Type: "none"}
	cfg.Interval = 10 * time.Second
	cfg.Timeout = 30 * time.Second
	if err := cfg.Validate(); err == nil {
		t.Fatal("timeout >= interval must fail")
	}
}

func TestValidate_QueueMaxSamples(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Endpoint = "http://example.com"
	cfg.Auth = AuthConfig{Type: "none"}
	cfg.Queue.MaxSamples = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("queue.max_samples=0 must fail")
	}
}

func TestValidate_AuthTypeUnknown(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Endpoint = "http://example.com"
	cfg.Auth = AuthConfig{Type: "kerberos"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("unknown auth type must fail")
	}
}

func TestValidate_BearerRequiresFile(t *testing.T) {
	dir := t.TempDir()
	tokenPath := writeFile(t, dir, "token", "abc")

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Endpoint = "http://example.com"
	cfg.Auth = AuthConfig{Type: "bearer", BearerTokenFile: tokenPath}
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid bearer config: %v", err)
	}

	cfg.Auth.BearerTokenFile = ""
	if err := cfg.Validate(); err == nil {
		t.Error("missing token file must fail")
	}
}

func TestValidate_MTLSRequiresAllThreeFiles(t *testing.T) {
	dir := t.TempDir()
	ca := writeFile(t, dir, "ca.pem", "x")
	cert := writeFile(t, dir, "cert.pem", "x")
	key := writeFile(t, dir, "key.pem", "x")

	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Endpoint = "https://example.com"
	cfg.Auth = AuthConfig{Type: "mtls", CACertFile: ca, ClientCertFile: cert, ClientKeyFile: key}
	if err := cfg.Validate(); err != nil {
		t.Errorf("complete mtls config: %v", err)
	}

	cfg.Auth.ClientKeyFile = ""
	if err := cfg.Validate(); err == nil {
		t.Error("missing client_key_file must fail")
	}
}

func TestValidate_AuthNoneOverHTTPS_IsWarning(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Endpoint = "https://example.com"
	cfg.Auth = AuthConfig{Type: "none"}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("auth=none over https should produce a warning")
	}
	if !IsWarning(err) {
		t.Errorf("expected ConfigWarning, got fatal: %v", err)
	}
}

func TestValidate_AuthNoneOverHTTPIsClean(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Endpoint = "http://example.com"
	cfg.Auth = AuthConfig{Type: "none"}
	if err := cfg.Validate(); err != nil {
		t.Errorf("auth=none over http should be clean, got: %v", err)
	}
}

func TestValidate_ExternalLabelKeySyntax(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Endpoint = "http://example.com"
	cfg.Auth = AuthConfig{Type: "none"}
	cfg.ExternalLabels = map[string]string{"123-bad": "x"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("invalid label key must fail")
	}
}

func TestIsWarning_NotWrapping(t *testing.T) {
	if IsWarning(errors.New("plain")) {
		t.Error("plain error must not look like a warning")
	}
}
