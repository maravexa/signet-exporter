package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDiscoverySubnetSizeLimitMatchesReloadValidation(t *testing.T) {
	large := SubnetConfig{CIDR: "10.0.0.0/15", ScanInterval: time.Minute}
	if err := validateSubnet(&large); err == nil {
		t.Fatal("startup validation accepted oversized discovery subnet")
	}
	if err := ValidateReloadable(ReloadableConfig{Subnets: []ReloadableSubnet{{CIDR: large.CIDR, ScanInterval: large.ScanInterval}}}); err == nil {
		t.Fatal("reload validation accepted oversized discovery subnet")
	}
	boundary := SubnetConfig{CIDR: "10.0.0.0/16", ScanInterval: time.Minute}
	if err := validateSubnet(&boundary); err != nil {
		t.Fatalf("startup validation rejected /16 boundary: %v", err)
	}
}

func TestValidateRejectsDuplicatePorts(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Subnets = []SubnetConfig{{CIDR: "10.0.1.0/24", ScanInterval: time.Minute, Ports: []uint16{53, 53}}}
	if err := Validate(cfg); err == nil {
		t.Fatal("startup validation accepted duplicate ports")
	}
}

func TestValidateDNSRequiresUsableTimeoutAndServerAddresses(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(cfg *Config) { cfg.DNS.Timeout = 0 },
		func(cfg *Config) { cfg.DNS.Servers = []string{"1.1.1.1"} },
		func(cfg *Config) { cfg.DNS.Servers = []string{"1.1.1.1:0"} },
		func(cfg *Config) { cfg.DNS.Servers = []string{"[::1]:dns"} },
	} {
		cfg := DefaultConfig()
		cfg.Subnets = []SubnetConfig{{CIDR: "10.0.1.0/24", ScanInterval: time.Minute}}
		mutate(cfg)
		if err := Validate(cfg); err == nil {
			t.Fatalf("Validate accepted invalid DNS config: %+v", cfg.DNS)
		}
	}
	cfg := DefaultConfig()
	cfg.Subnets = []SubnetConfig{{CIDR: "10.0.1.0/24", ScanInterval: time.Minute}}
	cfg.DNS.Servers = []string{"1.1.1.1:53", "[::1]:53", "resolver.internal:5353"}
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate rejected valid DNS servers: %v", err)
	}
}

func TestValidateListenAddressRejectsUnspecifiedAddresses(t *testing.T) {
	for _, address := range []string{
		":9420",
		"0.0.0.0:9420",
		"[::]:9420",
		"[0:0:0:0:0:0:0:0]:9420",
		"[::ffff:0.0.0.0]:9420",
	} {
		if err := validateListenAddress(address); err == nil {
			t.Errorf("validateListenAddress(%q) succeeded for an unspecified bind", address)
		}
	}
}

func TestValidateListenAddressRequiresNumericNonzeroPort(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "127.0.0.1:http", "127.0.0.1:65536"} {
		if err := validateListenAddress(address); err == nil {
			t.Errorf("validateListenAddress(%q) unexpectedly succeeded", address)
		}
	}
	if err := validateListenAddress("[::1]:9420"); err != nil {
		t.Errorf("loopback IPv6 bind rejected: %v", err)
	}
}

func TestValidateTLSRejectsIneffectiveMTLSSettings(t *testing.T) {
	for _, cfg := range []TLSConfig{
		{ClientAuthPolicy: "require_and_verify"},
		{ClientAuthPolicy: "verify_if_given"},
		{CertFile: "server.pem", KeyFile: "server.key", ClientCAFile: "ca.pem", ClientAuthPolicy: "no_client_cert"},
	} {
		if err := validateTLS(&cfg); err == nil {
			t.Errorf("validateTLS(%+v) unexpectedly succeeded", cfg)
		}
	}
}

func TestValidateTLSAllowsServerOnlyAndCompleteMTLS(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "server.pem")
	key := filepath.Join(dir, "server.key")
	ca := filepath.Join(dir, "ca.pem")
	for path, mode := range map[string]os.FileMode{cert: 0o644, key: 0o640, ca: 0o644} {
		if err := os.WriteFile(path, []byte("test"), mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, cfg := range []TLSConfig{
		{CertFile: cert, KeyFile: key},
		{CertFile: cert, KeyFile: key, ClientCAFile: ca},
		{CertFile: cert, KeyFile: key, ClientCAFile: ca, ClientAuthPolicy: "verify_if_given"},
	} {
		if err := validateTLS(&cfg); err != nil {
			t.Errorf("validateTLS(%+v): %v", cfg, err)
		}
	}
}
