package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfig_HostTTLPresence(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		set  bool
		want time.Duration
	}{
		{
			name: "omitted uses default policy",
			yaml: "listen_address: 127.0.0.1:9420\nsubnets: []\n",
			set:  false,
		},
		{
			name: "explicit zero disables ttl",
			yaml: "listen_address: 127.0.0.1:9420\nhost_ttl: 0s\nsubnets: []\n",
			set:  true,
			want: 0,
		},
		{
			name: "explicit duration",
			yaml: "listen_address: 127.0.0.1:9420\nhost_ttl: 5m\nsubnets: []\n",
			set:  true,
			want: 5 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "signet.yaml")
			if err := os.WriteFile(path, []byte(tt.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.HostTTLSet != tt.set || cfg.HostTTL != tt.want {
				t.Fatalf("HostTTLSet, HostTTL = %t, %s; want %t, %s", cfg.HostTTLSet, cfg.HostTTL, tt.set, tt.want)
			}
		})
	}
}
