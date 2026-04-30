// Package remotewrite implements native Prometheus remote write protocol v1.
//
// A Sender gathers metrics from a prometheus.Gatherer on a fixed interval,
// converts them to a *prompb.WriteRequest, and pushes them to a single
// configured endpoint with snappy compression. An in-memory bounded queue
// drops oldest on overflow; a single-flight consumer applies exponential
// backoff on recoverable failures (5xx, network, timeout).
//
// mTLS is the default authentication mode for compliance-heavy environments.
// Bearer-token and HTTP basic auth are supported as alternatives.
package remotewrite

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"time"
	"unicode/utf8"
)

// Config holds the operator-facing remote-write configuration.
type Config struct {
	Enabled        bool              `yaml:"enabled"`
	Endpoint       string            `yaml:"endpoint"`
	Interval       time.Duration     `yaml:"interval"`
	Timeout        time.Duration     `yaml:"timeout"`
	Queue          QueueConfig       `yaml:"queue"`
	Auth           AuthConfig        `yaml:"auth"`
	ExternalLabels map[string]string `yaml:"external_labels"`
}

// QueueConfig controls the in-memory FIFO buffer between the producer and
// the HTTP consumer.
type QueueConfig struct {
	MaxSamples int    `yaml:"max_samples"`
	Overflow   string `yaml:"overflow"` // "drop_oldest" only in v0.6.0; field exists for forward-compat
}

// AuthConfig selects the receiver authentication mechanism.
//
// Type is one of:
//
//	"mtls"   — default; client cert + key, receiver-side CA
//	"bearer" — Authorization: Bearer <token>
//	"basic"  — Authorization: Basic base64(user:pass)
//	"none"   — no authentication (legal but discouraged over https)
type AuthConfig struct {
	Type              string `yaml:"type"`
	BearerTokenFile   string `yaml:"bearer_token_file"`
	BasicUsername     string `yaml:"basic_username"`
	BasicPasswordFile string `yaml:"basic_password_file"`
	CACertFile        string `yaml:"ca_cert_file"`
	ClientCertFile    string `yaml:"client_cert_file"`
	ClientKeyFile     string `yaml:"client_key_file"`
}

// DefaultConfig returns the disabled-by-default remote write configuration.
// When operators enable it, mTLS paths default to /etc/signet/tls matching
// the existing TLS-listener defaults — most deployments share the same
// keypair for inbound mTLS scrape and outbound mTLS push.
func DefaultConfig() Config {
	return Config{
		Enabled:  false,
		Endpoint: "",
		Interval: 60 * time.Second,
		Timeout:  30 * time.Second,
		Queue: QueueConfig{
			MaxSamples: 50000,
			Overflow:   "drop_oldest",
		},
		Auth: AuthConfig{
			Type:           "mtls",
			CACertFile:     "/etc/signet/tls/ca.pem",
			ClientCertFile: "/etc/signet/tls/client.pem",
			ClientKeyFile:  "/etc/signet/tls/client-key.pem",
		},
		ExternalLabels: map[string]string{},
	}
}

// labelNameRE matches the Prometheus label name grammar.
var labelNameRE = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// ConfigWarning is a non-fatal validation result. Callers may choose to log
// and continue, or to treat it as an error. Returned only by Validate.
type ConfigWarning struct{ msg string }

// Error implements the error interface.
func (w *ConfigWarning) Error() string { return w.msg }

// IsWarning reports whether err is a non-fatal ConfigWarning.
func IsWarning(err error) bool {
	var w *ConfigWarning
	return errors.As(err, &w)
}

// Validate checks the configuration for logical errors. Fatal errors are
// returned as a regular error; auth=none over https returns a *ConfigWarning
// that callers may downgrade to a log line.
//
// When Enabled is false, Validate returns nil immediately — disabled remote
// write does not require any other field to be valid.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.Endpoint == "" {
		return fmt.Errorf("endpoint: required when remote_write.enabled is true")
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil {
		return fmt.Errorf("endpoint: %q is not a valid URL: %w", c.Endpoint, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("endpoint: scheme must be \"http\" or \"https\", got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("endpoint: host required, got %q", c.Endpoint)
	}

	if c.Interval < time.Second {
		return fmt.Errorf("interval: must be >= 1s, got %s", c.Interval)
	}
	if c.Timeout < time.Second {
		return fmt.Errorf("timeout: must be >= 1s, got %s", c.Timeout)
	}
	if c.Timeout >= c.Interval {
		return fmt.Errorf("timeout (%s) must be < interval (%s)", c.Timeout, c.Interval)
	}

	if c.Queue.MaxSamples <= 0 {
		return fmt.Errorf("queue.max_samples: must be > 0, got %d", c.Queue.MaxSamples)
	}
	if c.Queue.Overflow != "" && c.Queue.Overflow != "drop_oldest" {
		return fmt.Errorf("queue.overflow: only \"drop_oldest\" is supported in v0.6.0, got %q", c.Queue.Overflow)
	}

	if err := c.Auth.validate(u.Scheme); err != nil {
		// Pass *ConfigWarning through unchanged so callers can recognise it.
		var warn *ConfigWarning
		if errors.As(err, &warn) {
			if extLabelErr := c.validateExternalLabels(); extLabelErr != nil {
				return extLabelErr
			}
			return warn
		}
		return fmt.Errorf("auth: %w", err)
	}

	if err := c.validateExternalLabels(); err != nil {
		return err
	}

	return nil
}

func (c *Config) validateExternalLabels() error {
	for k, v := range c.ExternalLabels {
		if !labelNameRE.MatchString(k) {
			return fmt.Errorf("external_labels: key %q does not match [a-zA-Z_][a-zA-Z0-9_]*", k)
		}
		if !utf8.ValidString(v) {
			return fmt.Errorf("external_labels: value for key %q is not valid UTF-8", k)
		}
	}
	return nil
}

func (a *AuthConfig) validate(endpointScheme string) error {
	switch a.Type {
	case "", "mtls":
		// "" is treated as mtls because DefaultConfig sets mtls explicitly;
		// an empty string therefore indicates the user reset Type without a
		// replacement, which we treat as mtls to match documented defaults.
		if a.CACertFile == "" || a.ClientCertFile == "" || a.ClientKeyFile == "" {
			return fmt.Errorf("mtls auth requires ca_cert_file, client_cert_file, and client_key_file")
		}
		if err := mustExist(a.CACertFile, "ca_cert_file"); err != nil {
			return err
		}
		if err := mustExist(a.ClientCertFile, "client_cert_file"); err != nil {
			return err
		}
		if err := mustExist(a.ClientKeyFile, "client_key_file"); err != nil {
			return err
		}
	case "bearer":
		if a.BearerTokenFile == "" {
			return fmt.Errorf("bearer auth requires bearer_token_file")
		}
		if err := mustExist(a.BearerTokenFile, "bearer_token_file"); err != nil {
			return err
		}
	case "basic":
		if a.BasicUsername == "" || a.BasicPasswordFile == "" {
			return fmt.Errorf("basic auth requires basic_username and basic_password_file")
		}
		if err := mustExist(a.BasicPasswordFile, "basic_password_file"); err != nil {
			return err
		}
	case "none":
		if endpointScheme == "https" {
			return &ConfigWarning{msg: "auth: type=none over https is unusual — verify the receiver does not require authentication"}
		}
	default:
		return fmt.Errorf("type: must be one of \"mtls\", \"bearer\", \"basic\", \"none\", got %q", a.Type)
	}
	return nil
}

func mustExist(path, field string) error {
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}
