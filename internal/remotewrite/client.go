package remotewrite

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/golang/snappy"

	"github.com/maravexa/signet-exporter/internal/remotewrite/prompb"
)

// remoteWriteVersion is the protocol version we advertise. Receivers use it
// to gate features; v0.1.0 means "WriteRequest, samples + labels only" (no
// histograms-as-native-format, no metadata).
const remoteWriteVersion = "0.1.0"

// maxResponseBodyBytes caps how much of an error response we read into the
// SendError message. Receivers can be chatty when rejecting payloads;
// truncate so a misbehaving receiver cannot blow up our logs.
const maxResponseBodyBytes = 256

// Client is a thread-safe HTTP client wrapper for one remote-write endpoint.
type Client struct {
	httpClient  *http.Client
	endpoint    string
	auth        AuthConfig
	bearerToken atomic.Pointer[string] // set once at construction; nil for non-bearer auth
	basicSecret atomic.Pointer[string] // set once at construction; nil for non-basic auth
	userAgent   string
}

// SendError describes a remote-write failure with enough detail for the
// sender's retry logic to decide whether to back off (Recoverable=true)
// or drop the payload (Recoverable=false).
type SendError struct {
	StatusCode  int           // 0 for network/timeout errors
	Message     string        // truncated response body or net.OpError text
	Recoverable bool          // 5xx and network errors = true; 4xx = false
	RetryAfter  time.Duration // parsed from Retry-After header if present
}

// Error implements the error interface.
func (e *SendError) Error() string {
	if e.StatusCode == 0 {
		return fmt.Sprintf("remote write: network error: %s", e.Message)
	}
	return fmt.Sprintf("remote write: HTTP %d: %s", e.StatusCode, e.Message)
}

// IsRecoverable reports whether err is a SendError flagged Recoverable.
// Anything that is not a *SendError is treated as not recoverable.
func IsRecoverable(err error) bool {
	var se *SendError
	if errors.As(err, &se) {
		return se.Recoverable
	}
	return false
}

// NewClient builds a Client whose transport encodes the configured auth
// mode. mTLS sets RootCAs and the client keypair on the TLS config; bearer
// and basic credentials are read before the Client is published to a Sender.
//
// Failure to read TLS material or a configured credential at startup is fatal
// — callers should treat it as "refuse to start". Sender.Reload builds a new
// client before replacing the old one, so a later failed rotation is retained
// safely by the old client.
func NewClient(cfg Config, version string) (*Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	switch cfg.Auth.Type {
	case "", "mtls":
		caPool, err := loadCAPool(cfg.Auth.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("load ca cert: %w", err)
		}
		tlsCfg.RootCAs = caPool
		cert, err := tls.LoadX509KeyPair(cfg.Auth.ClientCertFile, cfg.Auth.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client keypair: %w", err)
		}
		if err := validateClientCertificate(cert, time.Now()); err != nil {
			return nil, err
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
		MaxIdleConns:    10,
		IdleConnTimeout: 90 * time.Second,
	}

	c := &Client{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   cfg.Timeout,
		},
		endpoint:  cfg.Endpoint,
		auth:      cfg.Auth,
		userAgent: fmt.Sprintf("signet-exporter/%s", version),
	}

	if cfg.Auth.Type == "bearer" {
		token, err := readTrimmed(cfg.Auth.BearerTokenFile)
		if err != nil {
			return nil, fmt.Errorf("read bearer token: %w", err)
		}
		c.bearerToken.Store(&token)
	}
	if cfg.Auth.Type == "basic" {
		password, err := readTrimmed(cfg.Auth.BasicPasswordFile)
		if err != nil {
			return nil, fmt.Errorf("read basic auth password: %w", err)
		}
		c.basicSecret.Store(&password)
	}
	return c, nil
}

// validateClientCertificate rejects a locally unusable client certificate at
// construction/reload time. This mirrors the listener keypair reloader and
// preserves the previously published immutable client on a bad rotation.
func validateClientCertificate(cert tls.Certificate, now time.Time) error {
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("client certificate has no leaf")
	}
	leaf := cert.Leaf
	if leaf == nil {
		parsed, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return fmt.Errorf("parse client certificate leaf: %w", err)
		}
		leaf = parsed
	}
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("client certificate is not valid before %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return fmt.Errorf("client certificate expired at %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

// Send marshals req to protobuf, snappy-compresses, and POSTs to the
// configured endpoint. Classification of the result into recoverable vs.
// fatal is done here so Sender's loop is simple.
func (c *Client) Send(ctx context.Context, req *prompb.WriteRequest) error {
	raw, err := req.Marshal()
	if err != nil {
		return fmt.Errorf("marshal write request: %w", err)
	}
	compressed := snappy.Encode(nil, raw)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(compressed))
	if err != nil {
		return fmt.Errorf("build http request: %w", err)
	}
	httpReq.Header.Set("Content-Encoding", "snappy")
	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	httpReq.Header.Set("X-Prometheus-Remote-Write-Version", remoteWriteVersion)
	httpReq.Header.Set("User-Agent", c.userAgent)

	switch c.auth.Type {
	case "bearer":
		if tok := c.bearerToken.Load(); tok != nil && *tok != "" {
			httpReq.Header.Set("Authorization", "Bearer "+*tok)
		}
	case "basic":
		if password := c.basicSecret.Load(); password != nil {
			httpReq.SetBasicAuth(c.auth.BasicUsername, *password)
		} else {
			return &SendError{StatusCode: 0, Message: "basic auth password unavailable", Recoverable: false}
		}
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return &SendError{StatusCode: 0, Message: err.Error(), Recoverable: true}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// Drain the body so connection reuse works.
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	msg := strings.TrimSpace(string(bodyBytes))
	se := &SendError{StatusCode: resp.StatusCode, Message: msg}

	switch {
	case resp.StatusCode >= 500:
		se.Recoverable = true
	case resp.StatusCode == http.StatusTooManyRequests:
		// 429 is recoverable per spec; receivers commonly use it for backpressure.
		se.Recoverable = true
	default:
		se.Recoverable = false
	}
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if d, perr := time.ParseDuration(ra + "s"); perr == nil {
			se.RetryAfter = d
		}
	}
	return se
}

// loadCAPool reads a PEM CA bundle into a fresh *x509.CertPool. Callers
// must not mutate the returned pool.
func loadCAPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no PEM certificates found in %s", path)
	}
	return pool, nil
}

// readTrimmed reads a small credential file and trims surrounding whitespace.
// We deliberately do not enforce a max size — operators occasionally supply
// long JWT tokens that exceed naive limits.
func readTrimmed(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
