package remotewrite

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/maravexa/signet-exporter/internal/audit"
	"github.com/maravexa/signet-exporter/internal/remotewrite/prompb"
)

// ErrEnableToggleRequiresRestart is returned by Reload when an operator
// flips the enabled bit. Toggling enabled at runtime would require us to
// start or stop goroutines mid-flight; that path produces too many
// edge-cases (in-flight requests, ticker resets, queue drain semantics)
// for a feature that is naturally a deploy-time decision.
var ErrEnableToggleRequiresRestart = errors.New("remotewrite: changing enabled requires restart")

// unreachableThreshold is how long the receiver must be failing before we
// emit a RemoteWriteEndpointUnreachable audit event. Five minutes matches
// the broader Prometheus convention for "missing"-state alerting.
const unreachableThreshold = 5 * time.Minute

// initialBackoff and maxBackoff bound the exponential backoff in the
// consumer loop. These match Prometheus Agent defaults and are intentionally
// not operator-tunable in v0.6.0.
const (
	initialBackoff = 1 * time.Second
	maxBackoff     = 60 * time.Second
)

// Sender orchestrates the gather → convert → enqueue → send pipeline. One
// Sender per process; a single configured endpoint per Sender.
type Sender struct {
	cfgMu sync.RWMutex
	cfg   Config

	gatherer prometheus.Gatherer
	client   *Client
	queue    *Queue
	metrics  *Metrics
	logger   *slog.Logger
	auditLog *audit.Logger
	version  string

	intervalReset chan time.Duration

	// Cancellation hook for the in-flight HTTP request. Set by the consumer
	// goroutine and called by Reload to abort an in-progress send when
	// endpoint or auth changes. Guarded by cfgMu.
	cancelInFlight context.CancelFunc
}

// NewSender constructs a Sender. The HTTP client is built immediately so
// TLS / token-file failures surface at startup rather than on first push.
func NewSender(cfg Config, gatherer prometheus.Gatherer, metrics *Metrics, logger *slog.Logger, auditLog *audit.Logger, version string) (*Sender, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("remotewrite: cannot construct Sender for disabled config")
	}
	client, err := NewClient(cfg, version)
	if err != nil {
		return nil, fmt.Errorf("build remote write client: %w", err)
	}
	if logger == nil {
		logger = slog.Default()
	}
	if auditLog == nil {
		auditLog = audit.Disabled()
	}
	return &Sender{
		cfg:           cfg,
		gatherer:      gatherer,
		client:        client,
		queue:         NewQueue(cfg.Queue.MaxSamples),
		metrics:       metrics,
		logger:        logger,
		auditLog:      auditLog,
		version:       version,
		intervalReset: make(chan time.Duration, 1),
	}, nil
}

// Endpoint returns the configured endpoint. Used as the value of the
// `endpoint` label on the subsystem's self-metrics.
func (s *Sender) Endpoint() string {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg.Endpoint
}

// Run starts the producer and consumer goroutines and blocks until ctx is
// cancelled. Returns the first non-nil error from either goroutine, or nil
// on clean shutdown.
func (s *Sender) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		s.runProducer(ctx)
	}()
	go func() {
		defer wg.Done()
		s.runConsumer(ctx)
	}()

	<-ctx.Done()
	s.queue.Close()
	wg.Wait()
	return nil
}

// runProducer ticks at cfg.Interval. On each tick: gather → convert → enqueue.
func (s *Sender) runProducer(ctx context.Context) {
	s.cfgMu.RLock()
	interval := s.cfg.Interval
	s.cfgMu.RUnlock()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	endpoint := s.Endpoint()

	for {
		select {
		case <-ctx.Done():
			return
		case newInterval := <-s.intervalReset:
			ticker.Reset(newInterval)
		case <-ticker.C:
			s.produceOnce(endpoint)
		}
	}
}

func (s *Sender) produceOnce(endpoint string) {
	families, err := s.gatherer.Gather()
	if err != nil {
		s.logger.Warn("remote write: gather failed", "err", err)
		return
	}

	s.cfgMu.RLock()
	extLabels := s.cfg.ExternalLabels
	s.cfgMu.RUnlock()

	wr, convErr := Convert(families, extLabels, time.Now().UnixMilli())
	if convErr != nil {
		// Convert reports the first collision; we count one sample per
		// dropped family rather than per-collision so we have a meaningful
		// non-zero counter. The caller log is more useful than the metric here.
		s.metrics.SamplesDropped.WithLabelValues(endpoint, "conversion_error").Inc()
		s.logger.Warn("remote write: conversion error", "err", convErr)
	}

	if wr == nil || len(wr.Timeseries) == 0 {
		return
	}
	dropped := s.queue.Push(wr)
	if dropped > 0 {
		s.metrics.SamplesDropped.WithLabelValues(endpoint, "queue_full").Add(float64(dropped))
	}
	s.metrics.QueueSize.WithLabelValues(endpoint).Set(float64(s.queue.Len()))
}

// runConsumer pops one batch at a time. Single-flight to keep semantics
// simple — ordering and retry budget are easier to reason about with one
// in-flight request. Receivers cope with this; Mimir/Cortex/Thanos all
// document expected throughput in samples/sec, not concurrent requests.
func (s *Sender) runConsumer(ctx context.Context) {
	endpoint := s.Endpoint()
	backoff := initialBackoff
	var inFlight *prompb.WriteRequest
	var firstFailure time.Time
	var lastErrMsg string
	startedLogged := false

	for {
		if ctx.Err() != nil {
			return
		}
		if inFlight == nil {
			req, ok := s.queue.PopWithContext(ctx)
			if !ok {
				return
			}
			inFlight = req
		}
		samples := countSamples(inFlight)

		s.cfgMu.RLock()
		timeout := s.cfg.Timeout
		s.cfgMu.RUnlock()

		sendCtx, cancel := context.WithTimeout(ctx, timeout)
		s.cfgMu.Lock()
		s.cancelInFlight = cancel
		s.cfgMu.Unlock()

		started := time.Now()
		err := s.client.Send(sendCtx, inFlight)
		duration := time.Since(started).Seconds()
		cancel()
		s.cfgMu.Lock()
		s.cancelInFlight = nil
		s.cfgMu.Unlock()

		s.metrics.SendDuration.WithLabelValues(endpoint).Observe(duration)

		if err == nil {
			s.metrics.SamplesSent.WithLabelValues(endpoint).Add(float64(samples))
			s.metrics.LastSuccess.WithLabelValues(endpoint).SetToCurrentTime()
			s.metrics.QueueSize.WithLabelValues(endpoint).Set(float64(s.queue.Len()))

			if !startedLogged {
				s.cfgMu.RLock()
				authType := s.cfg.Auth.Type
				s.cfgMu.RUnlock()
				if authType == "" {
					authType = "mtls"
				}
				s.auditLog.RemoteWriteStarted(endpoint, authType)
				startedLogged = true
			}
			if !firstFailure.IsZero() && time.Since(firstFailure) >= unreachableThreshold {
				s.auditLog.RemoteWriteRecovered(endpoint, time.Since(firstFailure))
			}
			firstFailure = time.Time{}
			lastErrMsg = ""
			inFlight = nil
			backoff = initialBackoff
			continue
		}

		if !IsRecoverable(err) {
			// Non-recoverable: drop the payload and continue with the next
			// batch. 4xx typically means a malformed request the receiver
			// will reject every time — retrying would just waste samples.
			s.metrics.SamplesDropped.WithLabelValues(endpoint, "fatal_response").Add(float64(samples))
			s.metrics.Failures.WithLabelValues(endpoint, classifyFailure(err)).Inc()
			s.logger.Warn("remote write: request rejected (non-recoverable)", "err", err)
			inFlight = nil
			continue
		}

		// Recoverable failure path.
		s.metrics.Failures.WithLabelValues(endpoint, classifyFailure(err)).Inc()
		if firstFailure.IsZero() {
			firstFailure = time.Now()
		} else if time.Since(firstFailure) >= unreachableThreshold && lastErrMsg != err.Error() {
			s.auditLog.RemoteWriteEndpointUnreachable(endpoint, time.Since(firstFailure), err.Error())
		}
		lastErrMsg = err.Error()
		s.logger.Warn("remote write: send failed; will retry",
			"err", err, "backoff", backoff)

		sleep := backoff
		var se *SendError
		if errors.As(err, &se) && se.RetryAfter > 0 {
			sleep = se.RetryAfter
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(sleep):
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// classifyFailure maps a SendError to one of the documented Failures-vec
// reason labels: 4xx | 5xx | network | timeout. Anything else is "network".
func classifyFailure(err error) string {
	var se *SendError
	if !errors.As(err, &se) {
		return "network"
	}
	switch {
	case se.StatusCode == 0:
		// Network or timeout — distinguishing them robustly is awkward, but
		// the deadline-exceeded case from context.WithTimeout always surfaces
		// as a Go-stdlib net.Error with `Timeout()==true` whose Error() string
		// contains "deadline exceeded" or "timeout".
		msg := se.Message
		if containsAny(msg, "deadline exceeded", "Timeout", "timeout", "i/o timeout") {
			return "timeout"
		}
		return "network"
	case se.StatusCode >= 500:
		return "5xx"
	case se.StatusCode >= 400:
		return "4xx"
	}
	return "network"
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) == 0 {
			continue
		}
		if indexOf(s, sub) >= 0 {
			return true
		}
	}
	return false
}

// indexOf is a tiny strings.Index alias — kept inline so this package needs
// no extra imports for the failure classifier.
func indexOf(s, sub string) int {
	n, m := len(s), len(sub)
	if m == 0 {
		return 0
	}
	for i := 0; i+m <= n; i++ {
		if s[i:i+m] == sub {
			return i
		}
	}
	return -1
}

// Reload applies a new config. The `enabled` bit cannot be toggled at
// runtime — see ErrEnableToggleRequiresRestart.
//
// Endpoint or auth change rebuilds the client and cancels the in-flight
// request so the next iteration uses the new credentials.
//
// Interval changes are signalled to the producer via a buffered channel.
// Queue capacity changes apply only to future pushes; existing contents
// are not redistributed.
//
// External label changes naturally take effect on the next produce cycle
// because the producer reads cfg under the read-lock.
func (s *Sender) Reload(newCfg Config) error {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	if newCfg.Enabled != s.cfg.Enabled {
		return ErrEnableToggleRequiresRestart
	}

	changes := diffConfig(s.cfg, newCfg)
	if len(changes) == 0 {
		return nil
	}

	// Endpoint or mTLS material change → full client rebuild.
	rebuildClient := s.cfg.Endpoint != newCfg.Endpoint ||
		!authMaterialEqual(s.cfg.Auth, newCfg.Auth) ||
		s.cfg.Timeout != newCfg.Timeout

	if rebuildClient {
		newClient, err := NewClient(newCfg, s.version)
		if err != nil {
			return fmt.Errorf("rebuild client: %w", err)
		}
		if s.cancelInFlight != nil {
			s.cancelInFlight()
		}
		s.client = newClient
	} else if s.cfg.Auth.Type == newCfg.Auth.Type && newCfg.Auth.Type == "bearer" {
		// Bearer-token rotation: the token file content might have changed
		// even though the path didn't.
		if err := s.client.ReloadAuth(newCfg.Auth); err != nil {
			s.logger.Warn("remote write: reload auth failed; retaining previous credentials", "err", err)
		}
	}

	if s.cfg.Interval != newCfg.Interval {
		select {
		case s.intervalReset <- newCfg.Interval:
		default:
			// Channel buffered size 1; a pending reset is fine — newest wins
			// when the producer picks it up.
		}
	}
	if s.cfg.Queue.MaxSamples != newCfg.Queue.MaxSamples {
		s.logger.Warn("remote write: queue capacity changed; existing entries are not redistributed",
			"old", s.cfg.Queue.MaxSamples, "new", newCfg.Queue.MaxSamples)
	}

	s.cfg = newCfg
	s.auditLog.RemoteWriteConfigReloaded(changes)
	return nil
}

// diffConfig returns a sorted list of human-readable change descriptions.
// Used both for Reload's audit event and to gate work in the no-op case.
func diffConfig(old, new Config) []string {
	var changes []string
	if old.Endpoint != new.Endpoint {
		changes = append(changes, fmt.Sprintf("endpoint: %s → %s", old.Endpoint, new.Endpoint))
	}
	if old.Interval != new.Interval {
		changes = append(changes, fmt.Sprintf("interval: %s → %s", old.Interval, new.Interval))
	}
	if old.Timeout != new.Timeout {
		changes = append(changes, fmt.Sprintf("timeout: %s → %s", old.Timeout, new.Timeout))
	}
	if old.Queue.MaxSamples != new.Queue.MaxSamples {
		changes = append(changes, fmt.Sprintf("queue.max_samples: %d → %d", old.Queue.MaxSamples, new.Queue.MaxSamples))
	}
	if old.Auth.Type != new.Auth.Type {
		changes = append(changes, fmt.Sprintf("auth.type: %s → %s", old.Auth.Type, new.Auth.Type))
	}
	if !authMaterialEqual(old.Auth, new.Auth) && old.Auth.Type == new.Auth.Type {
		changes = append(changes, "auth: credentials rotated")
	}
	if !mapsEqual(old.ExternalLabels, new.ExternalLabels) {
		changes = append(changes, "external_labels: changed")
	}
	sort.Strings(changes)
	return changes
}

// authMaterialEqual reports whether two AuthConfigs reference the same files
// and same username. It does not read the underlying files — content
// rotation is intentional and supported by ReloadAuth/full rebuild.
func authMaterialEqual(a, b AuthConfig) bool {
	return a.Type == b.Type &&
		a.BearerTokenFile == b.BearerTokenFile &&
		a.BasicUsername == b.BasicUsername &&
		a.BasicPasswordFile == b.BasicPasswordFile &&
		a.CACertFile == b.CACertFile &&
		a.ClientCertFile == b.ClientCertFile &&
		a.ClientKeyFile == b.ClientKeyFile
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}
