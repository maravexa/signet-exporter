package remotewrite

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"strconv"
	"strings"
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

	// unreachableAfter is fixed in production and shortened only by focused
	// tests that exercise outage audit transitions.
	unreachableAfter time.Duration

	// lastSeries is owned by the single producer goroutine. It lets remote
	// write explicitly mark a series stale when a subsequent gather no longer
	// emits it. It is advanced only after a batch has been acknowledged by the
	// receiver, so dropped batches retain their stale obligations.
	seriesMu    sync.Mutex
	lastSeries  map[string][]prompb.Label
	deliveryGen uint64 // guarded by cfgMu; changes when endpoint changes
	// deliveryEndpoints retains the label value for a generation long enough
	// to attribute an in-flight old-destination drop correctly after reload.
	deliveryEndpoints map[uint64]string // guarded by cfgMu

	// Cancellation hook for the in-flight HTTP request. Set by the consumer
	// goroutine and called by Reload to abort an in-progress send when
	// endpoint or auth changes. Guarded by cfgMu.
	cancelInFlight context.CancelFunc

	// beforeSend is a test synchronization hook. It is nil in production.
	beforeSend func()
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
		cfg:               cloneConfig(cfg),
		gatherer:          gatherer,
		client:            client,
		queue:             NewQueue(cfg.Queue.MaxSamples),
		metrics:           metrics,
		logger:            logger,
		auditLog:          auditLog,
		version:           version,
		intervalReset:     make(chan time.Duration, 1),
		lastSeries:        make(map[string][]prompb.Label),
		deliveryEndpoints: map[uint64]string{0: cfg.Endpoint},
		unreachableAfter:  unreachableThreshold,
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

	for {
		select {
		case <-ctx.Done():
			return
		case newInterval := <-s.intervalReset:
			ticker.Reset(newInterval)
		case <-ticker.C:
			s.produceOnce()
		}
	}
}

func (s *Sender) produceOnce() {
	families, err := s.gatherer.Gather()
	if err != nil {
		s.logger.Warn("remote write: gather failed", "err", err)
		return
	}

	// Keep the config read lock from snapshot through enqueue. A reload then
	// either drains this old-destination batch, or this producer observes the
	// new destination before it can enqueue anything.
	s.cfgMu.RLock()
	endpoint := s.cfg.Endpoint
	extLabels := s.cfg.ExternalLabels
	generation := s.deliveryGen
	wr, convErr := Convert(families, extLabels, time.Now().UnixMilli())
	if convErr != nil {
		// Convert reports the first collision; we count one sample per
		// dropped family rather than per-collision so we have a meaningful
		// non-zero counter. The caller log is more useful than the metric here.
		s.metrics.SamplesDropped.WithLabelValues(endpoint, "conversion_error").Inc()
		s.logger.Warn("remote write: conversion error", "err", convErr)
		s.cfgMu.RUnlock()
		return
	}

	if wr == nil {
		s.cfgMu.RUnlock()
		return
	}
	dropped := s.queue.PushWithGeneration(wr, generation)
	if dropped > 0 {
		s.metrics.SamplesDropped.WithLabelValues(endpoint, "queue_full").Add(float64(dropped))
	}
	s.metrics.QueueSize.WithLabelValues(endpoint).Set(float64(s.queue.Len()))
	s.cfgMu.RUnlock()
}

// prometheusStaleNaN is the exact IEEE-754 payload Prometheus uses for a
// staleness marker. A generic NaN must not be used: receivers distinguish this
// payload from an invalid sample.
var prometheusStaleNaN = math.Float64frombits(0x7ff0000000000002)

func (s *Sender) addStaleMarkers(wr *prompb.WriteRequest, timestamp int64) {
	if wr == nil {
		wr = &prompb.WriteRequest{}
	}
	current := make(map[string][]prompb.Label, len(wr.Timeseries))
	for i := range wr.Timeseries {
		labels := wr.Timeseries[i].Labels
		current[seriesKey(labels)] = append([]prompb.Label(nil), labels...)
	}
	s.seriesMu.Lock()
	defer s.seriesMu.Unlock()
	for key, labels := range s.lastSeries {
		if _, stillPresent := current[key]; stillPresent {
			continue
		}
		wr.Timeseries = append(wr.Timeseries, prompb.TimeSeries{
			Labels:  append([]prompb.Label(nil), labels...),
			Samples: []prompb.Sample{{Value: prometheusStaleNaN, Timestamp: timestamp}},
		})
	}
}

// acknowledgeSeries records the exact non-stale label sets contained in a
// successfully delivered batch. This is intentionally consumer-owned: a
// queue overflow or endpoint reload must not erase a marker that never made
// it to a receiver.
func (s *Sender) acknowledgeSeries(wr *prompb.WriteRequest) {
	current := make(map[string][]prompb.Label, len(wr.Timeseries))
	for _, ts := range wr.Timeseries {
		if staleOnly(ts.Samples) {
			continue
		}
		current[seriesKey(ts.Labels)] = append([]prompb.Label(nil), ts.Labels...)
	}
	s.seriesMu.Lock()
	s.lastSeries = current
	s.seriesMu.Unlock()
}

func staleOnly(samples []prompb.Sample) bool {
	if len(samples) == 0 {
		return false
	}
	for _, sample := range samples {
		if math.Float64bits(sample.Value) != math.Float64bits(prometheusStaleNaN) {
			return false
		}
	}
	return true
}

func seriesKey(labels []prompb.Label) string {
	var b strings.Builder
	for _, label := range labels {
		b.WriteString(strconv.Itoa(len(label.Name)))
		b.WriteByte(':')
		b.WriteString(label.Name)
		b.WriteString(strconv.Itoa(len(label.Value)))
		b.WriteByte(':')
		b.WriteString(label.Value)
	}
	return b.String()
}

// runConsumer pops one batch at a time. Single-flight to keep semantics
// simple — ordering and retry budget are easier to reason about with one
// in-flight request. Receivers cope with this; Mimir/Cortex/Thanos all
// document expected throughput in samples/sec, not concurrent requests.
func (s *Sender) runConsumer(ctx context.Context) {
	backoff := initialBackoff
	var inFlight *prompb.WriteRequest
	var inFlightGeneration uint64
	var firstFailure time.Time
	startedLogged := false
	unreachableLogged := false
	observabilityGeneration := uint64(0)

	for {
		if ctx.Err() != nil {
			return
		}
		if inFlight == nil {
			req, generation, ok := s.queue.PopWithGeneration(ctx)
			if !ok {
				return
			}
			// Staleness is a receiver-side transition, so compute it against
			// the last batch that this single consumer actually acknowledged.
			// Doing this in the producer is incorrect when multiple snapshots
			// queue ahead of delivery: an intermediate series could otherwise
			// appear at the receiver and never receive a stale marker.
			s.addStaleMarkers(req, time.Now().UnixMilli())
			if len(req.Timeseries) == 0 {
				// An empty snapshot is queued as a control item so disappearance
				// can be evaluated here. With no acknowledged series to retire,
				// there is nothing to send.
				continue
			}
			inFlight = req
			inFlightGeneration = generation
		}
		samples := countSamples(inFlight)

		// Snapshotting a client and registering its cancellation hook must be
		// one exclusive operation. Otherwise Reload could publish a new client
		// in between and return while this consumer still starts an uncancelled
		// request with old credentials or endpoint.
		s.cfgMu.Lock()
		timeout := s.cfg.Timeout
		client := s.client
		endpoint := client.endpoint
		activeGeneration := s.deliveryGen
		if activeGeneration != observabilityGeneration {
			firstFailure = time.Time{}
			startedLogged = false
			unreachableLogged = false
			observabilityGeneration = activeGeneration
		}
		if inFlightGeneration != activeGeneration {
			dropEndpoint := s.deliveryEndpoints[inFlightGeneration]
			s.cfgMu.Unlock()
			if dropEndpoint == "" {
				dropEndpoint = endpoint
			}
			s.metrics.SamplesDropped.WithLabelValues(dropEndpoint, "endpoint_changed").Add(float64(samples))
			s.metrics.QueueSize.WithLabelValues(endpoint).Set(float64(s.queue.Len()))
			inFlight = nil
			continue
		}
		beforeSend := s.beforeSend
		sendCtx, cancel := context.WithTimeout(ctx, timeout)
		s.cancelInFlight = cancel
		s.cfgMu.Unlock()
		if beforeSend != nil {
			beforeSend()
		}

		started := time.Now()
		err := client.Send(sendCtx, inFlight)
		duration := time.Since(started).Seconds()
		cancel()
		s.cfgMu.Lock()
		staleGeneration := inFlightGeneration != s.deliveryGen
		dropEndpoint := s.deliveryEndpoints[inFlightGeneration]
		currentGeneration := s.deliveryGen
		s.cancelInFlight = nil
		s.cfgMu.Unlock()
		if staleGeneration {
			if dropEndpoint == "" {
				dropEndpoint = endpoint
			}
			s.metrics.SamplesDropped.WithLabelValues(dropEndpoint, "endpoint_changed").Add(float64(samples))
			s.metrics.QueueSize.WithLabelValues(endpoint).Set(float64(s.queue.Len()))
			firstFailure = time.Time{}
			startedLogged = false
			unreachableLogged = false
			observabilityGeneration = currentGeneration
			inFlight = nil
			continue
		}

		s.metrics.SendDuration.WithLabelValues(endpoint).Observe(duration)

		if err == nil {
			s.metrics.SamplesSent.WithLabelValues(endpoint).Add(float64(samples))
			s.metrics.LastSuccess.WithLabelValues(endpoint).SetToCurrentTime()
			s.metrics.QueueSize.WithLabelValues(endpoint).Set(float64(s.queue.Len()))
			s.acknowledgeSeries(inFlight)

			if !startedLogged {
				authType := client.auth.Type
				if authType == "" {
					authType = "mtls"
				}
				s.auditLog.RemoteWriteStarted(endpoint, authType)
				startedLogged = true
			}
			if unreachableLogged {
				s.auditLog.RemoteWriteRecovered(endpoint, time.Since(firstFailure))
			}
			firstFailure = time.Time{}
			unreachableLogged = false
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
		} else if !unreachableLogged && time.Since(firstFailure) >= s.unreachableAfter {
			s.auditLog.RemoteWriteEndpointUnreachable(endpoint, time.Since(firstFailure), err.Error())
			unreachableLogged = true
		}
		s.logger.Warn("remote write: send failed; will retry",
			"err", err, "backoff", backoff)

		sleep := backoff
		var se *SendError
		if errors.As(err, &se) && se.RetryAfter > 0 {
			sleep = se.RetryAfter
		}
		retryTimer := time.NewTimer(sleep)
		select {
		case <-ctx.Done():
			retryTimer.Stop()
			return
		case <-retryTimer.C:
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
// request so the next iteration uses the new credentials. Certificate and
// credential files are also re-read on every SIGHUP, even when their paths
// are unchanged, so atomic secret/certificate rotation works as documented.
//
// Interval changes are signalled to the producer via a buffered channel.
// Queue capacity changes take effect immediately. If capacity is reduced,
// oldest queued payloads are evicted until the queue fits the new limit.
//
// External label changes naturally take effect on the next produce cycle.
func (s *Sender) Reload(newCfg Config) error {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	if newCfg.Enabled != s.cfg.Enabled {
		return ErrEnableToggleRequiresRestart
	}

	newCfg = cloneConfig(newCfg)
	changes := diffConfig(s.cfg, newCfg)
	oldEndpoint := s.cfg.Endpoint
	endpointChanged := oldEndpoint != newCfg.Endpoint

	// Clients are immutable after construction. Publishing a complete new
	// client prevents races with Send and means a failed credential rotation
	// leaves both the old client and old config active.
	rebuildClient := endpointChanged ||
		!authMaterialEqual(s.cfg.Auth, newCfg.Auth) ||
		s.cfg.Timeout != newCfg.Timeout ||
		newCfg.Auth.Type == "mtls" || newCfg.Auth.Type == "" ||
		newCfg.Auth.Type == "bearer" || newCfg.Auth.Type == "basic"

	if rebuildClient {
		newClient, err := NewClient(newCfg, s.version)
		if err != nil {
			return fmt.Errorf("rebuild client: %w", err)
		}
		if s.cancelInFlight != nil {
			s.cancelInFlight()
		}
		s.client = newClient
	}
	if endpointChanged {
		// Never forward data produced for one receiver/tenant to another. The
		// consumer generation check covers an item already popped while this
		// reload waited for cfgMu; Clear covers everything still buffered.
		s.deliveryGen++
		s.deliveryEndpoints[s.deliveryGen] = newCfg.Endpoint
		if dropped := s.queue.Clear(); dropped > 0 {
			s.metrics.SamplesDropped.WithLabelValues(oldEndpoint, "endpoint_changed").Add(float64(dropped))
		}
		s.metrics.QueueSize.WithLabelValues(oldEndpoint).Set(0)
		s.seriesMu.Lock()
		s.lastSeries = make(map[string][]prompb.Label)
		s.seriesMu.Unlock()
	}

	if s.cfg.Interval != newCfg.Interval {
		// Keep only the newest requested interval. A plain non-blocking send
		// would retain an older reset when SIGHUP arrives in a burst.
		select {
		case <-s.intervalReset:
		default:
		}
		s.intervalReset <- newCfg.Interval
	}
	if s.cfg.Queue.MaxSamples != newCfg.Queue.MaxSamples {
		dropped := s.queue.SetCapacity(newCfg.Queue.MaxSamples)
		if dropped > 0 {
			s.metrics.SamplesDropped.WithLabelValues(newCfg.Endpoint, "queue_full").Add(float64(dropped))
		}
		s.metrics.QueueSize.WithLabelValues(newCfg.Endpoint).Set(float64(s.queue.Len()))
	}

	s.cfg = newCfg
	if len(changes) > 0 {
		s.auditLog.RemoteWriteConfigReloaded(changes)
	}
	return nil
}

// cloneConfig detaches a Sender's immutable configuration snapshot from the
// YAML decoder and callers. In particular, maps must not be shared with the
// producer goroutine because Convert iterates external labels.
func cloneConfig(cfg Config) Config {
	if cfg.ExternalLabels == nil {
		return cfg
	}
	labels := make(map[string]string, len(cfg.ExternalLabels))
	for k, v := range cfg.ExternalLabels {
		labels[k] = v
	}
	cfg.ExternalLabels = labels
	return cfg
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
