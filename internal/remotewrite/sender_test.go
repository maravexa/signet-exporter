package remotewrite

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/snappy"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/proto"

	"github.com/maravexa/signet-exporter/internal/audit"
	"github.com/maravexa/signet-exporter/internal/remotewrite/prompb"
	"github.com/maravexa/signet-exporter/internal/tlsutil"
)

// stubGatherer returns the same canned MetricFamily list on every Gather call.
type stubGatherer struct{ families []*dto.MetricFamily }

func (s *stubGatherer) Gather() ([]*dto.MetricFamily, error) { return s.families, nil }

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// gatherFamily builds a single-gauge family for a Sender to scrape.
func gatherFamily() []*dto.MetricFamily {
	g := &dto.MetricFamily{
		Name: proto.String("signet_test"),
		Type: func() *dto.MetricType { t := dto.MetricType_GAUGE; return &t }(),
		Metric: []*dto.Metric{
			{Gauge: &dto.Gauge{Value: proto.Float64(42)}},
		},
	}
	return []*dto.MetricFamily{g}
}

// newTestSender wires a Sender to a test server with auth=none and a tight
// interval. The returned cleanup cancels the run context.
func newTestSender(t *testing.T, srvURL string, opts ...func(*Config)) (*Sender, *Metrics, context.CancelFunc) {
	t.Helper()
	cfg := Config{
		Enabled:        true,
		Endpoint:       srvURL,
		Interval:       100 * time.Millisecond,
		Timeout:        50 * time.Millisecond,
		Queue:          QueueConfig{MaxSamples: 1000, Overflow: "drop_oldest"},
		Auth:           AuthConfig{Type: "none"},
		ExternalLabels: map[string]string{"cluster": "test"},
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	metrics := NewMetrics()
	if err := metrics.Register(prometheus.NewRegistry()); err != nil {
		t.Fatalf("register: %v", err)
	}
	gatherer := &stubGatherer{families: gatherFamily()}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sender, err := NewSender(cfg, gatherer, metrics, logger, audit.Disabled(), "test")
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = sender.Run(ctx) }()
	return sender, metrics, cancel
}

func TestSender_HappyPath_PushesToReceiver(t *testing.T) {
	var pushes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		decompressed, err := snappy.Decode(nil, body)
		if err != nil {
			t.Errorf("snappy: %v", err)
		}
		var wr prompb.WriteRequest
		if err := wr.Unmarshal(decompressed); err != nil {
			t.Errorf("unmarshal: %v", err)
		}
		// Verify external label was stamped.
		found := false
		for _, ts := range wr.Timeseries {
			for _, l := range ts.Labels {
				if l.Name == "cluster" && l.Value == "test" {
					found = true
				}
			}
		}
		if !found {
			t.Errorf("external label not stamped on series")
		}
		pushes.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, metrics, cancel := newTestSender(t, srv.URL)
	defer cancel()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if pushes.Load() >= 1 && readCounterVec(metrics.SamplesSent, srv.URL) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if pushes.Load() == 0 {
		t.Fatal("receiver never got a request")
	}
	// SamplesSent should be > 0 for our endpoint label.
	if got := readCounterVec(metrics.SamplesSent, srv.URL); got == 0 {
		t.Errorf("samples_sent_total: want > 0, got %v", got)
	}
}

func TestSender_5xxRetries(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, _, cancel := newTestSender(t, srv.URL, func(c *Config) {
		c.Interval = 100 * time.Millisecond
	})
	defer cancel()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if attempts.Load() >= 3 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if attempts.Load() < 3 {
		t.Fatalf("expected at least 3 attempts, got %d", attempts.Load())
	}
}

func TestSender_4xxDropped(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	_, metrics, cancel := newTestSender(t, srv.URL)
	defer cancel()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if attempts.Load() >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got := readCounterVecLabels(metrics.SamplesDropped, srv.URL, "fatal_response"); got == 0 {
		t.Errorf("samples_dropped_total{reason=fatal_response} should be > 0")
	}
}

func TestSender_Reload_EnableToggleRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sender, _, cancel := newTestSender(t, srv.URL)
	defer cancel()

	sender.cfgMu.RLock()
	newCfg := sender.cfg
	sender.cfgMu.RUnlock()
	newCfg.Enabled = false
	if err := sender.Reload(newCfg); err != ErrEnableToggleRequiresRestart {
		t.Errorf("expected ErrEnableToggleRequiresRestart, got %v", err)
	}
}

func TestSender_Reload_NoChangesIsNoop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sender, _, cancel := newTestSender(t, srv.URL)
	defer cancel()

	sender.cfgMu.RLock()
	cfg := sender.cfg
	sender.cfgMu.RUnlock()
	if err := sender.Reload(cfg); err != nil {
		t.Errorf("reload identical config: %v", err)
	}
}

func TestSender_ReloadRotatesSamePathBearerCredential(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("old-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := Config{
		Enabled:  true,
		Endpoint: srv.URL,
		Interval: time.Second,
		Timeout:  500 * time.Millisecond,
		Queue:    QueueConfig{MaxSamples: 10, Overflow: "drop_oldest"},
		Auth:     AuthConfig{Type: "bearer", BearerTokenFile: tokenPath},
	}
	sender, err := NewSender(cfg, &stubGatherer{families: gatherFamily()}, NewMetrics(), nil, audit.Disabled(), "test")
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	sender.cfgMu.RLock()
	oldClient := sender.client
	sender.cfgMu.RUnlock()
	if err := oldClient.Send(context.Background(), sampleRequest()); err != nil {
		t.Fatalf("old client Send: %v", err)
	}
	if authorization, _ := got.Load().(string); authorization != "Bearer old-token" {
		t.Fatalf("old authorization = %q", authorization)
	}

	if err := os.WriteFile(tokenPath, []byte("new-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sender.Reload(cfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	sender.cfgMu.RLock()
	newClient := sender.client
	sender.cfgMu.RUnlock()
	if newClient == oldClient {
		t.Fatal("same-path bearer rotation did not publish a new immutable client")
	}
	if err := newClient.Send(context.Background(), sampleRequest()); err != nil {
		t.Fatalf("new client Send: %v", err)
	}
	if authorization, _ := got.Load().(string); authorization != "Bearer new-token" {
		t.Fatalf("new authorization = %q", authorization)
	}
}

func TestSender_ReloadSamePathMTLSKeepsOldClientOnInvalidRotation(t *testing.T) {
	dir := t.TempDir()
	if err := tlsutil.GenerateCerts(dir); err != nil {
		t.Fatalf("GenerateCerts: %v", err)
	}
	cfg := Config{
		Enabled:  true,
		Endpoint: "https://receiver.example.invalid/api/v1/write",
		Interval: time.Second,
		Timeout:  500 * time.Millisecond,
		Queue:    QueueConfig{MaxSamples: 10, Overflow: "drop_oldest"},
		Auth: AuthConfig{
			Type:           "mtls",
			CACertFile:     filepath.Join(dir, "ca.pem"),
			ClientCertFile: filepath.Join(dir, "client.pem"),
			ClientKeyFile:  filepath.Join(dir, "client-key.pem"),
		},
	}
	sender, err := NewSender(cfg, &stubGatherer{families: gatherFamily()}, NewMetrics(), nil, audit.Disabled(), "test")
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	sender.cfgMu.RLock()
	oldClient := sender.client
	sender.cfgMu.RUnlock()
	if err := sender.Reload(cfg); err != nil {
		t.Fatalf("same-path mTLS Reload: %v", err)
	}
	sender.cfgMu.RLock()
	rotatedClient := sender.client
	sender.cfgMu.RUnlock()
	if rotatedClient == oldClient {
		t.Fatal("same-path mTLS rotation did not publish a new immutable client")
	}

	if err := os.WriteFile(cfg.Auth.ClientCertFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := sender.Reload(cfg); err == nil {
		t.Fatal("Reload with invalid same-path certificate unexpectedly succeeded")
	}
	sender.cfgMu.RLock()
	defer sender.cfgMu.RUnlock()
	if sender.client != rotatedClient {
		t.Fatal("failed certificate rotation replaced the active client")
	}
}

func TestSender_ReloadKeepsClientOnExpiredCertificateRotation(t *testing.T) {
	dir := t.TempDir()
	if err := tlsutil.GenerateCerts(dir); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Enabled: true, Endpoint: "https://receiver.example.invalid/api/v1/write", Interval: time.Second, Timeout: 500 * time.Millisecond,
		Queue: QueueConfig{MaxSamples: 10, Overflow: "drop_oldest"}, Auth: AuthConfig{
			Type:       "mtls",
			CACertFile: filepath.Join(dir, "ca.pem"), ClientCertFile: filepath.Join(dir, "client.pem"), ClientKeyFile: filepath.Join(dir, "client-key.pem"),
		},
	}
	sender, err := NewSender(cfg, &stubGatherer{families: gatherFamily()}, NewMetrics(), nil, audit.Disabled(), "test")
	if err != nil {
		t.Fatal(err)
	}
	sender.cfgMu.RLock()
	oldClient := sender.client
	sender.cfgMu.RUnlock()
	writeClientCertWithValidity(t, cfg.Auth.ClientCertFile, cfg.Auth.ClientKeyFile, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	if err := sender.Reload(cfg); err == nil {
		t.Fatal("expired client certificate reload unexpectedly succeeded")
	}
	sender.cfgMu.RLock()
	defer sender.cfgMu.RUnlock()
	if sender.client != oldClient {
		t.Fatal("expired certificate rotation replaced active client")
	}
}

func writeClientCertWithValidity(t *testing.T, certPath, keyPath string, notBefore, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-client"},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSender_ReloadPublishesNewEndpointAndExternalLabels(t *testing.T) {
	var first, second atomic.Int32
	serverOne := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		first.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer serverOne.Close()
	serverTwo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		second.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer serverTwo.Close()

	sender, metrics, cancel := newTestSender(t, serverOne.URL)
	defer cancel()
	deadline := time.Now().Add(2 * time.Second)
	for first.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if first.Load() == 0 {
		t.Fatal("first endpoint was not used")
	}

	sender.cfgMu.RLock()
	newCfg := sender.cfg
	sender.cfgMu.RUnlock()
	newCfg.Endpoint = serverTwo.URL
	newCfg.ExternalLabels = map[string]string{"cluster": "reloaded"}
	if err := sender.Reload(newCfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	deadline = time.Now().Add(2 * time.Second)
	// Receiving the request precedes the client processing its response and
	// publishing the success metric; wait for both observations.
	for (second.Load() == 0 || readCounterVec(metrics.SamplesSent, serverTwo.URL) == 0) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if second.Load() == 0 {
		t.Fatal("reloaded endpoint was not used")
	}
	if got := readCounterVec(metrics.SamplesSent, serverTwo.URL); got == 0 {
		t.Errorf("new endpoint samples_sent_total = %v, want > 0", got)
	}
}

func TestSender_ReloadConcurrentWithRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	sender, _, cancel := newTestSender(t, srv.URL)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for n := 0; n < 50; n++ {
				sender.cfgMu.RLock()
				cfg := sender.cfg
				sender.cfgMu.RUnlock()
				cfg.Interval = time.Duration(100+i+n%2) * time.Millisecond
				cfg.ExternalLabels = map[string]string{"cluster": "race-test"}
				if err := sender.Reload(cfg); err != nil {
					t.Errorf("Reload: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

func TestSender_ReloadCancelsClientSnapshottedBeforeSend(t *testing.T) {
	cfg := Config{
		Enabled:  true,
		Endpoint: "http://old.example.invalid/write",
		Interval: time.Second,
		Timeout:  time.Second,
		Queue:    QueueConfig{MaxSamples: 10, Overflow: "drop_oldest"},
		Auth:     AuthConfig{Type: "none"},
	}
	sender, err := NewSender(cfg, &stubGatherer{families: gatherFamily()}, NewMetrics(), nil, audit.Disabled(), "test")
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}

	snapshotted := make(chan struct{})
	releaseSend := make(chan struct{})
	oldAttempted := make(chan struct{})
	var uncancelled atomic.Int32
	sender.cfgMu.Lock()
	sender.client = &Client{
		httpClient: &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			if r.Context().Err() == nil {
				uncancelled.Add(1)
			}
			close(oldAttempted)
			return nil, r.Context().Err()
		})},
		endpoint: cfg.Endpoint,
		auth:     AuthConfig{Type: "none"},
	}
	sender.beforeSend = func() {
		close(snapshotted)
		<-releaseSend
	}
	sender.cfgMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		sender.runConsumer(ctx)
		close(done)
	}()
	sender.queue.Push(sampleRequest())
	<-snapshotted

	newCfg := cfg
	newCfg.Endpoint = "http://new.example.invalid/write"
	if err := sender.Reload(newCfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	close(releaseSend)
	select {
	case <-oldAttempted:
	case <-time.After(time.Second):
		t.Fatal("old client never observed its cancelled context")
	}
	if got := uncancelled.Load(); got != 0 {
		t.Fatalf("Reload returned before old send was cancelled; uncancelled sends=%d", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("consumer did not stop")
	}
}

func TestSender_ReloadEndpointDropsOldDestinationBatches(t *testing.T) {
	var newEndpointCalls atomic.Int32
	serverTwo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		newEndpointCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer serverTwo.Close()

	cfg := Config{
		Enabled: true, Endpoint: "http://old.example.invalid/write", Interval: time.Second, Timeout: time.Second,
		Queue: QueueConfig{MaxSamples: 10, Overflow: "drop_oldest"}, Auth: AuthConfig{Type: "none"},
	}
	metrics := NewMetrics()
	sender, err := NewSender(cfg, &stubGatherer{families: gatherFamily()}, metrics, nil, audit.Disabled(), "test")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	sender.cfgMu.Lock()
	sender.client = &Client{httpClient: &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}, endpoint: cfg.Endpoint, auth: AuthConfig{Type: "none"}}
	sender.cfgMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { sender.runConsumer(ctx); close(done) }()
	// One batch is in flight and one remains buffered when the endpoint moves.
	sender.queue.PushWithGeneration(sampleRequest(), 0)
	sender.queue.PushWithGeneration(sampleRequest(), 0)
	<-started

	newCfg := cfg
	newCfg.Endpoint = serverTwo.URL
	if err := sender.Reload(newCfg); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	// This is the first payload created for the new receiver generation.
	sender.queue.PushWithGeneration(sampleRequest(), 1)
	deadline := time.Now().Add(time.Second)
	for newEndpointCalls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if newEndpointCalls.Load() != 1 {
		t.Fatalf("new endpoint calls = %d, want exactly one new-generation batch", newEndpointCalls.Load())
	}
	if got := readCounterVecLabels(metrics.SamplesDropped, cfg.Endpoint, "endpoint_changed"); got != 2 {
		t.Errorf("old endpoint endpoint_changed drops = %v, want 2", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("consumer did not stop")
	}
}

func TestSender_ProducesStaleMarkerForDisappearedSeries(t *testing.T) {
	cfg := Config{
		Enabled:        true,
		Endpoint:       "http://receiver.example.invalid/write",
		Interval:       time.Second,
		Timeout:        time.Second,
		Queue:          QueueConfig{MaxSamples: 10, Overflow: "drop_oldest"},
		Auth:           AuthConfig{Type: "none"},
		ExternalLabels: map[string]string{"cluster": "test"},
	}
	gatherer := &stubGatherer{families: gatherFamily()}
	sender, err := NewSender(cfg, gatherer, NewMetrics(), nil, audit.Disabled(), "test")
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	sender.produceOnce()
	first, ok := sender.queue.PopWithContext(context.Background())
	if !ok {
		t.Fatal("first gathered series was not queued")
	}
	// Staleness is only advanced after receiver acknowledgement. Simulate that
	// acknowledgement before the next gather removes the series.
	sender.acknowledgeSeries(first)

	gatherer.families = nil
	sender.produceOnce()
	stale, ok := sender.queue.PopWithContext(context.Background())
	sender.addStaleMarkers(stale, time.Now().UnixMilli())
	if !ok || len(stale.Timeseries) != 1 {
		t.Fatalf("stale batch = %#v, want one series", stale)
	}
	sample := stale.Timeseries[0].Samples[0]
	if bits := math.Float64bits(sample.Value); bits != math.Float64bits(prometheusStaleNaN) {
		t.Errorf("stale sample bits = %#x, want %#x", bits, math.Float64bits(prometheusStaleNaN))
	}
}

func TestSender_RegeneratesStaleMarkerAfterDroppedBatch(t *testing.T) {
	cfg := Config{
		Enabled: true, Endpoint: "http://receiver.example.invalid/write", Interval: time.Second, Timeout: time.Second,
		Queue: QueueConfig{MaxSamples: 10, Overflow: "drop_oldest"}, Auth: AuthConfig{Type: "none"},
	}
	gatherer := &stubGatherer{families: gatherFamily()}
	sender, err := NewSender(cfg, gatherer, NewMetrics(), nil, audit.Disabled(), "test")
	if err != nil {
		t.Fatal(err)
	}
	sender.produceOnce()
	first, ok := sender.queue.PopWithContext(context.Background())
	if !ok {
		t.Fatal("initial batch was not queued")
	}
	sender.acknowledgeSeries(first)
	gatherer.families = nil
	sender.produceOnce()
	if dropped := sender.queue.Clear(); dropped != 0 {
		t.Fatalf("dropped empty snapshot samples = %d, want 0", dropped)
	}
	// Since the empty snapshot was never delivered, the next clean gather must
	// still retire the last acknowledged series at the delivery boundary.
	sender.produceOnce()
	stale, ok := sender.queue.PopWithContext(context.Background())
	sender.addStaleMarkers(stale, time.Now().UnixMilli())
	if !ok || len(stale.Timeseries) != 1 || math.Float64bits(stale.Timeseries[0].Samples[0].Value) != math.Float64bits(prometheusStaleNaN) {
		t.Fatalf("regenerated stale batch = %#v", stale)
	}
}

func TestSender_QueuedSnapshotsComputeStalenessAtDelivery(t *testing.T) {
	requests := make(chan *prompb.WriteRequest, 3)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		decoded, err := snappy.Decode(nil, body)
		if err != nil {
			t.Errorf("snappy decode: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var wr prompb.WriteRequest
		if err := wr.Unmarshal(decoded); err != nil {
			t.Errorf("unmarshal: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requests <- &wr
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := Config{
		Enabled: true, Endpoint: srv.URL, Interval: time.Second, Timeout: time.Second,
		Queue: QueueConfig{MaxSamples: 10, Overflow: "drop_oldest"}, Auth: AuthConfig{Type: "none"},
	}
	sender, err := NewSender(cfg, &stubGatherer{}, NewMetrics(), nil, audit.Disabled(), "test")
	if err != nil {
		t.Fatal(err)
	}
	namedRequest := func(name string) *prompb.WriteRequest {
		return &prompb.WriteRequest{Timeseries: []prompb.TimeSeries{{
			Labels:  []prompb.Label{{Name: "__name__", Value: name}},
			Samples: []prompb.Sample{{Value: 1, Timestamp: time.Now().UnixMilli()}},
		}}}
	}
	for _, name := range []string{"a", "b", "c"} {
		sender.queue.PushWithGeneration(namedRequest(name), 0)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sender.runConsumer(ctx); close(done) }()
	got := make([]*prompb.WriteRequest, 0, 3)
	for len(got) < 3 {
		select {
		case wr := <-requests:
			got = append(got, wr)
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for delivered snapshots")
		}
	}
	cancel()
	<-done

	assertTransition := func(index int, current, retired string) {
		t.Helper()
		seenCurrent, seenStale := false, false
		for _, ts := range got[index].Timeseries {
			name := ""
			for _, label := range ts.Labels {
				if label.Name == "__name__" {
					name = label.Value
				}
			}
			if name == current && !staleOnly(ts.Samples) {
				seenCurrent = true
			}
			if name == retired && staleOnly(ts.Samples) {
				seenStale = true
			}
		}
		if !seenCurrent || !seenStale {
			t.Fatalf("delivery %d missing transition %s -> %s: %#v", index, retired, current, got[index])
		}
	}
	assertTransition(1, "b", "a")
	assertTransition(2, "c", "b")
}

func TestSender_IdenticalOutageEmitsOneUnreachableAndOneRecoveryAuditEvent(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	auditLog, err := audit.NewLogger(audit.Config{Enabled: true, Output: path})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = auditLog.Close() }()
	cfg := Config{
		Enabled:  true,
		Endpoint: srv.URL,
		Interval: 20 * time.Millisecond,
		Timeout:  10 * time.Millisecond,
		Queue:    QueueConfig{MaxSamples: 100, Overflow: "drop_oldest"},
		Auth:     AuthConfig{Type: "none"},
	}
	sender, err := NewSender(cfg, &stubGatherer{families: gatherFamily()}, NewMetrics(), nil, auditLog, "test")
	if err != nil {
		t.Fatal(err)
	}
	sender.unreachableAfter = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = sender.Run(ctx); close(done) }()

	deadline := time.Now().Add(5 * time.Second)
	for attempts.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if attempts.Load() < 3 {
		t.Fatalf("receiver attempts = %d, want at least 3", attempts.Load())
	}
	cancel()
	<-done
	if err := auditLog.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(data), `"event_type":"remote_write_endpoint_unreachable"`); got != 1 {
		t.Errorf("unreachable audit event count = %d, want 1", got)
	}
	if got := strings.Count(string(data), `"event_type":"remote_write_recovered"`); got != 1 {
		t.Errorf("recovered audit event count = %d, want 1", got)
	}
}

// readCounterVec reads the value of a CounterVec for the given endpoint label.
// Used to verify metrics emitted by the Sender.
func readCounterVec(c *prometheus.CounterVec, endpoint string) float64 {
	m, err := c.GetMetricWithLabelValues(endpoint)
	if err != nil {
		return 0
	}
	var d dto.Metric
	if err := m.Write(&d); err != nil {
		return 0
	}
	return d.Counter.GetValue()
}

func readCounterVecLabels(c *prometheus.CounterVec, lbls ...string) float64 {
	m, err := c.GetMetricWithLabelValues(lbls...)
	if err != nil {
		return 0
	}
	var d dto.Metric
	if err := m.Write(&d); err != nil {
		return 0
	}
	return d.Counter.GetValue()
}
