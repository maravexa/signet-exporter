package remotewrite

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/snappy"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/proto"

	"github.com/maravexa/signet-exporter/internal/audit"
	"github.com/maravexa/signet-exporter/internal/remotewrite/prompb"
)

// stubGatherer returns the same canned MetricFamily list on every Gather call.
type stubGatherer struct{ families []*dto.MetricFamily }

func (s *stubGatherer) Gather() ([]*dto.MetricFamily, error) { return s.families, nil }

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
		if pushes.Load() >= 1 {
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

	newCfg := sender.cfg
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

	if err := sender.Reload(sender.cfg); err != nil {
		t.Errorf("reload identical config: %v", err)
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
