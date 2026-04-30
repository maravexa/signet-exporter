package remotewrite

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics groups every observability counter / gauge / histogram emitted by
// the remote write subsystem itself. The Sender reads these on each iteration
// of its producer / consumer loops; they are exposed on the same /metrics
// endpoint that hosts the rest of the exporter so operators can scrape both
// host inventory and remote-write health from a single target.
type Metrics struct {
	SamplesSent    *prometheus.CounterVec
	SamplesDropped *prometheus.CounterVec
	SendDuration   *prometheus.HistogramVec
	LastSuccess    *prometheus.GaugeVec
	Failures       *prometheus.CounterVec
	QueueSize      *prometheus.GaugeVec
}

// NewMetrics constructs the metric vectors with the names and label sets
// documented in CLAUDE.md / signet.example.yaml. Nothing is registered yet —
// the caller passes a Registerer to Register.
func NewMetrics() *Metrics {
	return &Metrics{
		SamplesSent: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "signet_remote_write_samples_sent_total",
			Help: "Total number of samples successfully sent to the remote write endpoint.",
		}, []string{"endpoint"}),

		SamplesDropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "signet_remote_write_samples_dropped_total",
			Help: "Total number of samples dropped before delivery. reason: queue_full | conversion_error | fatal_response.",
		}, []string{"endpoint", "reason"}),

		SendDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "signet_remote_write_send_duration_seconds",
			Help:    "Duration of remote write HTTP send operations.",
			Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
		}, []string{"endpoint"}),

		LastSuccess: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "signet_remote_write_last_success_timestamp",
			Help: "Unix timestamp of the most recent successful remote write request.",
		}, []string{"endpoint"}),

		Failures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "signet_remote_write_failures_total",
			Help: "Total number of failed remote write requests. reason: 4xx | 5xx | network | timeout.",
		}, []string{"endpoint", "reason"}),

		QueueSize: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "signet_remote_write_queue_size",
			Help: "Current number of samples buffered in the remote write queue.",
		}, []string{"endpoint"}),
	}
}

// Register registers all metric vectors with reg. Returns the first error
// encountered. The exporter treats registration failure as fatal: a
// duplicate-name collision means another collector clashes, which would
// produce inconsistent scrape output.
func (m *Metrics) Register(reg prometheus.Registerer) error {
	for _, c := range []prometheus.Collector{
		m.SamplesSent,
		m.SamplesDropped,
		m.SendDuration,
		m.LastSuccess,
		m.Failures,
		m.QueueSize,
	} {
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}
