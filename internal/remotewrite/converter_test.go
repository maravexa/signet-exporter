package remotewrite

import (
	"errors"
	"math"
	"sort"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/proto"

	"github.com/maravexa/signet-exporter/internal/remotewrite/prompb"
)

// helper: build a metric family with one or more metrics. Caller composes.
func gaugeFamily(name string, metrics ...*dto.Metric) *dto.MetricFamily {
	t := dto.MetricType_GAUGE
	return &dto.MetricFamily{Name: proto.String(name), Type: &t, Metric: metrics}
}

func counterFamily(name string, metrics ...*dto.Metric) *dto.MetricFamily {
	t := dto.MetricType_COUNTER
	return &dto.MetricFamily{Name: proto.String(name), Type: &t, Metric: metrics}
}

func histogramFamily(name string, metrics ...*dto.Metric) *dto.MetricFamily {
	t := dto.MetricType_HISTOGRAM
	return &dto.MetricFamily{Name: proto.String(name), Type: &t, Metric: metrics}
}

func summaryFamily(name string, metrics ...*dto.Metric) *dto.MetricFamily {
	t := dto.MetricType_SUMMARY
	return &dto.MetricFamily{Name: proto.String(name), Type: &t, Metric: metrics}
}

func gauge(value float64, labels ...string) *dto.Metric {
	return &dto.Metric{
		Label: pairs(labels...),
		Gauge: &dto.Gauge{Value: proto.Float64(value)},
	}
}

func counter(value float64, labels ...string) *dto.Metric {
	return &dto.Metric{
		Label:   pairs(labels...),
		Counter: &dto.Counter{Value: proto.Float64(value)},
	}
}

func pairs(kv ...string) []*dto.LabelPair {
	out := make([]*dto.LabelPair, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, &dto.LabelPair{Name: proto.String(kv[i]), Value: proto.String(kv[i+1])})
	}
	return out
}

// findLabel returns the value of the named label, or "" if absent.
func findLabel(ts prompb.TimeSeries, name string) string {
	for _, l := range ts.Labels {
		if l.Name == name {
			return l.Value
		}
	}
	return ""
}

// labelsSorted reports whether the TimeSeries labels are in lex order.
func labelsSorted(ts prompb.TimeSeries) bool {
	return sort.SliceIsSorted(ts.Labels, func(i, j int) bool {
		return ts.Labels[i].Name < ts.Labels[j].Name
	})
}

func TestConvert_GaugeFamily(t *testing.T) {
	fam := gaugeFamily("signet_up",
		gauge(1, "subnet", "10.0.1.0/24"),
		gauge(0, "subnet", "10.0.2.0/24"),
	)
	wr, err := Convert([]*dto.MetricFamily{fam}, nil, 1234)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(wr.Timeseries) != 2 {
		t.Fatalf("want 2 series, got %d", len(wr.Timeseries))
	}
	for _, ts := range wr.Timeseries {
		if findLabel(ts, "__name__") != "signet_up" {
			t.Errorf("missing __name__ label")
		}
		if len(ts.Samples) != 1 {
			t.Errorf("want 1 sample per series, got %d", len(ts.Samples))
		}
		if ts.Samples[0].Timestamp != 1234 {
			t.Errorf("timestamp not stamped: got %d", ts.Samples[0].Timestamp)
		}
		if !labelsSorted(ts) {
			t.Errorf("labels not sorted: %+v", ts.Labels)
		}
	}
}

func TestConvert_CounterFamily(t *testing.T) {
	fam := counterFamily("signet_scan_total", counter(42))
	wr, err := Convert([]*dto.MetricFamily{fam}, nil, 0)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(wr.Timeseries) != 1 {
		t.Fatalf("want 1 series, got %d", len(wr.Timeseries))
	}
	if findLabel(wr.Timeseries[0], "__name__") != "signet_scan_total" {
		t.Errorf("counter __name__ should be preserved as-is (no _total stripping)")
	}
	if wr.Timeseries[0].Samples[0].Value != 42 {
		t.Errorf("counter value: got %v", wr.Timeseries[0].Samples[0].Value)
	}
}

func TestConvert_HistogramFamily_ExpandsBuckets(t *testing.T) {
	h := &dto.Metric{
		Label: pairs("op", "scan"),
		Histogram: &dto.Histogram{
			SampleCount: proto.Uint64(7),
			SampleSum:   proto.Float64(3.5),
			Bucket: []*dto.Bucket{
				{UpperBound: proto.Float64(0.1), CumulativeCount: proto.Uint64(2)},
				{UpperBound: proto.Float64(1.0), CumulativeCount: proto.Uint64(5)},
				{UpperBound: proto.Float64(math.Inf(+1)), CumulativeCount: proto.Uint64(7)},
			},
		},
	}
	fam := histogramFamily("signet_scan_seconds", h)
	wr, err := Convert([]*dto.MetricFamily{fam}, nil, 0)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	// 3 buckets (incl +Inf) + _sum + _count = 5
	if len(wr.Timeseries) != 5 {
		t.Fatalf("want 5 series, got %d", len(wr.Timeseries))
	}
	infFound := false
	for _, ts := range wr.Timeseries {
		if findLabel(ts, "le") == "+Inf" {
			infFound = true
		}
		if !labelsSorted(ts) {
			t.Errorf("labels not sorted: %+v", ts.Labels)
		}
	}
	if !infFound {
		t.Errorf("+Inf bucket missing")
	}
}

func TestConvert_HistogramFamily_AddsImplicitInf(t *testing.T) {
	h := &dto.Metric{
		Histogram: &dto.Histogram{
			SampleCount: proto.Uint64(10),
			SampleSum:   proto.Float64(5),
			Bucket: []*dto.Bucket{
				{UpperBound: proto.Float64(1), CumulativeCount: proto.Uint64(7)},
			},
		},
	}
	fam := histogramFamily("h_metric", h)
	wr, err := Convert([]*dto.MetricFamily{fam}, nil, 0)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	infFound := false
	for _, ts := range wr.Timeseries {
		if findLabel(ts, "le") == "+Inf" && ts.Samples[0].Value == 10 {
			infFound = true
		}
	}
	if !infFound {
		t.Errorf("implicit +Inf bucket should be derived from SampleCount")
	}
}

func TestConvert_SummaryFamily_ExpandsQuantiles(t *testing.T) {
	s := &dto.Metric{
		Summary: &dto.Summary{
			SampleCount: proto.Uint64(100),
			SampleSum:   proto.Float64(50),
			Quantile: []*dto.Quantile{
				{Quantile: proto.Float64(0.5), Value: proto.Float64(0.42)},
				{Quantile: proto.Float64(0.99), Value: proto.Float64(2.1)},
			},
		},
	}
	fam := summaryFamily("s_metric", s)
	wr, err := Convert([]*dto.MetricFamily{fam}, nil, 0)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	// 2 quantiles + _sum + _count = 4
	if len(wr.Timeseries) != 4 {
		t.Fatalf("want 4 series, got %d", len(wr.Timeseries))
	}
}

func TestConvert_ExternalLabelsStamped(t *testing.T) {
	fam := gaugeFamily("g", gauge(1, "subnet", "10.0.1.0/24"))
	ext := map[string]string{
		"cluster": "edge-dc1",
		"region":  "us-west-2",
	}
	wr, err := Convert([]*dto.MetricFamily{fam}, ext, 0)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	ts := wr.Timeseries[0]
	if findLabel(ts, "cluster") != "edge-dc1" {
		t.Errorf("cluster ext label missing")
	}
	if findLabel(ts, "region") != "us-west-2" {
		t.Errorf("region ext label missing")
	}
	if !labelsSorted(ts) {
		t.Errorf("labels not sorted: %+v", ts.Labels)
	}
}

func TestConvert_LabelCollision_ReturnsError(t *testing.T) {
	fam := gaugeFamily("g", gauge(1, "instance", "signet-01"))
	ext := map[string]string{"instance": "operator-supplied"}
	wr, err := Convert([]*dto.MetricFamily{fam}, ext, 0)
	if err == nil {
		t.Fatal("expected collision error")
	}
	var collision *LabelCollisionError
	if !errors.As(err, &collision) {
		t.Fatalf("expected *LabelCollisionError, got %T: %v", err, err)
	}
	if collision.Key != "instance" {
		t.Errorf("collision key: got %q", collision.Key)
	}
	// The colliding family must NOT appear in the output, but the WriteRequest
	// is still returned so the caller can keep converting other families.
	if wr == nil {
		t.Fatal("WriteRequest should be non-nil even on collision")
	}
	if len(wr.Timeseries) != 0 {
		t.Errorf("colliding family should be omitted, got %d series", len(wr.Timeseries))
	}
}

func TestConvert_LabelCollision_OtherFamiliesStillConverted(t *testing.T) {
	bad := gaugeFamily("bad", gauge(1, "cluster", "x"))
	good := gaugeFamily("good", gauge(2, "subnet", "10.0.1.0/24"))
	ext := map[string]string{"cluster": "ext"}
	wr, err := Convert([]*dto.MetricFamily{bad, good}, ext, 0)
	if err == nil {
		t.Fatal("expected collision error from bad family")
	}
	if len(wr.Timeseries) != 1 {
		t.Fatalf("good family should be converted; got %d series", len(wr.Timeseries))
	}
	if findLabel(wr.Timeseries[0], "__name__") != "good" {
		t.Errorf("unexpected family in output")
	}
}

func TestConvert_NaNAndInfDropped(t *testing.T) {
	fam := gaugeFamily("g",
		gauge(math.NaN()),
		gauge(math.Inf(+1)),
		gauge(math.Inf(-1)),
		gauge(1.23),
	)
	wr, err := Convert([]*dto.MetricFamily{fam}, nil, 0)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(wr.Timeseries) != 1 {
		t.Errorf("want 1 valid sample after NaN/Inf drop, got %d", len(wr.Timeseries))
	}
}

func TestFormatBound(t *testing.T) {
	cases := map[float64]string{
		math.Inf(+1): "+Inf",
		math.Inf(-1): "-Inf",
		1.0:          "1",
		0.5:          "0.5",
		1e-9:         "1e-09",
	}
	for in, want := range cases {
		if got := formatBound(in); got != want {
			t.Errorf("formatBound(%v)=%q want %q", in, got, want)
		}
	}
}
