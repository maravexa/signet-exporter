package remotewrite

import (
	"fmt"
	"math"
	"sort"
	"strconv"

	dto "github.com/prometheus/client_model/go"

	"github.com/maravexa/signet-exporter/internal/remotewrite/prompb"
)

// LabelCollisionError is returned by Convert when an external label key
// matches an existing series label key on the same metric. Operators must
// fix the configuration: silently overriding either value would let the
// "no magic" design commitment slip.
type LabelCollisionError struct {
	Metric        string
	Key           string
	SeriesValue   string
	ExternalValue string
}

// Error implements the error interface.
func (e *LabelCollisionError) Error() string {
	return fmt.Sprintf("remotewrite: external label %q collides with series label on metric %q (series=%q, external=%q)",
		e.Key, e.Metric, e.SeriesValue, e.ExternalValue)
}

// Convert turns gathered metric families into a remote write payload.
// External labels are stamped onto every series. External-label collisions
// with existing series labels are conversion errors, not silent overrides.
//
// One bad family does not poison the whole batch: a collision on family A
// is reported but conversion of family B continues. The first error
// encountered is returned alongside the (partial) WriteRequest so the
// caller can log and increment samples_dropped_total{reason="conversion_error"}.
//
// NaN, +Inf and -Inf sample values are dropped silently per remote write
// convention.
func Convert(families []*dto.MetricFamily, externalLabels map[string]string, timestamp int64) (*prompb.WriteRequest, error) {
	extLabels := externalLabelsToProto(externalLabels)
	wr := &prompb.WriteRequest{}
	var firstErr error

	for _, family := range families {
		series, err := familyToTimeSeries(family, extLabels, timestamp)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		wr.Timeseries = append(wr.Timeseries, series...)
	}
	return wr, firstErr
}

// externalLabelsToProto returns a sorted []prompb.Label from a map. Sorting
// by name keeps Convert deterministic and saves a sort step per series.
func externalLabelsToProto(m map[string]string) []prompb.Label {
	if len(m) == 0 {
		return nil
	}
	out := make([]prompb.Label, 0, len(m))
	for k, v := range m {
		out = append(out, prompb.Label{Name: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// familyToTimeSeries dispatches on metric type and returns one or more
// TimeSeries for a single MetricFamily.
func familyToTimeSeries(family *dto.MetricFamily, externalLabels []prompb.Label, timestamp int64) ([]prompb.TimeSeries, error) {
	if family == nil || family.Name == nil {
		return nil, nil
	}
	name := family.GetName()
	mtype := family.GetType()
	out := make([]prompb.TimeSeries, 0, len(family.Metric))
	var firstErr error

	for _, m := range family.Metric {
		switch mtype {
		case dto.MetricType_GAUGE, dto.MetricType_COUNTER, dto.MetricType_UNTYPED:
			ts, err := simpleToTimeSeries(name, mtype, m, externalLabels, timestamp)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			if ts != nil {
				out = append(out, *ts)
			}
		case dto.MetricType_HISTOGRAM:
			series, err := histogramToTimeSeries(name, m, externalLabels, timestamp)
			if err != nil && firstErr == nil {
				firstErr = err
			}
			out = append(out, series...)
		case dto.MetricType_SUMMARY:
			series, err := summaryToTimeSeries(name, m, externalLabels, timestamp)
			if err != nil && firstErr == nil {
				firstErr = err
			}
			out = append(out, series...)
		default:
			// GAUGE_HISTOGRAM and others — skip silently.
		}
	}
	return out, firstErr
}

// simpleToTimeSeries handles GAUGE / COUNTER / UNTYPED — single sample per metric.
func simpleToTimeSeries(name string, mtype dto.MetricType, m *dto.Metric, externalLabels []prompb.Label, timestamp int64) (*prompb.TimeSeries, error) {
	val, ok := simpleValue(mtype, m)
	if !ok {
		return nil, nil
	}
	if !validSampleValue(val) {
		return nil, nil
	}
	labels, err := buildLabels(name, m.Label, externalLabels, nil, name)
	if err != nil {
		return nil, err
	}
	return &prompb.TimeSeries{
		Labels:  labels,
		Samples: []prompb.Sample{{Value: val, Timestamp: timestamp}},
	}, nil
}

func simpleValue(mtype dto.MetricType, m *dto.Metric) (float64, bool) {
	switch mtype {
	case dto.MetricType_GAUGE:
		if m.Gauge == nil || m.Gauge.Value == nil {
			return 0, false
		}
		return m.Gauge.GetValue(), true
	case dto.MetricType_COUNTER:
		if m.Counter == nil || m.Counter.Value == nil {
			return 0, false
		}
		return m.Counter.GetValue(), true
	case dto.MetricType_UNTYPED:
		if m.Untyped == nil || m.Untyped.Value == nil {
			return 0, false
		}
		return m.Untyped.GetValue(), true
	}
	return 0, false
}

// histogramToTimeSeries expands a histogram into:
//   - <name>_bucket per upper-bound (with le="<bound>"), including +Inf
//   - <name>_sum
//   - <name>_count
func histogramToTimeSeries(name string, m *dto.Metric, externalLabels []prompb.Label, timestamp int64) ([]prompb.TimeSeries, error) {
	if m.Histogram == nil {
		return nil, nil
	}
	h := m.Histogram

	out := make([]prompb.TimeSeries, 0, len(h.Bucket)+3)
	bucketName := name + "_bucket"
	hasInf := false
	for _, b := range h.Bucket {
		if b == nil || b.UpperBound == nil || b.CumulativeCount == nil {
			continue
		}
		bound := b.GetUpperBound()
		if math.IsInf(bound, +1) {
			hasInf = true
		}
		labels, err := buildLabels(bucketName, m.Label, externalLabels,
			[]prompb.Label{{Name: "le", Value: formatBound(bound)}}, name)
		if err != nil {
			return nil, err
		}
		out = append(out, prompb.TimeSeries{
			Labels:  labels,
			Samples: []prompb.Sample{{Value: float64(b.GetCumulativeCount()), Timestamp: timestamp}},
		})
	}
	if !hasInf && h.SampleCount != nil {
		labels, err := buildLabels(bucketName, m.Label, externalLabels,
			[]prompb.Label{{Name: "le", Value: "+Inf"}}, name)
		if err != nil {
			return nil, err
		}
		out = append(out, prompb.TimeSeries{
			Labels:  labels,
			Samples: []prompb.Sample{{Value: float64(h.GetSampleCount()), Timestamp: timestamp}},
		})
	}

	if h.SampleSum != nil && validSampleValue(h.GetSampleSum()) {
		labels, err := buildLabels(name+"_sum", m.Label, externalLabels, nil, name)
		if err != nil {
			return nil, err
		}
		out = append(out, prompb.TimeSeries{
			Labels:  labels,
			Samples: []prompb.Sample{{Value: h.GetSampleSum(), Timestamp: timestamp}},
		})
	}
	if h.SampleCount != nil {
		labels, err := buildLabels(name+"_count", m.Label, externalLabels, nil, name)
		if err != nil {
			return nil, err
		}
		out = append(out, prompb.TimeSeries{
			Labels:  labels,
			Samples: []prompb.Sample{{Value: float64(h.GetSampleCount()), Timestamp: timestamp}},
		})
	}
	return out, nil
}

// summaryToTimeSeries expands a summary into:
//   - <name> per quantile (with quantile="<q>")
//   - <name>_sum
//   - <name>_count
func summaryToTimeSeries(name string, m *dto.Metric, externalLabels []prompb.Label, timestamp int64) ([]prompb.TimeSeries, error) {
	if m.Summary == nil {
		return nil, nil
	}
	s := m.Summary

	out := make([]prompb.TimeSeries, 0, len(s.Quantile)+2)
	for _, q := range s.Quantile {
		if q == nil || q.Quantile == nil || q.Value == nil {
			continue
		}
		val := q.GetValue()
		if !validSampleValue(val) {
			continue
		}
		labels, err := buildLabels(name, m.Label, externalLabels,
			[]prompb.Label{{Name: "quantile", Value: formatBound(q.GetQuantile())}}, name)
		if err != nil {
			return nil, err
		}
		out = append(out, prompb.TimeSeries{
			Labels:  labels,
			Samples: []prompb.Sample{{Value: val, Timestamp: timestamp}},
		})
	}
	if s.SampleSum != nil && validSampleValue(s.GetSampleSum()) {
		labels, err := buildLabels(name+"_sum", m.Label, externalLabels, nil, name)
		if err != nil {
			return nil, err
		}
		out = append(out, prompb.TimeSeries{
			Labels:  labels,
			Samples: []prompb.Sample{{Value: s.GetSampleSum(), Timestamp: timestamp}},
		})
	}
	if s.SampleCount != nil {
		labels, err := buildLabels(name+"_count", m.Label, externalLabels, nil, name)
		if err != nil {
			return nil, err
		}
		out = append(out, prompb.TimeSeries{
			Labels:  labels,
			Samples: []prompb.Sample{{Value: float64(s.GetSampleCount()), Timestamp: timestamp}},
		})
	}
	return out, nil
}

// buildLabels produces the final sorted []prompb.Label for a single series.
//
// Layout: __name__, then series labels (from dto.LabelPair), then any
// type-specific labels (le, quantile), then external labels — but only
// after a collision check between external labels and the union of the
// other three groups. The final slice is sorted lexicographically as
// required by the remote write spec.
//
// metricNameForError is the *family* name reported in collision errors so
// operators can locate the offending family even when emitting a
// _bucket / _sum / _count derived series.
func buildLabels(metricName string, seriesLabels []*dto.LabelPair, externalLabels []prompb.Label, typeLabels []prompb.Label, metricNameForError string) ([]prompb.Label, error) {
	labels := make([]prompb.Label, 0, len(seriesLabels)+len(typeLabels)+len(externalLabels)+1)
	labels = append(labels, prompb.Label{Name: "__name__", Value: metricName})
	for _, p := range seriesLabels {
		if p == nil || p.Name == nil {
			continue
		}
		labels = append(labels, prompb.Label{Name: p.GetName(), Value: p.GetValue()})
	}
	labels = append(labels, typeLabels...)

	// Collision check: external labels must not duplicate any name already present.
	for _, ext := range externalLabels {
		for _, existing := range labels {
			if existing.Name == ext.Name {
				return nil, &LabelCollisionError{
					Metric:        metricNameForError,
					Key:           ext.Name,
					SeriesValue:   existing.Value,
					ExternalValue: ext.Value,
				}
			}
		}
		labels = append(labels, ext)
	}

	sort.Slice(labels, func(i, j int) bool { return labels[i].Name < labels[j].Name })
	return labels, nil
}

// formatBound renders a histogram upper bound or summary quantile in the
// canonical Prometheus text-exposition format. `+Inf` is preserved literally;
// integers are rendered without a decimal point; everything else uses Go's
// shortest accurate float format.
func formatBound(f float64) string {
	switch {
	case math.IsInf(f, +1):
		return "+Inf"
	case math.IsInf(f, -1):
		return "-Inf"
	case math.IsNaN(f):
		return "NaN"
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// validSampleValue reports whether v should be transmitted. NaN / +Inf /
// -Inf are dropped because the remote write spec defines them as stale
// markers; Signet does not emit those, so any occurrence is a bug source
// or a runtime quirk we choose to silence rather than propagate.
func validSampleValue(v float64) bool {
	return !math.IsNaN(v) && !math.IsInf(v, 0)
}
