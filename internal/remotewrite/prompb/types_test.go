package prompb

import (
	"math"
	"testing"
)

func TestSampleRoundTrip(t *testing.T) {
	cases := []Sample{
		{Value: 0, Timestamp: 0},
		{Value: 1.5, Timestamp: 1234567890123},
		{Value: -42.5, Timestamp: -1},
		{Value: math.Pi, Timestamp: math.MaxInt64},
	}
	for _, in := range cases {
		buf, err := in.Marshal()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var out Sample
		if err := out.Unmarshal(buf); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if out != in {
			t.Errorf("round-trip mismatch: got %+v want %+v", out, in)
		}
	}
}

func TestLabelRoundTrip(t *testing.T) {
	cases := []Label{
		{Name: "__name__", Value: "signet_up"},
		{Name: "instance", Value: "signet-01"},
		{Name: "with_unicode", Value: "café-ünikœde"},
		{Name: "empty_value", Value: ""},
	}
	for _, in := range cases {
		buf, err := in.Marshal()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var out Label
		if err := out.Unmarshal(buf); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if out != in {
			t.Errorf("round-trip mismatch: got %+v want %+v", out, in)
		}
	}
}

func TestTimeSeriesRoundTrip(t *testing.T) {
	in := TimeSeries{
		Labels: []Label{
			{Name: "__name__", Value: "signet_up"},
			{Name: "subnet", Value: "10.0.1.0/24"},
		},
		Samples: []Sample{
			{Value: 1, Timestamp: 1},
			{Value: 0, Timestamp: 60_000},
			{Value: 1, Timestamp: 120_000},
		},
	}
	buf, err := in.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out TimeSeries
	if err := out.Unmarshal(buf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Labels) != len(in.Labels) || len(out.Samples) != len(in.Samples) {
		t.Fatalf("shape mismatch: got %d labels / %d samples, want %d / %d",
			len(out.Labels), len(out.Samples), len(in.Labels), len(in.Samples))
	}
	for i, l := range in.Labels {
		if out.Labels[i] != l {
			t.Errorf("label[%d]: got %+v want %+v", i, out.Labels[i], l)
		}
	}
	for i, s := range in.Samples {
		if out.Samples[i] != s {
			t.Errorf("sample[%d]: got %+v want %+v", i, out.Samples[i], s)
		}
	}
}

func TestWriteRequestRoundTrip(t *testing.T) {
	in := WriteRequest{
		Timeseries: []TimeSeries{
			{
				Labels:  []Label{{Name: "__name__", Value: "metric_a"}},
				Samples: []Sample{{Value: 1, Timestamp: 100}},
			},
			{
				Labels:  []Label{{Name: "__name__", Value: "metric_b"}, {Name: "instance", Value: "i1"}},
				Samples: []Sample{{Value: 2, Timestamp: 200}, {Value: 3, Timestamp: 300}},
			},
		},
	}
	buf, err := in.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out WriteRequest
	if err := out.Unmarshal(buf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Timeseries) != 2 {
		t.Fatalf("expected 2 timeseries, got %d", len(out.Timeseries))
	}
	if out.Timeseries[0].Samples[0].Value != 1 {
		t.Errorf("first sample value: got %v", out.Timeseries[0].Samples[0].Value)
	}
	if out.Timeseries[1].Samples[1].Timestamp != 300 {
		t.Errorf("nested timestamp: got %v", out.Timeseries[1].Samples[1].Timestamp)
	}
}

func TestSizeMatchesMarshal(t *testing.T) {
	wr := WriteRequest{
		Timeseries: []TimeSeries{
			{
				Labels:  []Label{{Name: "__name__", Value: "x"}, {Name: "y", Value: "z"}},
				Samples: []Sample{{Value: 1.5, Timestamp: 100}},
			},
		},
	}
	buf, err := wr.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if wr.Size() != len(buf) {
		t.Errorf("Size()=%d, but Marshal produced %d bytes", wr.Size(), len(buf))
	}
}
