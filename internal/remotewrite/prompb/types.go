// Copyright 2017 The Prometheus Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package prompb is a hand-rolled subset of github.com/prometheus/prometheus/prompb
// for signet-exporter, retaining only the message types needed for Prometheus
// Remote Write protocol v1: WriteRequest, TimeSeries, Sample, Label.
//
// trimmed: Exemplar, Histogram, BucketSpan, MetricMetadata, ReadRequest,
// trimmed: ReadResponse, Query, QueryResult, ChunkedReadResponse, Chunk,
// trimmed: ReadHints, the v2 symbol-table types (Request, Symbols), all
// trimmed: enum metric-type values, and all generated descriptor machinery.
//
// Wire format matches the upstream proto3 definitions exactly so this
// package is compatible with any conformant remote-write receiver
// (Prometheus, Mimir, Cortex, Thanos receive, Grafana Cloud).
package prompb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Sample is a single metric sample at a point in time.
//
// proto:
//
//	message Sample {
//	    double value     = 1;
//	    int64  timestamp = 2;
//	}
type Sample struct {
	Value     float64
	Timestamp int64
}

// Reset zeroes the Sample.
func (s *Sample) Reset() { *s = Sample{} }

// String returns a human-readable rendering. Used for debug logging only.
func (s *Sample) String() string {
	return fmt.Sprintf("Sample{Value:%g, Timestamp:%d}", s.Value, s.Timestamp)
}

// ProtoMessage tags Sample as a generated protobuf message type. No-op.
func (*Sample) ProtoMessage() {}

// Label is a name/value label pair. Names must conform to Prometheus label
// name regex; values are arbitrary UTF-8.
//
// proto:
//
//	message Label {
//	    string name  = 1;
//	    string value = 2;
//	}
type Label struct {
	Name  string
	Value string
}

// Reset zeroes the Label.
func (l *Label) Reset() { *l = Label{} }

// String returns a human-readable rendering.
func (l *Label) String() string {
	return fmt.Sprintf("Label{Name:%q, Value:%q}", l.Name, l.Value)
}

// ProtoMessage tags Label as a generated protobuf message type. No-op.
func (*Label) ProtoMessage() {}

// TimeSeries is a sorted-label series carrying one or more samples.
// Labels MUST be sorted lexicographically by name (remote write spec).
//
// proto:
//
//	message TimeSeries {
//	    repeated Label  labels  = 1;
//	    repeated Sample samples = 2;
//	}
type TimeSeries struct {
	Labels  []Label
	Samples []Sample
}

// Reset zeroes the TimeSeries.
func (t *TimeSeries) Reset() { *t = TimeSeries{} }

// String returns a human-readable rendering.
func (t *TimeSeries) String() string {
	return fmt.Sprintf("TimeSeries{Labels:%d, Samples:%d}", len(t.Labels), len(t.Samples))
}

// ProtoMessage tags TimeSeries as a generated protobuf message type. No-op.
func (*TimeSeries) ProtoMessage() {}

// WriteRequest is the body of a Prometheus remote-write request,
// snappy-framed and POSTed to the receiver endpoint.
//
// proto:
//
//	message WriteRequest {
//	    repeated TimeSeries timeseries = 1;
//	    // metadata field 3 omitted — Signet does not emit metadata yet.
//	}
type WriteRequest struct {
	Timeseries []TimeSeries
}

// Reset zeroes the WriteRequest.
func (w *WriteRequest) Reset() { *w = WriteRequest{} }

// String returns a human-readable rendering.
func (w *WriteRequest) String() string {
	return fmt.Sprintf("WriteRequest{Timeseries:%d}", len(w.Timeseries))
}

// ProtoMessage tags WriteRequest as a generated protobuf message type. No-op.
func (*WriteRequest) ProtoMessage() {}

// ----- protobuf wire encoding ----------------------------------------------
//
// Wire types used here:
//   0 = varint            (int32, int64, uint64, bool, enum)
//   1 = 64-bit fixed      (fixed64, sfixed64, double)
//   2 = length-delimited  (string, bytes, embedded message, packed repeated)

const (
	wireVarint  = 0
	wireFixed64 = 1
	wireBytes   = 2
)

// tag returns the wire-format tag byte sequence for (fieldNumber, wireType).
// All field numbers used here are < 16 so a single byte suffices.
func tag(fieldNumber, wireType int) byte {
	return byte(fieldNumber<<3 | wireType)
}

// appendVarint appends x to buf in little-endian base-128 varint encoding.
func appendVarint(buf []byte, x uint64) []byte {
	for x >= 0x80 {
		buf = append(buf, byte(x)|0x80)
		x >>= 7
	}
	return append(buf, byte(x))
}

// varintSize returns the number of bytes the varint encoding of x occupies.
func varintSize(x uint64) int {
	n := 1
	for x >= 0x80 {
		x >>= 7
		n++
	}
	return n
}

// ----- Marshal / Size --------------------------------------------------------

// Size returns the marshaled size of the Sample in bytes.
func (s *Sample) Size() int {
	// value: 1-byte tag + 8 bytes (fixed64). Always encoded for explicitness;
	// proto3 would normally omit zero, but receivers accept either form.
	// timestamp: 1-byte tag + varint of int64.
	return 1 + 8 + 1 + varintSize(uint64(s.Timestamp)) //nolint:gosec // proto3 int64 round-trips through uint64 by design
}

// MarshalTo serializes the Sample into buf and returns the number of bytes
// written. buf MUST have capacity >= s.Size().
func (s *Sample) MarshalTo(buf []byte) (int, error) {
	i := 0
	buf[i] = tag(1, wireFixed64)
	i++
	binary.LittleEndian.PutUint64(buf[i:i+8], math.Float64bits(s.Value))
	i += 8
	buf[i] = tag(2, wireVarint)
	i++
	tmp := appendVarint(buf[i:i], uint64(s.Timestamp)) //nolint:gosec // proto3 int64 round-trips through uint64 by design
	i += len(tmp)
	return i, nil
}

// Marshal returns the wire-encoded form of the Sample.
func (s *Sample) Marshal() ([]byte, error) {
	buf := make([]byte, s.Size())
	n, err := s.MarshalTo(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// Size returns the marshaled size of the Label in bytes.
func (l *Label) Size() int {
	n := 0
	if len(l.Name) > 0 {
		n += 1 + varintSize(uint64(len(l.Name))) + len(l.Name)
	}
	if len(l.Value) > 0 {
		n += 1 + varintSize(uint64(len(l.Value))) + len(l.Value)
	}
	return n
}

// MarshalTo serializes the Label into buf.
func (l *Label) MarshalTo(buf []byte) (int, error) {
	i := 0
	if len(l.Name) > 0 {
		buf[i] = tag(1, wireBytes)
		i++
		tmp := appendVarint(buf[i:i], uint64(len(l.Name)))
		i += len(tmp)
		i += copy(buf[i:], l.Name)
	}
	if len(l.Value) > 0 {
		buf[i] = tag(2, wireBytes)
		i++
		tmp := appendVarint(buf[i:i], uint64(len(l.Value)))
		i += len(tmp)
		i += copy(buf[i:], l.Value)
	}
	return i, nil
}

// Marshal returns the wire-encoded form of the Label.
func (l *Label) Marshal() ([]byte, error) {
	buf := make([]byte, l.Size())
	n, err := l.MarshalTo(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// Size returns the marshaled size of the TimeSeries in bytes.
func (t *TimeSeries) Size() int {
	n := 0
	for i := range t.Labels {
		sz := t.Labels[i].Size()
		n += 1 + varintSize(uint64(sz)) + sz //nolint:gosec // sz is the result of a Size() call; always non-negative
	}
	for i := range t.Samples {
		sz := t.Samples[i].Size()
		n += 1 + varintSize(uint64(sz)) + sz //nolint:gosec // sz is the result of a Size() call; always non-negative
	}
	return n
}

// MarshalTo serializes the TimeSeries into buf.
func (t *TimeSeries) MarshalTo(buf []byte) (int, error) {
	i := 0
	for li := range t.Labels {
		sz := t.Labels[li].Size()
		buf[i] = tag(1, wireBytes)
		i++
		tmp := appendVarint(buf[i:i], uint64(sz)) //nolint:gosec // sz is the result of a Size() call; always non-negative
		i += len(tmp)
		n, err := t.Labels[li].MarshalTo(buf[i : i+sz])
		if err != nil {
			return 0, err
		}
		i += n
	}
	for si := range t.Samples {
		sz := t.Samples[si].Size()
		buf[i] = tag(2, wireBytes)
		i++
		tmp := appendVarint(buf[i:i], uint64(sz)) //nolint:gosec // sz is the result of a Size() call; always non-negative
		i += len(tmp)
		n, err := t.Samples[si].MarshalTo(buf[i : i+sz])
		if err != nil {
			return 0, err
		}
		i += n
	}
	return i, nil
}

// Marshal returns the wire-encoded form of the TimeSeries.
func (t *TimeSeries) Marshal() ([]byte, error) {
	buf := make([]byte, t.Size())
	n, err := t.MarshalTo(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// Size returns the marshaled size of the WriteRequest in bytes.
func (w *WriteRequest) Size() int {
	n := 0
	for i := range w.Timeseries {
		sz := w.Timeseries[i].Size()
		n += 1 + varintSize(uint64(sz)) + sz //nolint:gosec // sz is the result of a Size() call; always non-negative
	}
	return n
}

// MarshalTo serializes the WriteRequest into buf.
func (w *WriteRequest) MarshalTo(buf []byte) (int, error) {
	i := 0
	for ti := range w.Timeseries {
		sz := w.Timeseries[ti].Size()
		buf[i] = tag(1, wireBytes)
		i++
		tmp := appendVarint(buf[i:i], uint64(sz)) //nolint:gosec // sz is the result of a Size() call; always non-negative
		i += len(tmp)
		n, err := w.Timeseries[ti].MarshalTo(buf[i : i+sz])
		if err != nil {
			return 0, err
		}
		i += n
	}
	return i, nil
}

// Marshal returns the wire-encoded form of the WriteRequest.
func (w *WriteRequest) Marshal() ([]byte, error) {
	buf := make([]byte, w.Size())
	n, err := w.MarshalTo(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// ----- Unmarshal -------------------------------------------------------------
//
// Unmarshal exists primarily for round-trip testing. The receiver in
// production is the Prometheus remote-write endpoint; Signet never decodes
// its own WriteRequests at runtime.

// errTruncated is returned when the wire bytes end mid-field.
var errTruncated = errors.New("prompb: truncated message")

// readVarint decodes a single varint from data starting at offset and returns
// (value, new offset, error).
func readVarint(data []byte, off int) (uint64, int, error) {
	var x uint64
	var shift uint
	for i := 0; i < 10; i++ {
		if off >= len(data) {
			return 0, 0, errTruncated
		}
		b := data[off]
		off++
		x |= uint64(b&0x7f) << shift
		if b < 0x80 {
			return x, off, nil
		}
		shift += 7
	}
	return 0, 0, fmt.Errorf("prompb: varint overflow")
}

// readTag splits a wire-format tag byte into (fieldNumber, wireType, newOffset).
func readTag(data []byte, off int) (int, int, int, error) {
	t, off, err := readVarint(data, off)
	if err != nil {
		return 0, 0, 0, err
	}
	// Field numbers and wire types are bounded — the >>3 shift caps fieldNumber
	// at 2^61-1 in theory, but valid protobuf encodings keep it < 2^29 and our
	// hand-rolled receivers only care about field numbers 1–2.
	return int(t >> 3), int(t & 0x7), off, nil //nolint:gosec
}

// skipField advances past an unknown field of the given wire type.
func skipField(data []byte, off, wireType int) (int, error) {
	switch wireType {
	case wireVarint:
		_, off, err := readVarint(data, off)
		return off, err
	case wireFixed64:
		if off+8 > len(data) {
			return 0, errTruncated
		}
		return off + 8, nil
	case wireBytes:
		n, off, err := readVarint(data, off)
		if err != nil {
			return 0, err
		}
		end := off + int(n) //nolint:gosec // n is bounded by len(data) via the truncation check below
		if end > len(data) {
			return 0, errTruncated
		}
		return end, nil
	}
	return 0, fmt.Errorf("prompb: unsupported wire type %d", wireType)
}

// Unmarshal parses the wire bytes into the Sample.
func (s *Sample) Unmarshal(data []byte) error {
	*s = Sample{}
	off := 0
	for off < len(data) {
		fn, wt, next, err := readTag(data, off)
		if err != nil {
			return err
		}
		off = next
		switch fn {
		case 1:
			if wt != wireFixed64 || off+8 > len(data) {
				return errTruncated
			}
			s.Value = math.Float64frombits(binary.LittleEndian.Uint64(data[off : off+8]))
			off += 8
		case 2:
			if wt != wireVarint {
				return fmt.Errorf("prompb: Sample.timestamp: unexpected wire type %d", wt)
			}
			v, next, err := readVarint(data, off)
			if err != nil {
				return err
			}
			s.Timestamp = int64(v) //nolint:gosec // proto3 int64 round-trips through uint64 by design
			off = next
		default:
			off, err = skipField(data, off, wt)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// Unmarshal parses the wire bytes into the Label.
func (l *Label) Unmarshal(data []byte) error {
	*l = Label{}
	off := 0
	for off < len(data) {
		fn, wt, next, err := readTag(data, off)
		if err != nil {
			return err
		}
		off = next
		if wt != wireBytes {
			off, err = skipField(data, off, wt)
			if err != nil {
				return err
			}
			continue
		}
		n, next, err := readVarint(data, off)
		if err != nil {
			return err
		}
		off = next
		end := off + int(n) //nolint:gosec // n is bounded by len(data) via the truncation check below
		if end > len(data) {
			return errTruncated
		}
		switch fn {
		case 1:
			l.Name = string(data[off:end])
		case 2:
			l.Value = string(data[off:end])
		}
		off = end
	}
	return nil
}

// Unmarshal parses the wire bytes into the TimeSeries.
func (t *TimeSeries) Unmarshal(data []byte) error {
	*t = TimeSeries{}
	off := 0
	for off < len(data) {
		fn, wt, next, err := readTag(data, off)
		if err != nil {
			return err
		}
		off = next
		if wt != wireBytes {
			off, err = skipField(data, off, wt)
			if err != nil {
				return err
			}
			continue
		}
		n, next, err := readVarint(data, off)
		if err != nil {
			return err
		}
		off = next
		end := off + int(n) //nolint:gosec // n is bounded by len(data) via the truncation check below
		if end > len(data) {
			return errTruncated
		}
		switch fn {
		case 1:
			var lbl Label
			if err := lbl.Unmarshal(data[off:end]); err != nil {
				return err
			}
			t.Labels = append(t.Labels, lbl)
		case 2:
			var s Sample
			if err := s.Unmarshal(data[off:end]); err != nil {
				return err
			}
			t.Samples = append(t.Samples, s)
		}
		off = end
	}
	return nil
}

// Unmarshal parses the wire bytes into the WriteRequest.
func (w *WriteRequest) Unmarshal(data []byte) error {
	*w = WriteRequest{}
	off := 0
	for off < len(data) {
		fn, wt, next, err := readTag(data, off)
		if err != nil {
			return err
		}
		off = next
		if wt != wireBytes {
			off, err = skipField(data, off, wt)
			if err != nil {
				return err
			}
			continue
		}
		n, next, err := readVarint(data, off)
		if err != nil {
			return err
		}
		off = next
		end := off + int(n) //nolint:gosec // n is bounded by len(data) via the truncation check below
		if end > len(data) {
			return errTruncated
		}
		if fn == 1 {
			var ts TimeSeries
			if err := ts.Unmarshal(data[off:end]); err != nil {
				return err
			}
			w.Timeseries = append(w.Timeseries, ts)
		}
		off = end
	}
	return nil
}
