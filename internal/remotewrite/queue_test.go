package remotewrite

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/maravexa/signet-exporter/internal/remotewrite/prompb"
)

// reqWith builds a WriteRequest containing n synthetic samples across one series.
func reqWith(n int) *prompb.WriteRequest {
	samples := make([]prompb.Sample, n)
	for i := range samples {
		samples[i] = prompb.Sample{Value: float64(i), Timestamp: int64(i)}
	}
	return &prompb.WriteRequest{
		Timeseries: []prompb.TimeSeries{{
			Labels:  []prompb.Label{{Name: "__name__", Value: "x"}},
			Samples: samples,
		}},
	}
}

func TestQueue_PushAndPop(t *testing.T) {
	q := NewQueue(100)
	if dropped := q.Push(reqWith(10)); dropped != 0 {
		t.Errorf("dropped: got %d", dropped)
	}
	if l := q.Len(); l != 10 {
		t.Errorf("len: got %d want 10", l)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, ok := q.PopWithContext(ctx)
	if !ok {
		t.Fatal("pop returned !ok")
	}
	if countSamples(got) != 10 {
		t.Errorf("expected 10 samples in popped batch, got %d", countSamples(got))
	}
	if l := q.Len(); l != 0 {
		t.Errorf("len after pop: got %d want 0", l)
	}
}

func TestQueue_DropOldestOnOverflow(t *testing.T) {
	q := NewQueue(20)
	// First push: 15 samples, fits.
	if dropped := q.Push(reqWith(15)); dropped != 0 {
		t.Errorf("first push: dropped=%d want 0", dropped)
	}
	// Second push: 10 samples, total would be 25, exceeds 20. Must drop the
	// oldest 15-sample batch (dropped=15) to fit.
	if dropped := q.Push(reqWith(10)); dropped != 15 {
		t.Errorf("second push: dropped=%d want 15", dropped)
	}
	if l := q.Len(); l != 10 {
		t.Errorf("len: got %d want 10", l)
	}
}

func TestQueue_RejectOversizedSinglePush(t *testing.T) {
	q := NewQueue(50)
	dropped := q.Push(reqWith(100))
	if dropped != 100 {
		t.Errorf("oversized push should report all 100 samples dropped, got %d", dropped)
	}
	if l := q.Len(); l != 0 {
		t.Errorf("queue should be empty: got %d", l)
	}
}

func TestQueue_PopWithContext_CancelUnblocks(t *testing.T) {
	q := NewQueue(100)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_, _ = q.PopWithContext(ctx)
		close(done)
	}()

	// Cancel before any push; Pop must return promptly.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("PopWithContext did not return after ctx cancel")
	}
}

func TestQueue_Close_UnblocksPop(t *testing.T) {
	q := NewQueue(100)
	done := make(chan struct{})
	go func() {
		_, ok := q.PopWithContext(context.Background())
		if ok {
			t.Errorf("Pop after close should return ok=false")
		}
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	q.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Pop did not unblock on Close")
	}
}

func TestQueue_ConcurrentPushPop(t *testing.T) {
	q := NewQueue(10000)
	var wg sync.WaitGroup
	wg.Add(2)
	const N = 50

	go func() {
		defer wg.Done()
		for i := 0; i < N; i++ {
			q.Push(reqWith(5))
		}
	}()

	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for i := 0; i < N; i++ {
			if _, ok := q.PopWithContext(ctx); !ok {
				t.Errorf("pop %d returned !ok", i)
				return
			}
		}
	}()

	wg.Wait()
}
