package remotewrite

import (
	"context"
	"sync"

	"github.com/maravexa/signet-exporter/internal/remotewrite/prompb"
)

// Queue is a bounded FIFO of *prompb.WriteRequest payloads, sized by total
// sample count rather than item count — a single push cycle can produce
// thousands of samples, so byte- or item-bounded queues would be operator-hostile.
//
// Drop-oldest on overflow. Thread-safe.
type Queue struct {
	mu          sync.Mutex
	cond        *sync.Cond
	items       []*queueItem
	sampleCount int
	maxSamples  int
	closed      bool
}

type queueItem struct {
	req        *prompb.WriteRequest
	samples    int // pre-counted at enqueue for fast accounting
	generation uint64
}

// NewQueue returns a Queue with the given sample-count capacity.
func NewQueue(maxSamples int) *Queue {
	q := &Queue{maxSamples: maxSamples}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// Push enqueues req and returns the number of samples dropped to make room.
//
//   - If req on its own exceeds capacity, it is rejected and *all* of its
//     samples are reported as dropped — the queue is left unchanged.
//   - Otherwise oldest items are evicted until the new item fits.
//   - The new item's sample count is then added.
//
// Push never blocks. Callers should increment
// signet_remote_write_samples_dropped_total{reason="queue_full"}
// by the returned count.
func (q *Queue) Push(req *prompb.WriteRequest) int {
	return q.PushWithGeneration(req, 0)
}

// PushWithGeneration enqueues req with the remote-write destination generation
// that produced it. Sender uses this to prevent a pre-reload payload from being
// delivered to a newly configured endpoint.
func (q *Queue) PushWithGeneration(req *prompb.WriteRequest, generation uint64) int {
	if req == nil {
		return 0
	}
	samples := countSamples(req)
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return samples
	}
	if samples == 0 {
		// Preserve an empty gather as an ordered control item: the consumer
		// needs it to emit stale markers for the last acknowledged snapshot.
		// Coalesce consecutive empty snapshots so a sample-count-bounded queue
		// cannot grow without bound while the receiver is slow.
		if n := len(q.items); n > 0 && q.items[n-1].samples == 0 && q.items[n-1].generation == generation {
			q.items[n-1].req = req
			return 0
		}
		q.items = append(q.items, &queueItem{req: req, generation: generation})
		q.cond.Signal()
		return 0
	}
	if samples > q.maxSamples {
		// Single payload exceeds total capacity — reject without modifying queue.
		return samples
	}

	dropped := 0
	for q.sampleCount+samples > q.maxSamples && len(q.items) > 0 {
		head := q.items[0]
		dropped += head.samples
		q.sampleCount -= head.samples
		q.items[0] = nil // help GC
		q.items = q.items[1:]
	}

	q.items = append(q.items, &queueItem{req: req, samples: samples, generation: generation})
	q.sampleCount += samples
	q.cond.Signal()
	return dropped
}

// PopWithContext blocks until an item is available, the queue is closed,
// or ctx is cancelled. Returns (nil, false) on close or cancel.
//
// Implementation: a tiny watcher goroutine wakes the cond on ctx.Done so
// the cond.Wait returns even when no Push happens. The watcher exits as
// soon as Pop returns either path.
func (q *Queue) PopWithContext(ctx context.Context) (*prompb.WriteRequest, bool) {
	req, _, ok := q.PopWithGeneration(ctx)
	return req, ok
}

// PopWithGeneration is PopWithContext plus the generation assigned by
// PushWithGeneration. A false result means closed or cancelled.
func (q *Queue) PopWithGeneration(ctx context.Context) (*prompb.WriteRequest, uint64, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Spawn a watcher to broadcast on context cancellation. done channels
	// out of the goroutine so we can stop it once we return.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			q.mu.Lock()
			q.cond.Broadcast()
			q.mu.Unlock()
		case <-done:
		}
	}()

	for len(q.items) == 0 && !q.closed && ctx.Err() == nil {
		q.cond.Wait()
	}
	if ctx.Err() != nil || (q.closed && len(q.items) == 0) {
		return nil, 0, false
	}

	head := q.items[0]
	q.items[0] = nil
	q.items = q.items[1:]
	q.sampleCount -= head.samples
	return head.req, head.generation, true
}

// Len returns the current sample count in the queue.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.sampleCount
}

// Capacity returns the maximum sample count the queue will hold.
func (q *Queue) Capacity() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.maxSamples
}

// SetCapacity changes the sample capacity and returns samples evicted to make
// the current contents fit. Like Push, it drops oldest payloads first. The
// Sender calls this during a validated reload, so maxSamples is always > 0.
func (q *Queue) SetCapacity(maxSamples int) int {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.maxSamples = maxSamples
	dropped := 0
	for q.sampleCount > q.maxSamples && len(q.items) > 0 {
		head := q.items[0]
		dropped += head.samples
		q.sampleCount -= head.samples
		q.items[0] = nil
		q.items = q.items[1:]
	}
	return dropped
}

// Clear discards every queued payload and returns its total sample count.
// It deliberately leaves capacity and closed state unchanged.
func (q *Queue) Clear() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	dropped := q.sampleCount
	for i := range q.items {
		q.items[i] = nil
	}
	q.items = nil
	q.sampleCount = 0
	return dropped
}

// Close marks the queue as closed and wakes any blocked PopWithContext.
// Items already enqueued can still be drained — Pop returns them until
// the queue is empty, then signals close.
func (q *Queue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	q.cond.Broadcast()
}

// countSamples sums Samples across every TimeSeries in the request.
// Defined at package scope so converter and queue can share it cheaply.
func countSamples(req *prompb.WriteRequest) int {
	if req == nil {
		return 0
	}
	n := 0
	for i := range req.Timeseries {
		n += len(req.Timeseries[i].Samples)
	}
	return n
}
