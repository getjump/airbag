package effects

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"
)

// BatchSink acknowledges a batch after committing it to durable storage.
type BatchSink interface {
	AddBatchChecked([]Effect) error
}

// BufferOptions bound both the amount of uncommitted audit data and its normal
// batching interval. The interval is a scheduling target, not a durability SLA:
// slow storage can extend it. A full queue applies backpressure, never drops.
type BufferOptions struct {
	Interval    time.Duration
	BatchSize   int
	MaxEvents   int
	MaxBytes    int
	WaitTimeout time.Duration
}

type BufferStats struct {
	Events            uint64 `json:"events"`
	Commits           uint64 `json:"commits"`
	CommitNanoseconds int64  `json:"commit_ns"`
	PeakEvents        int    `json:"peak_events"`
	PeakBytes         int    `json:"peak_bytes"`
	Backpressure      uint64 `json:"backpressure"`
	Failures          uint64 `json:"failures"`
}

type auditBatch struct {
	events   []Effect
	bytes    int
	sequence uint64
}

// BufferedAudit acknowledges an event once a bounded, trusted memory queue owns
// it. Its worker still uses FULL durable commits, but ACK precedes the commit.
// A crash can lose acknowledged events. Flush is a durable prefix barrier;
// security state such as secret taint must cross it before allowing any bytes.
// Errors latch: subsequent enqueue/flush/close fail, without silently dropping
// audit or reverting to an unaudited allow.
type BufferedAudit struct {
	sink                         BatchSink
	opts                         BufferOptions
	mu                           sync.Mutex
	queue                        []auditBatch
	pendingEvents, pendingBytes  int // includes the batch currently committing
	next, committed, flushTarget uint64
	closing                      bool
	err                          error
	changed                      chan struct{}
	wake                         chan struct{}
	done                         chan struct{}
	stats                        BufferStats
}

func NewBufferedAudit(sink BatchSink, opts BufferOptions) *BufferedAudit {
	if opts.Interval <= 0 {
		opts.Interval = 50 * time.Millisecond
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 64
	}
	if opts.MaxEvents <= 0 {
		opts.MaxEvents = 4096
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 8 * 1024 * 1024
	}
	if opts.WaitTimeout <= 0 {
		opts.WaitTimeout = 30 * time.Second
	}
	b := &BufferedAudit{sink: sink, opts: opts, changed: make(chan struct{}), wake: make(chan struct{}, 1), done: make(chan struct{})}
	go b.run()
	return b
}

func (b *BufferedAudit) signalLocked() {
	close(b.changed)
	b.changed = make(chan struct{})
	select {
	case b.wake <- struct{}{}:
	default:
	}
}

func (b *BufferedAudit) AddBatchChecked(events []Effect) error {
	if len(events) == 0 {
		return nil
	}
	owned := make([]Effect, len(events))
	now := time.Now()
	weight := 0
	for i, e := range events {
		e.Argv = slices.Clone(e.Argv)
		e.Predict = slices.Clone(e.Predict)
		if e.Time.IsZero() {
			e.Time = now
		}
		owned[i] = e
		weight += 192 + len(e.Kind) + len(e.Target) + len(e.Verdict) + len(e.Reason) + len(e.Source) + len(e.Detail)
		for _, v := range e.Argv {
			weight += 16 + len(v)
		}
		for _, v := range e.Predict {
			weight += 16 + len(v)
		}
	}
	if len(owned) > b.opts.MaxEvents || weight > b.opts.MaxBytes {
		return fmt.Errorf("runtime audit batch exceeds bounded queue capacity")
	}
	timer := time.NewTimer(b.opts.WaitTimeout)
	defer timer.Stop()
	b.mu.Lock()
	defer b.mu.Unlock()
	waited := false
	for {
		if b.err != nil {
			return b.err
		}
		if b.closing {
			return errors.New("runtime audit is closed")
		}
		if b.pendingEvents+len(owned) <= b.opts.MaxEvents && b.pendingBytes+weight <= b.opts.MaxBytes {
			break
		}
		if !waited {
			b.stats.Backpressure++
			waited = true
		}
		// Flush a partial batch when space is exhausted; waiting for the normal
		// threshold/timer would add avoidable queue latency.
		b.flushTarget = b.next
		b.signalLocked()
		changed := b.changed
		b.mu.Unlock()
		select {
		case <-changed:
		case <-timer.C:
			b.mu.Lock()
			return errors.New("runtime audit queue timeout")
		}
		b.mu.Lock()
	}
	b.next++
	b.queue = append(b.queue, auditBatch{owned, weight, b.next})
	b.pendingEvents += len(owned)
	b.pendingBytes += weight
	b.stats.Events += uint64(len(owned))
	if b.pendingEvents > b.stats.PeakEvents {
		b.stats.PeakEvents = b.pendingEvents
	}
	if b.pendingBytes > b.stats.PeakBytes {
		b.stats.PeakBytes = b.pendingBytes
	}
	b.signalLocked()
	return nil
}

// Flush waits until every event accepted before this call is durably committed.
func (b *BufferedAudit) Flush() error {
	timer := time.NewTimer(b.opts.WaitTimeout)
	defer timer.Stop()
	b.mu.Lock()
	defer b.mu.Unlock()
	target := b.next
	if target > b.flushTarget {
		b.flushTarget = target
	}
	b.signalLocked()
	for b.committed < target && b.err == nil {
		changed := b.changed
		b.mu.Unlock()
		select {
		case <-changed:
		case <-timer.C:
			b.mu.Lock()
			return errors.New("runtime audit flush timeout")
		}
		b.mu.Lock()
	}
	return b.err
}

// Close rejects new events, drains the queue, and reports any persistence error.
func (b *BufferedAudit) Close() error {
	b.mu.Lock()
	b.closing = true
	b.signalLocked()
	b.mu.Unlock()
	<-b.done
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.err
}

func (b *BufferedAudit) Stats() BufferStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stats
}

func (b *BufferedAudit) run() {
	ticker := time.NewTicker(b.opts.Interval)
	defer ticker.Stop()
	defer close(b.done)
	for {
		force := false
		select {
		case <-ticker.C:
			force = true
		case <-b.wake:
		}
		for {
			b.mu.Lock()
			if len(b.queue) == 0 {
				closing := b.closing
				b.mu.Unlock()
				if closing {
					return
				}
				break
			}
			queued := 0
			for _, q := range b.queue {
				queued += len(q.events)
			}
			if !force && !b.closing && queued < b.opts.BatchSize && b.flushTarget <= b.committed {
				b.mu.Unlock()
				break
			}
			var batch []Effect
			weight, n := 0, 0
			for n < len(b.queue) && len(batch) < b.opts.BatchSize {
				q := b.queue[n]
				batch = append(batch, q.events...)
				weight += q.bytes
				n++
			}
			sequence := b.queue[n-1].sequence
			clear(b.queue[:n])
			b.queue = b.queue[n:]
			b.mu.Unlock()
			start := time.Now()
			err := b.sink.AddBatchChecked(batch)
			elapsed := time.Since(start)
			b.mu.Lock()
			b.stats.Commits++
			b.stats.CommitNanoseconds += int64(elapsed)
			if err != nil {
				b.stats.Failures++
				b.err = fmt.Errorf("runtime audit persistence failed: %w", err)
				b.queue = nil
				b.signalLocked()
				b.mu.Unlock()
				return
			}
			b.committed = sequence
			b.pendingEvents -= len(batch)
			b.pendingBytes -= weight
			b.signalLocked()
			b.mu.Unlock()
		}
	}
}
