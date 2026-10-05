package effects

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

type blockingAuditSink struct {
	started chan []Effect
	release chan error
}

func (s *blockingAuditSink) AddBatchChecked(es []Effect) error {
	s.started <- es
	return <-s.release
}

func TestBufferedOwnsEventsAndFlushWaitsForDurability(t *testing.T) {
	sink := &blockingAuditSink{make(chan []Effect, 1), make(chan error, 1)}
	b := NewBufferedAudit(sink, BufferOptions{Interval: time.Hour, BatchSize: 1})
	e := Effect{Kind: "proc.exec", Source: "seccomp", Argv: []string{"original"}}
	if err := b.AddBatchChecked([]Effect{e}); err != nil {
		t.Fatal(err)
	}
	e.Argv[0] = "mutated"
	got := <-sink.started
	if got[0].Argv[0] != "original" || got[0].Time.IsZero() {
		t.Fatalf("did not own event: %+v", got)
	}
	flushed := make(chan error, 1)
	go func() { flushed <- b.Flush() }()
	select {
	case <-flushed:
		t.Fatal("flush acknowledged before durable commit")
	case <-time.After(10 * time.Millisecond):
	}
	sink.release <- nil
	if err := <-flushed; err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBufferedCapacityIncludesInflightAndNeverDrops(t *testing.T) {
	sink := &blockingAuditSink{make(chan []Effect, 2), make(chan error, 2)}
	b := NewBufferedAudit(sink, BufferOptions{Interval: time.Hour, BatchSize: 1, MaxEvents: 1})
	if err := b.AddBatchChecked([]Effect{{Target: "first"}}); err != nil {
		t.Fatal(err)
	}
	<-sink.started
	added := make(chan error, 1)
	go func() { added <- b.AddBatchChecked([]Effect{{Target: "second"}}) }()
	select {
	case <-added:
		t.Fatal("inflight commit escaped queue bound")
	case <-time.After(10 * time.Millisecond):
	}
	sink.release <- nil
	if err := <-added; err != nil {
		t.Fatal(err)
	}
	got := <-sink.started
	if got[0].Target != "second" {
		t.Fatalf("event dropped: %+v", got)
	}
	sink.release <- nil
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	stats := b.Stats()
	if stats.Events != 2 || stats.Commits != 2 || stats.PeakEvents != 1 || stats.Backpressure != 1 {
		t.Fatalf("stats: %+v", stats)
	}
}

func TestBufferedCommitFailureLatchesAndWakesWaiters(t *testing.T) {
	sink := &blockingAuditSink{make(chan []Effect, 1), make(chan error, 1)}
	b := NewBufferedAudit(sink, BufferOptions{Interval: time.Hour, BatchSize: 1, MaxEvents: 1})
	if err := b.AddBatchChecked([]Effect{{Target: "first"}}); err != nil {
		t.Fatal(err)
	}
	<-sink.started
	added := make(chan error, 1)
	go func() { added <- b.AddBatchChecked([]Effect{{Target: "second"}}) }()
	failure := errors.New("disk full")
	sink.release <- failure
	if err := <-added; !errors.Is(err, failure) {
		t.Fatalf("future allow after failure: %v", err)
	}
	if err := b.Flush(); !errors.Is(err, failure) {
		t.Fatalf("flush concealed failure: %v", err)
	}
	if err := b.Close(); !errors.Is(err, failure) {
		t.Fatalf("close concealed failure: %v", err)
	}
}

type collectingAuditSink struct {
	mu     sync.Mutex
	events []Effect
}

func (s *collectingAuditSink) AddBatchChecked(es []Effect) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, es...)
	return nil
}

func TestBufferedCloseDrainsOrderedPrefixAndRejectsOversize(t *testing.T) {
	sink := &collectingAuditSink{}
	b := NewBufferedAudit(sink, BufferOptions{Interval: time.Hour, BatchSize: 64, MaxBytes: 4096})
	if err := b.AddBatchChecked([]Effect{{Target: string(make([]byte, 4096))}}); err == nil {
		t.Fatal("unbounded audit accepted")
	}
	for i := 0; i < 10; i++ {
		if err := b.AddBatchChecked([]Effect{{Target: fmt.Sprint(i)}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if len(sink.events) != 10 {
		t.Fatalf("close lost %d events", 10-len(sink.events))
	}
	for i, e := range sink.events {
		if e.Target != fmt.Sprint(i) {
			t.Fatal("audit order changed")
		}
	}
	if err := b.AddBatchChecked([]Effect{{Target: "after-close"}}); err == nil {
		t.Fatal("enqueue after close")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
}
