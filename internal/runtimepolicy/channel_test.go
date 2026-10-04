package runtimepolicy

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/policy"
)

func TestRuntimeChannelCommitsAndFailsClosed(t *testing.T) {
	dir := t.TempDir()
	p, err := policy.Load(dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	log, err := effects.Open(filepath.Join(dir, "effects.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	server, peer := net.Pipe()
	defer peer.Close()
	go func() { _ = Serve(server, policy.NewGate(p, dir), log) }()
	client := NewClient(peer)
	if err := client.Check(Request{Source: "fuse", Kind: "fs.write", Target: "/work/file", PID: 42}); err != nil {
		t.Fatal(err)
	}
	events, err := effects.Read(filepath.Join(dir, "effects.db"))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Source != "fuse" || events[0].PID != 42 {
		t.Fatalf("missing committed context: %+v", events)
	}
	if err := client.Check(Request{Source: "seccomp", Kind: "proc.exec.invalid", Detail: "bad pointer", PID: 43}); err == nil {
		t.Fatal("unreadable exec was allowed")
	}
	log.Close()
	if err := client.Check(Request{Source: "fuse", Kind: "fs.read", Target: "/work/file", PID: 42}); err == nil {
		t.Fatal("allow after audit failure")
	}
	peer.Close()
	if err := client.Check(Request{Source: "fuse", Kind: "fs.read", Target: "/work/file"}); err == nil {
		t.Fatal("allow after disconnection")
	}
}

func TestConcurrentChecksCommitBeforeReturning(t *testing.T) {
	dir := t.TempDir()
	p, err := policy.Load(dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "effects.db")
	log, err := effects.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	server, peer := net.Pipe()
	defer peer.Close()
	go func() { _ = Serve(server, policy.NewGate(p, dir), log) }()
	client := NewClient(peer)
	const workers = 96 // exceeds the bounded in-flight window
	start := make(chan struct{})
	errors := make(chan error, workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			<-start
			errors <- client.CheckBatch([]Request{{Source: "fuse", Kind: "fs.read", Target: fmt.Sprint(i), PID: uint32(i + 1)}, {Source: "fuse", Kind: "fs.write", Target: fmt.Sprint(i), PID: uint32(i + 1)}})
		}(i)
	}
	close(start)
	for i := 0; i < workers; i++ {
		if err := <-errors; err != nil {
			t.Fatal(err)
		}
	}
	events, err := effects.Read(path)
	if err != nil || len(events) != workers*2 {
		t.Fatalf("lost events: %d %v", len(events), err)
	}
	seen := map[string]bool{}
	for i := 0; i < len(events); i += 2 {
		a, b := events[i], events[i+1]
		if a.Target != b.Target || a.PID != b.PID || a.Kind != "fs.read" || b.Kind != "fs.write" || seen[a.Target] {
			t.Fatalf("interleaved/duplicate operation: %+v %+v", a, b)
		}
		seen[a.Target] = true
	}
	// A later check in one operation cannot undo a denial, and is not evaluated.
	if err := client.CheckBatch([]Request{{Source: "fuse", Kind: "fs.read", Target: "prefix"}, {Source: "seccomp", Kind: "proc.exec.invalid", Detail: "unreadable"}, {Source: "fuse", Kind: "fs.write", Target: "must-not-run"}}); err == nil {
		t.Fatal("batch denial lost")
	}
	events, err = effects.Read(path)
	if err != nil || len(events) != workers*2+2 || events[len(events)-1].Verdict != "deny" {
		t.Fatalf("denial prefix: %d %v", len(events), err)
	}
}

func TestClientMatchesOutOfOrderReplies(t *testing.T) {
	server, peer := net.Pipe()
	defer server.Close()
	defer peer.Close()
	client := NewClient(peer)
	done := make(chan error, 2)
	go func() { done <- client.Check(Request{Source: "fuse", Kind: "fs.read", Target: "allowed"}) }()
	go func() { done <- client.Check(Request{Source: "fuse", Kind: "fs.read", Target: "denied"}) }()
	// Read both before replying: a client-wide request mutex would deadlock here.
	server.SetDeadline(time.Now().Add(3 * time.Second))
	dec, enc := json.NewDecoder(server), json.NewEncoder(server)
	var a, b frame
	if err := dec.Decode(&a); err != nil {
		t.Fatal(err)
	}
	if err := dec.Decode(&b); err != nil {
		t.Fatal(err)
	}
	for _, f := range []frame{b, a} {
		if err := enc.Encode(response{ID: f.ID, Allow: f.Requests[0].Target == "allowed", Message: f.Requests[0].Target}); err != nil {
			t.Fatal(err)
		}
	}
	n := 0
	for i := 0; i < 2; i++ {
		if <-done != nil {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("wrong number of denials: %d", n)
	}
}
