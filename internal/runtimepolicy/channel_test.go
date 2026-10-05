package runtimepolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/policy"
)

type testBufferedSink struct {
	log     *effects.Log
	gate    *policy.Gate
	queued  []effects.Effect
	fail    error
	flushed bool
}

func (s *testBufferedSink) AddBatchChecked(batch []effects.Effect) error {
	if s.fail != nil {
		err := s.fail
		s.fail = nil // a recovered sink must not recover this runtime channel
		return err
	}
	s.queued = append(s.queued, batch...)
	return nil
}

func (s *testBufferedSink) Flush() error {
	s.flushed = true
	return s.log.AddBatchChecked(s.queued)
}

func TestBufferedSecretStillCommitsBeforeAllow(t *testing.T) {
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
	defer func() { _ = log.Close() }()
	gate := policy.NewGate(p, dir)
	sink := &testBufferedSink{log: log, gate: gate}
	profile := &Profile{}
	server, peer := net.Pipe()
	defer peer.Close()
	go func() { _ = ServeWithOptions(server, gate, log, Options{Audit: sink, Profile: profile}) }()
	client := NewClient(peer)
	if err := client.Check(Request{Source: "fuse", Kind: "fs.read", Target: "ordinary"}); err != nil {
		t.Fatal(err)
	}
	events, err := effects.Read(path)
	if err != nil || len(events) != 0 {
		t.Fatalf("buffered event was already committed: %+v %v", events, err)
	}
	if err := client.Check(Request{Source: "fuse", Kind: "secret.read", Target: "credential", Secret: true}); err != nil {
		t.Fatal(err)
	}
	events, err = effects.Read(path)
	if err != nil || len(events) != 2 || events[0].Target != "ordinary" || events[1].Target != "credential" {
		t.Fatalf("secret barrier lost ordering or persistence: %+v %v", events, err)
	}
	if !sink.flushed || gate.Tainted() != "credential" {
		t.Fatal("secret barrier did not flush and taint")
	}
	if got := profile.Snapshot().Metrics["runtime.audit.durable"].Count; got != 1 {
		t.Fatalf("durable commits %d, want 1", got)
	}
}

func TestBufferedAuditFailureRemainsClosed(t *testing.T) {
	dir := t.TempDir()
	p, err := policy.Load(dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	log, err := effects.Open(filepath.Join(dir, "effects.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	server, peer := net.Pipe()
	defer peer.Close()
	diskError := errors.New("disk error")
	sink := &testBufferedSink{fail: diskError}
	served := make(chan error, 1)
	go func() { served <- ServeWithOptions(server, policy.NewGate(p, dir), log, Options{Audit: sink}) }()
	client := NewClient(peer)
	for i := 0; i < 2; i++ {
		if err := client.Check(Request{Source: "fuse", Kind: "fs.write", Target: "file"}); err == nil {
			t.Fatal("audit failure recovered into an allow")
		}
	}
	peer.Close()
	if err := <-served; !errors.Is(err, diskError) {
		t.Fatalf("lost audit error at shutdown: %v", err)
	}
}

func TestProfileFrameOnlyAcceptedWhenEnabled(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
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
			defer func() { _ = log.Close() }()
			server, peer := net.Pipe()
			defer peer.Close()
			var profile *Profile
			if enabled {
				profile = &Profile{}
			}
			go func() { _ = ServeWithOptions(server, policy.NewGate(p, dir), log, Options{Profile: profile}) }()
			client := NewClient(peer)
			err = client.ReportProfile(ProfileSnapshot{Metrics: map[string]Metric{"fuse.open": {Count: 3, Requests: 3, DurationNS: 100, MaxNS: 50}}})
			if (err == nil) != enabled {
				t.Fatalf("enabled=%v: %v", enabled, err)
			}
			events, err := effects.Read(path)
			if err != nil || len(events) != 0 {
				t.Fatalf("profile wrote audit events: %+v %v", events, err)
			}
			if enabled && profile.Snapshot().Metrics["child.fuse.open"].Count != 3 {
				t.Fatal("child profile not merged")
			}
		})
	}
}

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
	defer func() { _ = log.Close() }()
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
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
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
	defer func() { _ = log.Close() }()
	server, peer := net.Pipe()
	defer peer.Close()
	go func() { _ = Serve(server, policy.NewGate(p, dir), log) }()
	client := NewClient(peer)
	const workers = 96 // exceeds the bounded in-flight window
	start := make(chan struct{})
	errors := make(chan error, workers)
	for i := range uint32(workers) {
		go func() {
			<-start
			errors <- client.CheckBatch([]Request{{Source: "fuse", Kind: "fs.read", Target: fmt.Sprint(i), PID: i + 1}, {Source: "fuse", Kind: "fs.write", Target: fmt.Sprint(i), PID: i + 1}})
		}()
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
	if err := server.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
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

// A secret can share a commit group with other checks. Applying its taint only
// after the group commit would let the following check evaluate an old label.
func TestSecretTaintVisibleToLaterCheckInCommitGroup(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "airbag.yaml"), []byte(`rules:
  - name: deny-tainted-read
    when: effect.kind == "fs.read" && "secret" in session.labels
    verdict: deny
`), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := policy.Load(dir, dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "effects.db")
	log, err := effects.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	server, peer := net.Pipe()
	defer peer.Close()
	gate := policy.NewGate(p, dir)
	go func() {
		_ = ServeWithOptions(server, gate, log, Options{Audit: &testBufferedSink{log: log, gate: gate}})
	}()
	client := NewClient(peer)
	if err := client.CheckBatch([]Request{
		{Source: "fuse", Kind: "secret.read", Target: "credential", Secret: true},
		{Source: "fuse", Kind: "fs.read", Target: "later-check"},
	}); err == nil {
		t.Fatal("later check used untainted state")
	}
	events, err := effects.Read(path)
	if err != nil || len(events) != 2 || events[1].Verdict != policy.Deny {
		t.Fatalf("missing durable taint/deny: %+v %v", events, err)
	}
}

// An exec within the argv limits can still escape past one frame (each '<'
// is six bytes in JSON). It is refused alone; the channel keeps serving.
func TestOversizedRequestRefusedBeforeSending(t *testing.T) {
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
	defer func() { _ = log.Close() }()
	server, peer := net.Pipe()
	defer peer.Close()
	go func() { _ = Serve(server, policy.NewGate(p, dir), log) }()
	client := NewClient(peer)
	argv := make([]string, 16)
	for i := range argv {
		argv[i] = strings.Repeat("<", 4000)
	}
	if err := client.Check(Request{Source: "seccomp", Kind: "proc.exec", Target: "/usr/bin/true", Argv: argv}); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized frame: %v", err)
	}
	if err := client.Check(Request{Source: "fuse", Kind: "fs.read", Target: "after"}); err != nil {
		t.Fatal("channel lost after an oversized request:", err)
	}
	events, err := effects.Read(path)
	if err != nil || len(events) != 1 || events[0].Target != "after" {
		t.Fatalf("wrong log: %+v %v", events, err)
	}
}
