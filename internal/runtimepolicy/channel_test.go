package runtimepolicy

import (
	"net"
	"path/filepath"
	"testing"

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
