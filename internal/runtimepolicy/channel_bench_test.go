//go:build airbag_bench

package runtimepolicy

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/policy"
)

func TestDiagnosticAuditBypassRetainsDurableSecretBarrier(t *testing.T) {
	t.Setenv("AIRBAG_BENCH_RUNTIME_STAGE", "policy-no-audit")
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
	if err := client.Check(Request{Source: "fuse", Kind: "fs.read", Target: "ordinary"}); err != nil {
		t.Fatal(err)
	}
	events, err := effects.Read(path)
	if err != nil || len(events) != 0 {
		t.Fatalf("diagnostic audit not bypassed: %+v %v", events, err)
	}
	if err := client.Check(Request{Source: "fuse", Kind: "secret.read", Target: "credential", Secret: true}); err != nil {
		t.Fatal(err)
	}
	events, err = effects.Read(path)
	if err != nil || len(events) != 1 || events[0].Kind != "secret.read" {
		t.Fatalf("secret notification lost durability: %+v %v", events, err)
	}
}
