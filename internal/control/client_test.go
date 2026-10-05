package control

import (
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/getjump/airbag/internal/effects"
)

// Calls from inside the sandbox share one connection to the host side.
// A Transport per call kept each call's connection open and idle, two
// goroutines here and one on the host's side, for the life of the
// process: the sandbox's init reports every secret read this way.
func TestClientReusesConnection(t *testing.T) {
	dir := t.TempDir()
	log, err := effects.Open(filepath.Join(dir, "effects.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	sock := filepath.Join(dir, "ctl.sock")
	l, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() { _ = (&Server{Log: log}).Serve(l) }()
	t.Setenv("AIRBAG_CONTROL", sock)
	t.Cleanup(transport.CloseIdleConnections)

	g0 := runtime.NumGoroutine()
	const calls = 50
	for range calls {
		if v := ReportExec(Exec{Shell: "sh", Script: "true"}); v.Verdict != "allow" {
			t.Fatalf("verdict %+v", v)
		}
	}
	// One idle connection: its two client goroutines and the server's.
	if g := runtime.NumGoroutine(); g > g0+4 {
		t.Fatalf("%d calls left %d goroutines behind, want at most 4", calls, g-g0)
	}
	transport.CloseIdleConnections()
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > g0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if g := runtime.NumGoroutine(); g > g0 {
		t.Fatalf("goroutines %d after closing idle connections, baseline %d", g, g0)
	}
}
