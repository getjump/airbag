package sandbox

import (
	"io"
	"net"
	"path/filepath"
	"testing"

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/policy"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/internal/taint"
)

// After a secret read, a forward to another machine refuses; one to
// this machine keeps relaying.
func TestForwarderTaint(t *testing.T) {
	log, err := effects.Open(filepath.Join(t.TempDir(), "effects.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	pol, err := policy.Load(t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gate := policy.NewGate(pol, t.TempDir())
	gate.Mark(taint.Secret, ".env")

	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }()
		}
	}()
	try := func(f session.Forward) bool {
		fw := newForwarder(f, gate, log)
		a, b := net.Pipe()
		go fw.handle(b)
		defer a.Close()
		_, _ = a.Write([]byte("x"))
		buf := make([]byte, 1)
		_, err := a.Read(buf)
		return err == nil && buf[0] == 'x'
	}
	port := echo.Addr().(*net.TCPAddr).Port
	if !try(session.Forward{Host: "127.0.0.1", Port: port}) {
		t.Error("a loopback forward stopped after the secret read")
	}
	if try(session.Forward{Host: "db.example.test", Port: port}) {
		t.Error("a forward off this machine relayed after the secret read")
	}
}
