//go:build linux

package sandbox

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/getjump/airbag/internal/netcap"
)

func unixListener(t *testing.T, name string) net.Listener {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", filepath.Join(t.TempDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// closedSoon reports whether c is closed by the other end within d.
func closedSoon(c net.Conn, d time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(d))
	_, err := c.Read(make([]byte, 1))
	return err != nil && !errors.Is(err, os.ErrDeadlineExceeded)
}

// A relay holds no more pairs than its cap, closes a pair whose downstream
// ended once the client has been quiet for drain, closes an idle pair, and
// gives each place back: ten clients do not stay open against a downstream
// that serves one.
func TestRelayCapHolds(t *testing.T) {
	down := unixListener(t, "down")
	var open atomic.Int64
	held := make(chan net.Conn, 64)
	go func() {
		l := netcap.Limit(down, 1) // as the proxy and control socket cap theirs
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			open.Add(1)
			held <- c
		}
	}()
	relay := unixListener(t, "relay")
	lim := relayLimits{max: 2, idle: 400 * time.Millisecond, drain: 200 * time.Millisecond}
	go serveRelay(relay, lim, func() (net.Conn, error) {
		return (&net.Dialer{}).DialContext(context.Background(), "unix", down.Addr().String())
	})
	dial := func() net.Conn {
		c, err := (&net.Dialer{}).DialContext(context.Background(), "unix", relay.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	var clients []net.Conn
	for range 10 {
		clients = append(clients, dial())
	}
	alive := 0
	for _, c := range clients {
		if !closedSoon(c, 150*time.Millisecond) {
			alive++
		}
	}
	if alive > lim.max {
		t.Fatalf("%d relay pairs open past a cap of %d", alive, lim.max)
	}
	// Everything ends within idle, or drain once the downstream that
	// refused its second connection has closed it.
	deadline := time.Now().Add(2 * time.Second)
	for _, c := range clients {
		if !closedSoon(c, time.Until(deadline)) {
			t.Fatal("a relay pair outlived its idle and drain bounds")
		}
		_ = c.Close()
	}
	// The places are given back: a new pair reaches the downstream and
	// carries bytes.
	for len(held) > 0 {
		_ = (<-held).Close()
	}
	c := dial()
	defer c.Close()
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	select {
	case d := <-held:
		defer d.Close()
		b := make([]byte, 1)
		_ = d.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := io.ReadFull(d, b); err != nil || b[0] != 'x' {
			t.Fatalf("relayed %q, %v", b, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the relay did not give its places back")
	}
}

// The relay's own cap holds against a downstream that would take every
// connection: the pairs past it are closed, and never reach it.
func TestRelayCapsWhatItOpens(t *testing.T) {
	down := unixListener(t, "down")
	var accepted atomic.Int64
	go func() {
		for {
			c, err := down.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	relay := unixListener(t, "relay")
	go serveRelay(relay, relayLimits{max: 3, idle: time.Minute, drain: time.Minute}, func() (net.Conn, error) {
		return (&net.Dialer{}).DialContext(context.Background(), "unix", down.Addr().String())
	})
	alive := 0
	for range 10 {
		c, err := (&net.Dialer{}).DialContext(context.Background(), "unix", relay.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		if !closedSoon(c, 150*time.Millisecond) {
			alive++
		}
	}
	if alive != 3 || accepted.Load() > 3 {
		t.Fatalf("%d pairs open, %d reached the server, past a cap of 3", alive, accepted.Load())
	}
}
