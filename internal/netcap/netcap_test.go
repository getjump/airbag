package netcap

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

// Past max open, a connection is closed at once; closing one gives its
// place to the next.
func TestLimit(t *testing.T) {
	inner, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := Limit(inner, 2)
	defer l.Close()
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				close(accepted)
				return
			}
			accepted <- c
		}
	}()
	dial := func() net.Conn {
		c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	closedByServer := func(c net.Conn) bool {
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err := c.Read(make([]byte, 1))
		return errors.Is(err, io.EOF)
	}
	dial()
	dial()
	a, b := <-accepted, <-accepted
	if !closedByServer(dial()) {
		t.Fatal("a third connection was kept open")
	}
	a.Close()
	dial()
	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("the freed place was not given to the next connection")
	}
	b.Close()
	l.Close()
	for c := range accepted {
		c.Close()
	}
}
