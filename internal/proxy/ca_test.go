package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"
	"testing"
)

// The leaf cache stays within its bound however many names the agent
// asks for, and keeps the ones asked for last.
func TestLeafCacheBounded(t *testing.T) {
	ca, err := NewCA([]string{"*.example.test:443"})
	if err != nil {
		t.Fatal(err)
	}
	const n = 5000
	for i := range n {
		if _, err := ca.leaf(fmt.Sprintf("h%d.example.test", i)); err != nil {
			t.Fatal(err)
		}
	}
	ca.mu.Lock()
	size, listed := len(ca.leaves), ca.order.Len()
	_, last := ca.leaves[fmt.Sprintf("h%d.example.test", n-1)]
	ca.mu.Unlock()
	if size > maxLeaves || listed != size || !last {
		t.Fatalf("after %d names: %d cached (%d listed), want at most %d with the last kept", n, size, listed, maxLeaves)
	}
}

// Leaves dropped from the cache while handshakes use them stay valid:
// every handshake gets a certificate for its own name.
func TestLeafCacheEvictsDuringHandshakes(t *testing.T) {
	ca, err := NewCA([]string{"*.example.test:443"})
	if err != nil {
		t.Fatal(err)
	}
	ca.max = 4 // 16 names: most handshakes find their leaf dropped
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.PEM)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for w := range 8 {
		wg.Go(func() {
			for i := range 25 {
				name := fmt.Sprintf("h%d.example.test", (w*7+i)%16)
				a, b := net.Pipe()
				srv := tls.Server(a, &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
					return ca.leaf(hi.ServerName)
				}})
				go func() { _ = srv.HandshakeContext(t.Context()); a.Close() }()
				cl := tls.Client(b, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name, RootCAs: roots})
				err := cl.HandshakeContext(t.Context())
				b.Close() // not cl.Close: its close_notify would wait on the unbuffered pipe
				if err != nil {
					errs <- fmt.Errorf("%s: %w", name, err)
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
