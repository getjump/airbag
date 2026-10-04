package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
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

// Each kind of name the session CA does not name a host by is closed:
// a CA for DNS names vouches for no IP address, one for addresses for
// no DNS name, and a mixed one for each host only.
func TestCANameConstraintKinds(t *testing.T) {
	for _, c := range []struct {
		hosts   []string
		ok, bad []string
	}{
		{[]string{"api.github.com:443"}, []string{"api.github.com"}, []string{"127.0.0.1", "10.0.0.1", "::1", "evil.example"}},
		{[]string{"10.0.0.1:8443"}, []string{"10.0.0.1"}, []string{"example.com", "invalid.example", "10.0.0.2", "::1"}},
		{[]string{"[2001:db8::1]:443"}, []string{"2001:db8::1"}, []string{"example.com", "10.0.0.1", "2001:db8::2"}},
		{[]string{"api.github.com", "10.0.0.1:8443"}, []string{"api.github.com", "10.0.0.1"}, []string{"evil.example", "10.0.0.2", "::1"}},
	} {
		ca, err := NewCA(c.hosts)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM(ca.PEM)
		check := func(host string, want bool) {
			leaf, err := ca.leaf(host) // the key could sign any name
			if err != nil {
				t.Fatal(err)
			}
			cert, _ := x509.ParseCertificate(leaf.Certificate[0])
			_, err = cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: host})
			if (err == nil) != want {
				t.Errorf("CA for %v, leaf for %s: verify err %v, want ok=%v", c.hosts, host, err, want)
			}
			if err := verifyOpenSSL(t, ca, leaf, host); (err == nil) != want && !errors.Is(err, errNoOpenSSL) {
				t.Errorf("CA for %v, leaf for %s: openssl: %v, want ok=%v", c.hosts, host, err, want)
			}
		}
		for _, h := range c.ok {
			check(h, true)
		}
		for _, h := range c.bad {
			check(h, false)
		}
	}
}

var errNoOpenSSL = errors.New("no openssl")

// verifyOpenSSL checks leaf for host with the openssl command, when
// there is one: OpenSSL also checks a leaf's common name against the
// constraints, which Go does not.
func verifyOpenSSL(t *testing.T, ca *CA, leaf *tls.Certificate, host string) error {
	t.Helper()
	bin, err := exec.LookPath("openssl")
	if err != nil {
		return errNoOpenSSL
	}
	dir := t.TempDir()
	caFile, leafFile := dir+"/ca.pem", dir+"/leaf.pem"
	_ = os.WriteFile(caFile, ca.PEM, 0o600)
	_ = os.WriteFile(leafFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]}), 0o600)
	flag := "-verify_hostname"
	if net.ParseIP(host) != nil {
		flag = "-verify_ip"
	}
	out, err := exec.CommandContext(t.Context(), bin, "verify", "-x509_strict", "-purpose", "sslserver", flag, host, "-CAfile", caFile, leafFile).CombinedOutput() //nolint:gosec // openssl on files this test wrote
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
