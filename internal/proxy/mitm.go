package proxy

import (
	"container/list"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/getjump/airbag/internal/creds"
	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/models"
	"github.com/getjump/airbag/internal/policy"
)

// CA signs the certificates the proxy shows for the hosts it
// intercepts. It is made for one session and lives in memory: the key
// is never written anywhere. Name constraints limit it to the bound
// hosts, so even its key could not vouch for any other site.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	PEM  []byte

	mu     sync.Mutex
	leaves map[string]*list.Element // host → its *cachedLeaf in order
	order  list.List                // most recently used first
	max    int
}

// maxLeaves bounds the certificates a CA keeps. Under a wildcard
// binding (*.example.com) the agent picks the names, and each would
// otherwise stay; a leaf dropped is made again when next asked for.
const maxLeaves = 256

type cachedLeaf struct {
	host string
	cert *tls.Certificate
}

func NewCA(hosts []string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:                serial(),
		Subject:                     pkix.Name{CommonName: "airbag session CA", Organization: []string{"airbag"}},
		NotBefore:                   time.Now().Add(-time.Hour),
		NotAfter:                    time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
	}
	for _, h := range hosts {
		host, _ := creds.SplitHost(h)
		if ip := net.ParseIP(host); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			tmpl.PermittedIPRanges = append(tmpl.PermittedIPRanges, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		tmpl.PermittedDNSDomains = append(tmpl.PermittedDNSDomains, strings.TrimPrefix(host, "*"))
	}
	// A constraint limits only the kind of name it is about: with DNS
	// names alone the CA could still vouch for any IP address, with
	// addresses alone for any DNS name. So the kind the hosts do not use
	// is closed: every address is excluded, or the only DNS name allowed
	// is "invalid", which never names a real site (RFC 6761).
	if len(tmpl.PermittedIPRanges) == 0 {
		tmpl.ExcludedIPRanges = []*net.IPNet{
			{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		}
	}
	if len(tmpl.PermittedDNSDomains) == 0 {
		tmpl.PermittedDNSDomains = []string{"invalid"}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		leaves: map[string]*list.Element{}, max: maxLeaves}, nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n
}

// leaf returns a certificate for host, signed by the CA. The most
// recently used ones are kept; one dropped from the cache stays valid
// for a handshake that holds it already.
func (c *CA) leaf(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.leaves[host]; ok {
		c.order.MoveToFront(e)
		return e.Value.(*cachedLeaf).cert, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     c.cert.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		// No common name: OpenSSL checks a leaf's CN as a DNS name when it
		// has no DNS name, and "10.0.0.1" is not among the permitted ones.
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.Subject = pkix.Name{CommonName: host}
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	t := &tls.Certificate{Certificate: [][]byte{der, c.cert.Raw}, PrivateKey: key}
	c.leaves[host] = c.order.PushFront(&cachedLeaf{host: host, cert: t})
	for c.order.Len() > c.max {
		e := c.order.Back()
		c.order.Remove(e)
		delete(c.leaves, e.Value.(*cachedLeaf).host)
	}
	return t, nil
}

// intercept terminates TLS for a host a credential is bound to. Each
// request is logged with its method and path, checked by policy, gets
// the value in place of the placeholder, and goes on to the real host
// over a TLS connection verified against this machine's roots. The
// response comes back with the value masked.
//
// The connection is the flow f: bytes either way on it or on its
// upstream connections keep it open. It is closed when it has waited
// Limits.KeepAlive for its next request, or when a request in progress
// has moved no byte for Limits.Idle (a host that stalls). A protocol
// upgrade is refused, so no connection outlives its HTTP exchanges.
func (p *Proxy) intercept(w http.ResponseWriter, r *http.Request, host string, live *creds.Live, f *flow) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "airbag: cannot intercept", http.StatusInternalServerError)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	target := r.Host
	tconn := tls.Server(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// The certificate is for the host the CONNECT named, whatever
			// the client says in SNI: the policy checks were for that one.
			return p.CA.leaf(host)
		},
	})
	if !f.hold(tconn) {
		return // cut
	}
	_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	_ = tconn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tconn.HandshakeContext(context.Background()); err != nil {
		conn.Close()
		p.Log.Add(effects.Effect{Kind: "net.egress", Target: target, Verdict: "deny", Reason: "TLS to airbag's proxy failed (does the tool trust airbag's CA?): " + err.Error()})
		return
	}
	_ = tconn.SetDeadline(time.Time{})

	check := !p.Allow.explicitIP(host)
	// The upstream sees the bound host spelled one way, in SNI and Host,
	// whatever spelling the agent used in CONNECT or Host: a router that
	// tells "API.github.com." from "api.github.com" must not be handed the
	// agent's spelling along with the real value.
	name, canonical := upstreamHost(target)
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			c, err := p.dial(target, check)
			if err != nil {
				return nil, err
			}
			tc := tls.Client(c, &tls.Config{ServerName: name, RootCAs: p.UpstreamRoots, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
			if err := tc.HandshakeContext(ctx); err != nil {
				c.Close()
				return nil, err
			}
			wc := &watchedConn{Conn: tc, f: f}
			if !f.hold(wc) {
				return nil, errStopped
			}
			return wc, nil
		},
		ResponseHeaderTimeout: 2 * time.Minute,
		IdleConnTimeout:       time.Minute,
	}
	defer tr.CloseIdleConnections()
	closed := make(chan struct{})
	var once sync.Once
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme, pr.Out.URL.Host = "https", target
			pr.Out.Host = canonical
			// Without the client's Accept-Encoding the transport asks for
			// gzip itself and unpacks it, so the body can be masked.
			pr.Out.Header.Del("Accept-Encoding")
			live.Substitute(pr.Out.Header, pr.Out.URL)
		},
		Transport: tr,
		ModifyResponse: func(resp *http.Response) error {
			if ce := resp.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
				// Only gzip is asked for, and the transport unpacks it; a
				// body packed some other way cannot be checked.
				resp.Body.Close()
				return errors.New("the host sent a body encoded as " + ce + " without being asked; airbag cannot check it for the credential")
			}
			live.MaskHeader(resp.Header)
			resp.Body = live.MaskBody(resp.Body)
			if !live.SameLength() {
				resp.Header.Del("Content-Length")
				resp.ContentLength = -1
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			var b *blockedAddr
			if errors.As(err, &b) {
				p.Log.Add(effects.Effect{Kind: "net.egress", Target: target, Verdict: "deny", Reason: "address: " + b.why})
				http.Error(w, "airbag: "+host+" "+b.Error(), http.StatusForbidden)
				return
			}
			http.Error(w, "airbag: "+err.Error(), http.StatusBadGateway)
		},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// host/path, with the port when it is not 443.
		what := host + req.URL.Path
		if _, port, _ := net.SplitHostPort(target); port != "443" {
			what = target + req.URL.Path
		}
		// The connection goes to the bound host, but a server that hosts
		// several sites (a CDN) routes by the Host header: a request
		// naming another site there would carry the real value to it
		// (domain fronting). The value goes only to the host it is bound to.
		// An HTTP/1.0 request may name no host; it goes to the bound one.
		if req.Host != "" && !sameHost(req.Host, target) {
			p.Log.Add(effects.Effect{Kind: "http.request", Target: clipTarget(req.Method + " " + what), Verdict: "deny", Reason: "Host " + clipTarget(req.Host) + " is not the bound host"})
			http.Error(w, "airbag: Host "+req.Host+" is not "+host+", the host this credential is bound to; the credential goes only to that host", http.StatusForbidden)
			return
		}
		if p.Gate != nil && p.Gate.Tainted() != "" && !Allowlist(DefaultAllow).Allows(host) {
			p.Log.Add(effects.Effect{Kind: "http.request", Target: clipTarget(req.Method + " " + what), Verdict: "deny", Reason: "secret-taint"})
			http.Error(w, "airbag: blocked by policy \"secret-taint\": this session read "+p.Gate.Tainted(), http.StatusForbidden)
			return
		}
		if p.Gate != nil {
			if d, id := p.Gate.Check(policy.Input{Effect: models.Effect{Kind: "http.request", Target: what, Detail: req.Method}}); d.Verdict != policy.Allow {
				p.Log.Add(effects.Effect{Kind: "http.request", Target: clipTarget(req.Method + " " + what), Verdict: d.Verdict, Reason: d.Rule})
				http.Error(w, policy.Explain(d, id), http.StatusForbidden)
				return
			}
		}
		if req.Header.Get("Upgrade") != "" {
			// After an upgrade (a websocket) the stream is not HTTP.
			// Putting the placeholder back in it would mean holding up
			// any bytes that could start the value (a "ping", when the
			// value starts with "g"); without that, a host that echoes
			// would hand the value to the agent. The request is refused
			// before it reaches the host.
			p.Log.Add(effects.Effect{Kind: "http.request", Target: clipTarget(req.Method + " " + what), Verdict: "deny", Reason: "protocol upgrade: the stream cannot be checked for the credential"})
			http.Error(w, "airbag: "+host+" is reached with a credential, and airbag does not pass a protocol upgrade (websocket) there: it could not keep the value out of the upgraded stream", http.StatusForbidden)
			return
		}
		reason := ""
		if live.Substitute(req.Header.Clone(), cloneURL(req)) {
			reason = live.Name
		}
		p.Log.Add(effects.Effect{Kind: "http.request", Target: clipTarget(req.Method + " " + what), Verdict: "allow", Reason: reason})
		rp.ServeHTTP(w, req)
	})

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       p.Limits.KeepAlive,
		ConnState: func(_ net.Conn, s http.ConnState) {
			if s == http.StateClosed {
				once.Do(func() { close(closed) })
			}
		},
	}
	go func() { _ = srv.Serve(&oneConn{c: &watchedConn{Conn: tconn, f: f}}) }()
	<-closed
	_ = srv.Close()
}

func cloneURL(r *http.Request) *url.URL {
	u := *r.URL
	return &u
}

func clipTarget(s string) string {
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}

// oneConn is a listener that hands out one connection, then blocks
// until it is closed.
type oneConn struct {
	c    net.Conn
	once sync.Once
	done chan struct{}
	mu   sync.Mutex
}

func (l *oneConn) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.done == nil {
		l.done = make(chan struct{})
	}
	l.mu.Unlock()
	var c net.Conn
	l.once.Do(func() { c = l.c })
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConn) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.done == nil {
		l.done = make(chan struct{})
	}
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

func (l *oneConn) Addr() net.Addr { return l.c.LocalAddr() }

// upstreamHost spells the CONNECT target one way: the name in lower
// case without a trailing dot, and the Host header, which adds brackets
// for IPv6 and the port when it is not 443.
func upstreamHost(target string) (name, hostHeader string) {
	h, port := creds.SplitHost(target)
	name = strings.ToLower(strings.TrimSuffix(h, "."))
	if port == "443" {
		if strings.Contains(name, ":") {
			return name, "[" + name + "]"
		}
		return name, name
	}
	return name, net.JoinHostPort(name, port)
}

// sameHost reports whether a request's Host header names the CONNECT
// target: the same host and port in any spelling (creds.CanonHost and
// CanonPort), 443 when the header gives none.
func sameHost(header, target string) bool {
	hh, hp := creds.SplitHost(header)
	th, tp := creds.SplitHost(target)
	return hh != "" && creds.CanonHost(hh) == creds.CanonHost(th) && creds.CanonPort(hp) == creds.CanonPort(tp)
}
