package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/getjump/airbag/audit"
	"github.com/getjump/airbag/proxy/simulate"
)

// serveSimulated answers for a host that stubs cover (Proxy.Simulation): the
// plain HTTP request itself, or, after a CONNECT, every request on the
// TLS connection the proxy ends with the session CA. No connection is
// opened to the host, whatever the request, so the allowlist, the
// policy rules, the secret label and the untrusted label do not come
// into it: nothing reaches the host and nothing from outside comes in.
func (p *Proxy) serveSimulated(w http.ResponseWriter, r *http.Request, host, port, target string) {
	if r.Method == http.MethodConnect && p.CA == nil {
		// An embedding that set stubs without a CA: the TLS cannot be
		// answered, and the host must not be reached instead.
		p.Log.Add(audit.Event{Kind: simulate.Kind, Target: target, Verdict: "deny", Reason: "no session CA to answer TLS with"})
		answer(w, "airbag: "+host+" is simulated, and this proxy has no certificate authority to answer its TLS with; it was not contacted", http.StatusServiceUnavailable)
		return
	}
	f, done := p.admit(w, host, target, true)
	if f == nil {
		return
	}
	defer done()
	if r.Method != http.MethodConnect {
		f.begin()
		p.stub(w, r, host, port, false, f)
		return
	}
	tconn := p.terminate(w, host, f, func(err error) {
		p.Log.Add(audit.Event{Kind: simulate.Kind, Target: target, Verdict: "deny",
			Reason: "TLS to airbag's proxy failed (does the tool trust airbag's CA, or pin the host's certificate?): " + err.Error()})
	})
	if tconn == nil {
		return
	}
	p.serveTLS(tconn, f, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// The previous answer on this connection left a write deadline.
		_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
		// The connection is to the CONNECT's host, and its stubs answer;
		// a request naming another host there is not one of them.
		if req.Host != "" && !sameHost(req.Host, target) {
			p.Log.Add(audit.Event{Kind: simulate.Kind, Target: clipTarget(req.Method + " " + host + req.URL.Path), Verdict: "deny", Reason: "Host " + clipTarget(req.Host) + " is not the connection's host"})
			http.Error(w, "airbag: Host "+req.Host+" is not "+host+", the simulated host this connection is to", http.StatusForbidden)
			return
		}
		p.stub(w, req, host, port, true, f)
	}))
}

// stub answers one request on a simulated host from the first stub
// that matches it, or refuses it. tls says whether it came on an
// intercepted connection (its refusals then keep the connection, as the
// intercepted ones of credentials do) or as a plain proxy request.
func (p *Proxy) stub(w http.ResponseWriter, req *http.Request, host, port string, tls bool, f *flow) {
	rc := http.NewResponseController(w)
	what := host + req.URL.Path
	if (tls && port != "443") || (!tls && port != "80") {
		what = net.JoinHostPort(host, port) + req.URL.Path
	}
	target := clipTarget(req.Method + " " + what)
	refuse := func(msg string, code int) {
		if tls {
			http.Error(w, msg, code)
			return
		}
		answer(w, msg, code)
	}
	// Stopping the flow (the proxy closing, or its idle limit) ends the
	// delay and any blocked read or write, not only the connection.
	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()
	stop := &onStop{live: true, f: func() {
		cancel()
		_ = rc.SetReadDeadline(time.Now())
		_ = rc.SetWriteDeadline(time.Now())
	}}
	if !f.hold(stop) {
		w.Header().Set("Connection", "close")
		refuse("airbag: the connection to "+host+" was closed", http.StatusServiceUnavailable)
		return
	}
	defer f.release(stop)
	defer stop.end()
	// The body is read, up to a bound and within AnswerWrite, and thrown
	// away: no stub looks at it, and it is never logged. A longer or
	// slower one is left, and the connection closes after the answer.
	if req.Body != nil && req.Body != http.NoBody {
		_ = rc.SetReadDeadline(time.Now().Add(AnswerWrite))
		n, err := io.Copy(io.Discard, io.LimitReader(req.Body, simulate.MaxRequestBody+1))
		if err != nil || n > simulate.MaxRequestBody {
			w.Header().Set("Connection", "close")
		} else {
			_ = rc.SetReadDeadline(time.Time{})
		}
	}
	resp := p.Simulation.Match(host, port, req.Method, req.URL, req.Header)
	if resp == nil {
		p.Log.Add(audit.Event{Kind: simulate.Kind, Target: target, Verdict: "deny", Reason: "no stub matches"})
		refuse("airbag: no stub matches "+req.Method+" "+what+"; "+host+" is simulated, so the request was refused and not sent (simulate: in your airbag.yaml or --simulate)", http.StatusForbidden)
		return
	}
	p.Log.Add(audit.Event{Kind: simulate.Kind, Target: target, Verdict: "allow", Reason: resp.Stub})
	if resp.Delay > 0 {
		t := time.NewTimer(resp.Delay)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			// Returning would send an empty 200 for the stub's answer.
			panic(http.ErrAbortHandler)
		}
	}
	h := w.Header()
	for k, v := range resp.Header {
		h[k] = slices.Clone(v)
	}
	if _, ok := h["Content-Type"]; !ok {
		h["Content-Type"] = nil // the answer is the stub's, not one net/http guesses at
	}
	h.Set("Content-Length", strconv.Itoa(len(resp.Body)))
	pw := paced{w, rc}
	pw.WriteHeader(resp.Status)
	_, _ = pw.Write(resp.Body)
	pw.renew()
}

// onStop runs f when its flow stops, until end: after the handler has
// returned, its ResponseController must not be used.
type onStop struct {
	mu   sync.Mutex
	live bool
	f    func()
}

func (s *onStop) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live {
		s.f()
	}
	return nil
}

func (s *onStop) end() {
	s.mu.Lock()
	s.live = false
	s.mu.Unlock()
}
