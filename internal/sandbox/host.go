package sandbox

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/getjump/airbag/internal/control"
	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/mirror"
	"github.com/getjump/airbag/internal/policy"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/internal/steps"
	"github.com/getjump/airbag/internal/taint"
	"github.com/getjump/airbag/outbox"
	"github.com/getjump/airbag/proxy"
)

// hostEndpoints describes only the channels a runtime exposes. Host policy,
// credentials, persistence and review do not belong to the runtime adapter.
type hostEndpoints struct {
	ProxyNetwork string
	ProxyAddress string
	ControlRoot  string
	Forwards     bool
}

type hostServices struct {
	Gate      *policy.Gate
	Log       *effects.Log
	Proxy     *proxy.Proxy
	ProxyAddr net.Addr
	box       *outbox.Box
	servers   []*http.Server
	listeners []net.Listener
	forwards  []*forwarder
	wg        sync.WaitGroup
	once      sync.Once
	closeErr  error
}

// startHostServices constructs the common host authority before launching any
// agent. Failure unwinds every resource already acquired.
func startHostServices(s *session.Session, allow proxy.Allowlist, pol *policy.Policy, ep hostEndpoints) (_ *hostServices, err error) {
	h := &hostServices{Gate: policy.NewGate(pol, s.Dir)}
	defer func() {
		if err != nil {
			err = errors.Join(err, h.Close())
		}
	}()
	restoreLabels(h.Gate, s)
	if h.Log, err = effects.Open(s.EffectsPath()); err != nil {
		return nil, err
	}
	h.Proxy = proxy.New(allow, h.Log)
	h.Proxy.Gate = h.Gate
	if h.Proxy.Creds, h.Proxy.CA, err = setupCredentials(s, pol.Credentials); err != nil {
		return nil, err
	}
	mr := mirror.New(filepath.Join(session.Root(), "mirror"), h.Log)
	mr.Tainted = h.Gate.Tainted
	mr.Pinned = mirror.FindPins(s.Workspace)
	h.Proxy.Mirror = mr
	if err := os.MkdirAll(s.RunDir(), 0o700); err != nil {
		return nil, err
	}
	pl, err := h.listen(ep.ProxyNetwork, ep.ProxyAddress)
	if err != nil {
		return nil, err
	}
	h.ProxyAddr = pl.Addr()
	if ep.Forwards {
		for i, f := range s.Forwards {
			_ = os.Remove(s.ForwardSock(i))
			fl, listenErr := h.listen("unix", s.ForwardSock(i))
			if listenErr != nil {
				return nil, listenErr
			}
			fw := newForwarder(f, h.Gate, h.Log)
			h.forwards = append(h.forwards, fw)
			h.wg.Go(func() { fw.serve(fl) })
		}
	}
	h.Gate.Labels().OnAdd(func(label taint.Label, _ string) {
		if label == taint.Secret {
			h.Proxy.Cut(proxy.DefaultAllow, "secret-taint")
			for _, fw := range h.forwards {
				fw.cut()
			}
		}
	})
	_ = os.Remove(s.ControlSock())
	cl, err := h.listen("unix", s.ControlSock())
	if err != nil {
		return nil, err
	}
	if h.box, err = outbox.Open(s.EffectsPath()); err != nil {
		return nil, err
	}
	ctl := &control.Server{Box: h.box, Log: h.Log, Steps: steps.NewTracker(s), Gate: h.Gate, Root: ep.ControlRoot}
	h.serve(&http.Server{Handler: h.Proxy, ReadHeaderTimeout: 30 * time.Second}, pl)
	h.serve(ctl.HTTPServer(), cl)
	return h, nil
}

func (h *hostServices) listen(network, address string) (net.Listener, error) {
	l, err := (&net.ListenConfig{}).Listen(context.Background(), network, address)
	if err == nil {
		h.listeners = append(h.listeners, l)
	}
	return l, err
}

func (h *hostServices) serve(srv *http.Server, l net.Listener) {
	h.servers = append(h.servers, srv)
	h.wg.Go(func() { _ = srv.Serve(l) })
}

// Close stops admission and connections before closing storage. It is also
// safe during partial startup, and repeated calls return the same result.
func (h *hostServices) Close() error {
	h.once.Do(func() {
		for _, srv := range h.servers {
			_ = srv.Close()
		}
		for _, l := range h.listeners {
			_ = l.Close()
		}
		if h.Proxy != nil {
			h.Proxy.Close()
		}
		for _, fw := range h.forwards {
			fw.close()
		}
		h.wg.Wait()
		if h.box != nil {
			h.closeErr = errors.Join(h.closeErr, h.box.Close())
		}
		if h.Log != nil {
			h.closeErr = errors.Join(h.closeErr, h.Log.Close())
		}
	})
	return h.closeErr
}
