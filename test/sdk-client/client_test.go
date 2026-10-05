package sdkclient_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/getjump/airbag/audit"
	"github.com/getjump/airbag/creds"
	"github.com/getjump/airbag/githubpr"
	"github.com/getjump/airbag/operation"
	"github.com/getjump/airbag/outbox"
	"github.com/getjump/airbag/policy"
	"github.com/getjump/airbag/proxy"
)

func request() operation.Request {
	return operation.Request{Schema: operation.Schema, Kind: operation.CreatePullRequest, PullRequest: &operation.PullRequest{
		Repository: "example/repo", Base: "main", Head: "work", HeadCommit: strings.Repeat("a", 40), Title: "Reviewed fix", Body: "Frozen body\n", Draft: true,
	}}
}

func TestIndependentOutboxPublication(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(fmt.Sprint(uncertain), func(t *testing.T) {
			r := request()
			preview, err := r.Preview()
			if err != nil {
				t.Fatal(err)
			}
			var posts atomic.Int32
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method == http.MethodGet && req.URL.Path == "/repos/example/repo/git/ref/heads/work" {
					_, _ = fmt.Fprintf(w, `{"object":{"sha":%q}}`, r.PullRequest.HeadCommit)
					return
				}
				if req.Method != http.MethodPost || req.URL.Path != "/repos/example/repo/pulls" {
					http.Error(w, "unexpected method/path", http.StatusBadRequest)
					return
				}
				posts.Add(1)
				var payload struct {
					Title      string `json:"title"`
					Body       string `json:"body"`
					Head       string `json:"head"`
					Base       string `json:"base"`
					Draft      bool   `json:"draft"`
					Maintainer bool   `json:"maintainer_can_modify"`
				}
				d := json.NewDecoder(req.Body)
				d.DisallowUnknownFields()
				if err := d.Decode(&payload); err != nil || payload.Title != "Reviewed fix" || payload.Body != "Frozen body\n" || payload.Head != "work" || payload.Base != "main" || !payload.Draft || payload.Maintainer {
					t.Errorf("POST differs from frozen request: %+v, %v", payload, err)
				}
				sha := r.PullRequest.HeadCommit
				if uncertain {
					sha = strings.Repeat("b", 40) // remote head raced the POST
				}
				_, _ = fmt.Fprintf(w, `{"number":7,"html_url":"https://github.com/example/repo/pull/7","title":"Reviewed fix","body":"Frozen body\n","draft":true,"head":{"sha":%q,"ref":"work","repo":{"full_name":"example/repo"}},"base":{"ref":"main","repo":{"full_name":"example/repo"}}}`, sha)
			}))
			defer api.Close()
			handler := githubpr.Handler{Call: func(ctx context.Context, method, endpoint string, body []byte) ([]byte, error) {
				req, err := http.NewRequestWithContext(ctx, method, api.URL+"/"+endpoint, strings.NewReader(string(body)))
				if err != nil {
					return nil, err
				}
				resp, err := api.Client().Do(req)
				if err != nil {
					return nil, err
				}
				defer resp.Body.Close()
				return io.ReadAll(io.LimitReader(resp.Body, 2<<20))
			}}
			path := filepath.Join(t.TempDir(), "outbox.db")
			box, err := outbox.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = box.Close() }()
			it, err := box.Push(outbox.Intent{Kind: outbox.KindPullRequest, Request: &r})
			if err != nil {
				t.Fatal(err)
			}
			if result := it.TypedResult(); result.Outcome != operation.Queued || result.Value != "" || posts.Load() != 0 {
				t.Fatal("queued action masqueraded as publication", result)
			}
			if err := box.Approve(it.ID, operation.Hash([]byte("different"))); err == nil {
				t.Fatal("approval accepted a different request")
			}
			if err := box.Approve(it.ID, preview.RequestDigest); err != nil {
				t.Fatal(err)
			}
			// Reopen before execution: approval belongs to storage, not this client.
			if err := box.Close(); err != nil {
				t.Fatal(err)
			}
			box, err = outbox.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			lock, err := box.LockExecution()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = lock.Close() }()
			prepared, err := handler.Prepare(t.Context(), r)
			if err != nil || prepared.Digest() != it.RequestDigest || posts.Load() != 0 {
				t.Fatal("preparation published or changed the request", err)
			}
			r.PullRequest.Title = "Mutable caller title"
			if err := box.Claim(it.ID, prepared.Digest()); err != nil {
				t.Fatal(err)
			}
			result := prepared.Publish(t.Context())
			if again := prepared.Publish(t.Context()); again != result || posts.Load() != 1 {
				t.Fatal("prepared interpreter repeated an external effect")
			}
			result.Ticket = it.ID
			it.Status = outbox.Done
			if uncertain {
				it.Status = outbox.Unknown
			}
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			it.Output = string(encoded)
			if err := box.Update(it); err != nil {
				t.Fatal(err)
			}
			if err := box.Claim(it.ID, prepared.Digest()); err == nil || posts.Load() != 1 {
				t.Fatal("terminal action could be claimed again")
			}
			rows, err := box.List()
			if err != nil || len(rows) != 1 {
				t.Fatal(rows, err)
			}
			want := operation.Succeeded
			if uncertain {
				want = operation.Uncertain
			}
			if got := rows[0].TypedResult(); got == nil || got.Outcome != want || got.RequestDigest != preview.RequestDigest {
				t.Fatal("result not bound to the queued operation", got)
			}
		})
	}
}

type recorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recorder) Add(e audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

type gate struct{ engine *policy.Engine }

func (g gate) Check(in policy.Input) (policy.Decision, string) { return g.engine.Decide(in), "" }
func (g gate) AllowsHost(string) bool                          { return false }
func (g gate) Tainted() string                                 { return "" }
func (g gate) MarkUntrusted(string) bool                       { return false }

func TestIndependentProxyCredentialsAndPolicy(t *testing.T) {
	const token = "host-only-token-1234567890"
	var gotToken atomic.Value
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		gotToken.Store(r.Header.Get("Authorization"))
		_, _ = fmt.Fprint(w, token)
	}))
	defer upstream.Close()
	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	log := &recorder{}
	p := proxy.New(proxy.Allowlist{u.Host}, log)
	defer p.Close()
	p.Upstream = func(*url.URL) (*url.URL, error) { return nil, nil }
	live := &creds.Live{Name: "fixture", Hosts: []string{u.Host}, Value: token, Placeholder: creds.Placeholder(token)}
	p.Creds = creds.Set{live}
	p.CA, err = proxy.NewCA([]string{u.Host})
	if err != nil {
		t.Fatal(err)
	}
	p.UpstreamRoots = x509.NewCertPool()
	p.UpstreamRoots.AddCert(upstream.Certificate())
	p.Gate = gate{engine: mustPolicy(t)}
	server := httptest.NewServer(p)
	defer server.Close()
	proxyURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(p.CA.PEM) {
		t.Fatal("invalid proxy CA")
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: upstream.Client().Transport.(*http.Transport).TLSClientConfig.Clone()}
	transport.TLSClientConfig.RootCAs = roots
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL+"/allowed", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", live.Placeholder)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || gotToken.Load() != token || string(data) != live.Placeholder {
		t.Fatal("credential substitution or response masking failed", gotToken.Load(), string(data), err)
	}
	req, err = http.NewRequestWithContext(t.Context(), http.MethodGet, upstream.URL+"/blocked", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatal("custom policy failed to deny an allowlisted destination", resp.StatusCode)
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	found := false
	for _, event := range log.events {
		if strings.Contains(fmt.Sprint(event), token) {
			t.Fatal("audit leaked the real credential")
		}
		found = found || event.Kind == "http.request" && event.Verdict == policy.Deny
	}
	if !found {
		t.Fatal("custom recorder did not receive the policy decision")
	}
}

func mustPolicy(t *testing.T) *policy.Engine {
	t.Helper()
	engine, err := policy.Compile([]policy.Rule{{Name: "blocked", When: `effect.kind == "http.request" && effect.target.endsWith("/blocked")`, Verdict: policy.Deny}}, policy.Allow)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}
