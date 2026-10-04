package policy

import (
	"fmt"
	"sync"
	"time"

	"github.com/getjump/airbag/internal/taint"
)

// Gate applies a policy during a session and handles "ask": the action
// is held, the human decides (`airbag approve`, `airbag deny`, or any
// tool that calls them), and the agent's retry gets the decision.
type Gate struct {
	*Policy
	asks   *Asks
	labels *taint.Set
	mu     sync.Mutex
	onAsk  []func(Request)

	// Workspace and ApprovalsPath scope standing approvals; AskWait is
	// how long a new or pending request is held for a decision before
	// the agent is told to ask.
	Workspace     string
	ApprovalsPath string
	AskWait       time.Duration
}

// NewGate opens the session's requests in the session database.
func NewGate(p *Policy, dbPath string) (*Gate, error) {
	asks, err := OpenAsks(dbPath)
	if err != nil {
		return nil, err
	}
	return &Gate{Policy: p, asks: asks, labels: taint.NewSet()}, nil
}

func (g *Gate) Close() error { return g.asks.Close() }

// Labels is the session's label set, shared with the proxy and review.
func (g *Gate) Labels() *taint.Set { return g.labels }

// Mark records that source gave the session a label; it returns true
// the first time that label appears.
func (g *Gate) Mark(label taint.Label, source string) bool { return g.labels.Add(label, source) }

// Taint marks the session as having read a secret.
func (g *Gate) Taint(source string) { g.labels.Add(taint.Secret, source) }

// Tainted returns the first secret the session read, or "".
func (g *Gate) Tainted() string { return g.labels.Source(taint.Secret) }

// OnAsk registers f to run for every new request, before the wait.
func (g *Gate) OnAsk(f func(Request)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.onAsk = append(g.onAsk, f)
}

// Check decides an effect. For ask it returns the request's ID: the
// effect passes once the human approves it (now, within AskWait, or for
// good through a standing approval) and is refused once they deny it.
func (g *Gate) Check(in Input) (Decision, string) {
	in.Tainted = in.Tainted || g.Tainted() != ""
	in.Labels = g.labels.Labels()
	d := g.Decide(in)
	if d.Verdict != Ask {
		return d, ""
	}
	what := in.Effect.String()
	if standing(g.ApprovalsPath, g.Workspace, d.Rule, what) {
		return Decision{Verdict: Allow, Rule: d.Rule, Message: "approved always"}, ""
	}
	r, created, err := g.asks.Open(d.Rule+"|"+what, d.Rule, what, d.Message)
	if err != nil {
		return Decision{Verdict: Deny, Rule: d.Rule, Message: "request could not be recorded: " + err.Error()}, ""
	}
	if created {
		g.mu.Lock()
		hooks := g.onAsk
		g.mu.Unlock()
		for _, f := range hooks {
			f(r)
		}
	}
	for deadline := time.Now().Add(g.AskWait); ; {
		switch r.Decision {
		case Approved:
			return Decision{Verdict: Allow, Rule: d.Rule, Message: "approved as " + r.ID}, r.ID
		case Denied:
			return Decision{Verdict: Deny, Rule: d.Rule, Message: "the user denied " + r.ID}, r.ID
		}
		if !time.Now().Before(deadline) {
			return d, r.ID
		}
		time.Sleep(200 * time.Millisecond)
		if got, err := g.asks.Get(r.ID); err == nil {
			r = got
		}
	}
}

// Explain is the text an agent sees when it is blocked.
func Explain(d Decision, askID string) string {
	msg := fmt.Sprintf("airbag: blocked by policy %q", d.Rule)
	if d.Message != "" {
		msg += ": " + d.Message
	}
	if d.Verdict == Ask {
		msg += fmt.Sprintf(". This needs the user's approval: ask them to run `airbag approve %s`, then retry.", askID)
	}
	return msg
}
