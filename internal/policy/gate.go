package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/getjump/airbag/internal/taint"
)

// Gate applies a policy during a session and handles "ask": the action
// is blocked, the agent is told to have the human run
// `airbag approve a-N`, and the retry passes.
type Gate struct {
	*Policy
	mu     sync.Mutex
	dir    string
	labels *taint.Set
}

// Labels is the session's label set, shared with the proxy and review.
func (g *Gate) Labels() *taint.Set { return g.labels }

// Mark records that source gave the session a label; it returns true
// the first time that label appears.
func (g *Gate) Mark(label taint.Label, source string) bool { return g.labels.Add(label, source) }

// Taint marks the session as having read a secret.
func (g *Gate) Taint(source string) { g.labels.Add(taint.Secret, source) }

// Tainted returns the first secret the session read, or "".
func (g *Gate) Tainted() string { return g.labels.Source(taint.Secret) }

type Request struct {
	ID       string    `json:"id"`
	Key      string    `json:"key"`
	Rule     string    `json:"rule"`
	What     string    `json:"what"`
	Message  string    `json:"message,omitempty"`
	Created  time.Time `json:"created"`
	Approved bool      `json:"approved"`
}

func NewGate(p *Policy, sessionDir string) *Gate {
	return &Gate{Policy: p, dir: sessionDir, labels: taint.NewSet()}
}

func asksPath(dir string) string { return filepath.Join(dir, "asks.json") }

// Check decides an effect. For ask it returns the request's ID, or
// allow when the human already approved this exact effect.
func (g *Gate) Check(in Input) (Decision, string) {
	in.Tainted = in.Tainted || g.Tainted() != ""
	in.Labels = g.labels.Labels()
	d := g.Decide(in)
	if d.Verdict != Ask {
		return d, ""
	}
	key := d.Rule + "|" + in.Effect.String()
	g.mu.Lock()
	defer g.mu.Unlock()
	asks, _ := ReadAsks(g.dir)
	for _, a := range asks {
		if a.Key == key {
			if a.Approved {
				return Decision{Verdict: Allow, Rule: d.Rule, Message: "approved as " + a.ID}, a.ID
			}
			return d, a.ID
		}
	}
	a := Request{ID: fmt.Sprintf("a-%d", len(asks)+1), Key: key, Rule: d.Rule, What: in.Effect.String(), Message: d.Message, Created: time.Now()}
	_ = writeAsks(g.dir, append(asks, a))
	return d, a.ID
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

func ReadAsks(dir string) ([]Request, error) {
	b, err := os.ReadFile(asksPath(dir))
	if err != nil {
		return nil, nil
	}
	var out []Request
	err = json.Unmarshal(b, &out)
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out, err
}

func writeAsks(dir string, asks []Request) error {
	b, err := json.MarshalIndent(asks, "", "  ")
	if err != nil {
		return err
	}
	tmp := asksPath(dir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, asksPath(dir))
}

// Approve marks asks as approved; "all" approves every pending one.
func Approve(dir, id string) ([]Request, error) {
	asks, err := ReadAsks(dir)
	if err != nil {
		return nil, err
	}
	var done []Request
	for i := range asks {
		if !asks[i].Approved && (id == "all" || asks[i].ID == id) {
			asks[i].Approved = true
			done = append(done, asks[i])
		}
	}
	if len(done) == 0 {
		return nil, fmt.Errorf("no pending request %s", id)
	}
	return done, writeAsks(dir, asks)
}
