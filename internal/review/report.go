package review

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/internal/steps"
	"github.com/getjump/airbag/operation"
	"github.com/getjump/airbag/outbox"
)

// Schema names the JSON layout of Report. Fields are only added within
// a version; a removal or change of meaning bumps it.
const Schema = "airbag.review/v1"

// Report is the review as data, for editors, CI and scripts:
// `airbag review --json`. The text review shows the same.
type Report struct {
	Schema    string         `json:"schema"`
	Session   ReportSession  `json:"session"`
	Changes   []ReportChange `json:"changes"`
	Attention []ReportItem   `json:"attention"`
	Network   ReportNetwork  `json:"network"`
	Secrets   []ReportSecret `json:"secrets_read"`
	Untrusted []string       `json:"untrusted_from"`
	Packages  []string       `json:"packages"`
	Blocked   []ReportEffect `json:"blocked"`
	Outbox    []ReportIntent `json:"outbox"`
	Steps     []steps.Step   `json:"steps"`
}

type ReportSession struct {
	ID        string    `json:"id"`
	Workspace string    `json:"workspace"`
	Argv      []string  `json:"argv"`
	Status    string    `json:"status"`
	ExitCode  int       `json:"exit_code"`
	Created   time.Time `json:"created"`
	Ended     time.Time `json:"ended,omitzero"`
	Runs      int       `json:"runs"`
	Branch    string    `json:"branch,omitempty"`
}

type ReportChange struct {
	Layer string   `json:"layer"` // ws or home
	Path  string   `json:"path"`  // relative to the workspace or $HOME
	Kind  string   `json:"kind"`  // added, modified, deleted, replaced
	Type  string   `json:"type"`  // file, dir, symlink
	Flags []string `json:"flags,omitempty"`
}

// ReportItem is one thing the human should decide on.
type ReportItem struct {
	What   string `json:"what"`   // change, intent, blocked, secret, deletions, log
	Target string `json:"target"` // a path, an intent ID, a host
	Why    string `json:"why"`
}

type ReportNetwork struct {
	Allowed map[string]int `json:"allowed"` // host: connections
	Denied  map[string]int `json:"denied"`  // host:port: attempts
	Cut     map[string]int `json:"cut"`     // host:port: tunnels closed on a secret read
	// Requests: "METHOD host/path" to hosts a credential is bound to.
	Requests map[string]int `json:"requests"`
}

type ReportSecret struct {
	File string `json:"file"`
	By   string `json:"by"`
}

type ReportEffect struct {
	Verdict string `json:"verdict"`
	Kind    string `json:"kind"`
	Target  string `json:"target"`
	Reason  string `json:"reason,omitempty"`
}

type ReportIntent struct {
	ID     string   `json:"id"`
	Kind   string   `json:"kind"` // git.push, or cmd for a `defer:` entry
	Argv   []string `json:"argv"`
	Status string   `json:"status"`
	// Files: workspace files the command runs only on, with SHA-256.
	Files         map[string]string  `json:"files,omitempty"`
	Request       *operation.Request `json:"request,omitempty"`
	RequestDigest string             `json:"request_digest,omitempty"`
	Result        *operation.Result  `json:"result,omitempty"`
}

// manyDeletions is when deletions in the workspace become one item.
const manyDeletions = 50

func BuildReport(s *session.Session, cs []Change, effs []effects.Effect, intents []outbox.Intent, sts []steps.Step) Report {
	r := Report{
		Schema: Schema,
		Session: ReportSession{ID: s.ID, Workspace: s.Workspace, Argv: s.Argv, Status: s.Status,
			ExitCode: s.ExitCode, Created: s.Created, Ended: s.Ended, Runs: max(s.Runs, 1), Branch: s.Branch},
		Changes:   []ReportChange{},
		Attention: []ReportItem{},
		Network:   ReportNetwork{Allowed: map[string]int{}, Denied: map[string]int{}, Cut: map[string]int{}, Requests: map[string]int{}},
		Secrets:   []ReportSecret{},
		Untrusted: []string{},
		Packages:  []string{},
		Blocked:   []ReportEffect{},
		Outbox:    []ReportIntent{},
		Steps:     sts,
	}
	if r.Steps == nil {
		r.Steps = []steps.Step{}
	}
	deleted := 0
	for _, c := range cs {
		typ := "file"
		switch c.Type {
		case fs.ModeDir:
			typ = "dir"
		case fs.ModeSymlink:
			typ = "symlink"
		}
		r.Changes = append(r.Changes, ReportChange{Layer: c.Layer, Path: filepath.ToSlash(c.Rel), Kind: c.Kind, Type: typ, Flags: c.Flags})
		if c.Layer == "ws" && c.Kind == Deleted && !strings.HasPrefix(c.Rel, ".git/") {
			deleted++
		}
	}
	for _, a := range attentionLines(cs) {
		if a.c == nil {
			r.Attention = append(r.Attention, ReportItem{What: "change", Target: "~/" + a.group, Why: gitDirWhy(a.n)})
			continue
		}
		target := filepath.ToSlash(a.c.Rel)
		if a.c.Layer == "home" {
			target = "~/" + target
		}
		r.Attention = append(r.Attention, ReportItem{What: "change", Target: target, Why: attentionWhy(*a.c)})
	}
	if deleted > manyDeletions {
		r.Attention = append(r.Attention, ReportItem{What: "deletions", Target: s.Workspace, Why: fmt.Sprintf("%d files deleted in the workspace", deleted)})
	}

	seenU, seenPkg := map[string]bool{}, map[string]bool{}
	dropped := map[string]int{}
	for _, e := range effs {
		switch {
		case e.Kind == effects.Dropped:
			dropped[e.Target] += effects.DroppedCount(e)
		case e.Kind == "net.egress" || e.Kind == "net.tcp":
			host, _, err := net.SplitHostPort(e.Target)
			if err != nil {
				host = e.Target
			}
			switch e.Verdict {
			case "deny", "ask":
				r.Network.Denied[e.Target]++
			case "cut":
				r.Network.Cut[e.Target]++
			default:
				r.Network.Allowed[host]++
			}
		case e.Kind == "http.request" && e.Verdict == "allow":
			r.Network.Requests[e.Target]++
		case e.Kind == "secret.read":
			r.Secrets = append(r.Secrets, ReportSecret{File: e.Target, By: e.Reason})
			r.Attention = append(r.Attention, ReportItem{What: "secret", Target: e.Target, Why: "read by " + e.Reason + "; egress was narrowed from then on"})
		case e.Kind == "label" && e.Verdict == "untrusted" && !seenU[e.Target]:
			seenU[e.Target] = true
			r.Untrusted = append(r.Untrusted, e.Target)
		case e.Kind == "pkg.fetch" && !seenPkg[e.Target]:
			seenPkg[e.Target] = true
			r.Packages = append(r.Packages, e.Target)
		}
		if (e.Verdict == "deny" || e.Verdict == "ask") && e.Kind != "net.egress" {
			r.Blocked = append(r.Blocked, ReportEffect{Verdict: e.Verdict, Kind: e.Kind, Target: e.Target, Reason: e.Reason})
			r.Attention = append(r.Attention, ReportItem{What: "blocked", Target: e.Target, Why: e.Verdict + " by " + orUnnamed(e.Reason)})
		}
	}
	for _, kind := range sortedKeys(dropped) {
		r.Attention = append(r.Attention, ReportItem{What: "log", Target: kind,
			Why: fmt.Sprintf("%d refusals not logged: more than %d a second", dropped[kind], effects.RefuseRate)})
	}
	secrets := knownSecrets(s.Workspace)
	out := linksOut(s, cs)
	for _, in := range intents {
		r.Outbox = append(r.Outbox, ReportIntent{ID: in.ID, Kind: in.Kind, Argv: in.Argv, Status: in.Status, Files: in.Files, Request: in.Request, RequestDigest: in.RequestDigest, Result: in.TypedResult()})
		if (in.Status == outbox.Pending || in.Status == string(operation.Approved)) && intentHasSecret(in, secrets) {
			r.Attention = append(r.Attention, ReportItem{What: "secret", Target: in.ID, Why: "`" + outbox.Line(in.Argv) + "` carries a value from a secret file"})
		}
		switch in.Status {
		case outbox.Pending, string(operation.Approved):
			why := "`" + outbox.Line(in.Argv) + "` waits for apply"
			if in.Kind == outbox.KindCmd && out > 0 {
				why += fmt.Sprintf("; %d links this session adds lead out of the workspace, and apply holds it while one does, unless it leads to an installed program (`airbag apply --trust-links` runs it anyway)", out)
			}
			r.Attention = append(r.Attention, ReportItem{What: "intent", Target: in.ID, Why: why})
		case outbox.Unknown:
			r.Attention = append(r.Attention, ReportItem{What: "intent", Target: in.ID, Why: "outcome unknown: " + in.Output +
				"; once checked, `airbag outbox resolve " + in.ID + " done|failed " + s.ID + "` lets the intents after it run"})
		}
	}
	sort.SliceStable(r.Attention, func(i, j int) bool { return attentionRank(r.Attention[i].What) < attentionRank(r.Attention[j].What) })
	return r
}

// linksOut counts the links cs adds whose target, as the agent wrote
// it, is outside the workspace. Apply holds the session's deferred
// commands while such a link is in the real files, unless it leads to an
// installed program; a link review cannot read counts.
func linksOut(s *session.Session, cs []Change) int {
	in := func(p, dir string) bool {
		if dir == "" {
			return false
		}
		dir = filepath.Clean(dir)
		return p == dir || strings.HasPrefix(p, dir+string(filepath.Separator))
	}
	n := 0
	for _, c := range cs {
		if c.Type != fs.ModeSymlink || c.Kind == Deleted {
			continue
		}
		t, err := os.Readlink(c.Upper)
		if err != nil {
			n++
			continue
		}
		if !filepath.IsAbs(t) {
			t = filepath.Join(filepath.Dir(c.Path), t)
		}
		t = filepath.Clean(t)
		if !in(t, s.Workspace) && !in(t, s.WorkspaceID.Real) {
			n++
		}
	}
	return n
}

func attentionRank(what string) int {
	return map[string]int{"secret": 0, "change": 1, "deletions": 2, "intent": 3, "blocked": 4, "log": 5}[what]
}

func orUnnamed(rule string) string {
	if rule == "" {
		return "policy"
	}
	return rule
}

func WriteJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteAttention prints only what needs a decision, one line each; an
// empty review prints that nothing does.
func WriteAttention(w io.Writer, r Report) {
	if len(r.Attention) == 0 {
		fmt.Fprintf(w, "Session %s: nothing needs a decision beyond the diff (%d changes).\n", r.Session.ID, len(r.Changes))
		return
	}
	fmt.Fprintf(w, "Session %s: %d things need a decision\n", r.Session.ID, len(r.Attention))
	for _, a := range r.Attention {
		fmt.Fprintf(w, "  %-9s %-40s %s\n", a.What, clip(OneLine(a.Target), 40), a.Why)
	}
}
