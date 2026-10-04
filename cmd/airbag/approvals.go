package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/policy"
	"github.com/getjump/airbag/internal/sandbox"
	"github.com/getjump/airbag/internal/session"
)

// cmdDecide is `airbag approve` and `airbag deny`. Anything can call it:
// a person, `airbag watch`, a notification action, a chat bot.
//
//	airbag approve                     list pending requests
//	airbag approve [--always] [S] ID   approve; --always also from now on
//	airbag deny [S] ID                 refuse
//
// ID is a-N, all, or S/a-N with the session.
func cmdDecide(args []string, decision string) error {
	always := false
	var id, sid string
	for _, a := range args {
		switch {
		case a == "--always" && decision == policy.Approved:
			always = true
		case strings.HasPrefix(a, "s-") && !strings.Contains(a, "/"):
			sid = a
		default:
			s, i := policy.SplitAskID(a)
			if s != "" {
				sid = s
			}
			id = i
		}
	}
	s, err := findSession(sid)
	if err != nil {
		return err
	}
	asks, err := policy.OpenAsks(s.EffectsPath())
	if err != nil {
		return err
	}
	defer asks.Close()
	if id == "" {
		all, _ := asks.List()
		n := 0
		for _, a := range all {
			if a.Decision == policy.Pending {
				fmt.Printf("%-5s %-24s %s  %s\n", a.ID, a.Rule, a.What, a.Message)
				n++
			}
		}
		if n == 0 {
			fmt.Println("No pending requests.")
		}
		return nil
	}
	done, err := asks.Decide(id, decision)
	if len(done) == 0 {
		return err
	}
	log, lerr := effects.Open(s.EffectsPath())
	for _, a := range done {
		verdict := decision
		if always {
			verdict = "approved always"
			home, _ := os.UserHomeDir()
			if err := policy.AddApproval(policy.ApprovalsPath(home), policy.Approval{
				Rule: a.Rule, Effect: a.What, Workspace: s.Workspace, Added: time.Now().UTC()}); err != nil {
				return err
			}
		}
		if lerr == nil {
			log.Add(effects.Effect{Kind: "ask.decided", Target: a.ID, Verdict: verdict, Reason: a.Rule, Predict: []string{a.What}})
		}
		switch {
		case always:
			fmt.Printf("Approved %s: %s (%s), from now on in %s. The agent can retry.\n", a.ID, a.What, a.Rule, s.Workspace)
		case decision == policy.Approved:
			fmt.Printf("Approved %s: %s (%s). The agent can retry.\n", a.ID, a.What, a.Rule)
		default:
			fmt.Printf("Denied %s: %s (%s).\n", a.ID, a.What, a.Rule)
		}
	}
	if lerr == nil {
		log.Close()
	}
	return err
}

// Event is one line of `airbag events`: an effect from a session's log,
// or the start and end of a session.
type Event struct {
	Session   string `json:"session"`
	Workspace string `json:"workspace"`
	effects.Effect
	Ask *sandbox.AskEvent `json:"ask,omitempty"`
}

// follow reports the events of every session (or one), as they happen.
// Sessions already over when it starts are skipped; requests still
// pending in running sessions are reported first.
func follow(only string, emit func(Event)) {
	type state struct {
		last   int64
		status string
	}
	seen := map[string]*state{}
	first := true
	for {
		all, _ := session.List()
		for _, s := range all {
			if only != "" && s.ID != only {
				continue
			}
			st := seen[s.ID]
			if st == nil {
				st = &state{}
				seen[s.ID] = st
				if first && s.Status != session.StatusRunning {
					st.status = s.Status
					if effs, _ := effects.Read(s.EffectsPath()); len(effs) > 0 {
						st.last = effs[len(effs)-1].ID
					}
					continue
				}
				emit(Event{Session: s.ID, Workspace: s.Workspace, Effect: effects.Effect{
					Time: s.Created, Kind: "session.start", Target: strings.Join(s.Argv, " ")}})
				if first {
					st.last = pendingFirst(s, emit)
				}
				st.status = session.StatusRunning // a short session may be over already
			}
			effs, _ := effects.ReadSince(s.EffectsPath(), st.last)
			for _, e := range effs {
				emit(eventOf(s, e))
				st.last = e.ID
			}
			if st.status == session.StatusRunning && s.Status != session.StatusRunning {
				emit(Event{Session: s.ID, Workspace: s.Workspace, Effect: effects.Effect{
					Time: time.Now(), Kind: "session.end", Verdict: s.Status, Reason: fmt.Sprint("exit ", s.ExitCode)}})
			}
			st.status = s.Status
		}
		first = false
		time.Sleep(500 * time.Millisecond)
	}
}

// pendingFirst reports the pending requests of a session joined while
// running, and returns the log position to tail from.
func pendingFirst(s *session.Session, emit func(Event)) int64 {
	effs, _ := effects.Read(s.EffectsPath())
	var last int64
	if len(effs) > 0 {
		last = effs[len(effs)-1].ID
	}
	asks, err := policy.OpenAsks(s.EffectsPath())
	if err != nil {
		return last
	}
	defer asks.Close()
	all, _ := asks.List()
	for _, e := range effs {
		if e.Kind != "ask" {
			continue
		}
		for _, a := range all {
			if a.ID == e.Target && a.Decision == policy.Pending {
				emit(eventOf(s, e))
			}
		}
	}
	return last
}

func eventOf(s *session.Session, e effects.Effect) Event {
	ev := Event{Session: s.ID, Workspace: s.Workspace, Effect: e}
	if e.Kind == "ask" {
		if asks, err := policy.OpenAsks(s.EffectsPath()); err == nil {
			if r, err := asks.Get(e.Target); err == nil {
				a := sandbox.NewAskEvent(s, r)
				ev.Ask = &a
			}
			asks.Close()
		}
	}
	return ev
}

// cmdEvents prints events as JSON lines: one session's log, or with -f
// every session as it happens, for scripts and bridges.
func cmdEvents(args []string) error {
	f, id := false, ""
	for _, a := range args {
		if a == "-f" || a == "--follow" {
			f = true
		} else {
			id = a
		}
	}
	enc := json.NewEncoder(os.Stdout)
	if f {
		follow(id, func(e Event) { _ = enc.Encode(e) })
		return nil
	}
	s, err := findSession(id)
	if err != nil {
		return err
	}
	effs, err := effects.Read(s.EffectsPath())
	for _, e := range effs {
		_ = enc.Encode(eventOf(s, e))
	}
	return err
}

// cmdWatch shows what running sessions do and asks you about requests
// as they come: y approves, n denies, a approves from now on.
func cmdWatch(args []string) error {
	verbose := len(args) > 0 && (args[0] == "-v" || args[0] == "--verbose")
	events := make(chan Event, 1024)
	go follow("", func(e Event) { events <- e })
	in := bufio.NewReader(os.Stdin)
	fmt.Println("airbag watch: requests from running sessions appear here. Ctrl-C to stop.")
	for e := range events {
		short := e.Session
		if len(short) > 8 {
			short = short[:8]
		}
		at := e.Time.Local().Format("15:04:05")
		switch {
		case e.Kind == "ask" && e.Ask != nil:
			fmt.Printf("%s %s ? %s %s: %s", at, short, e.Ask.ID, e.Ask.Rule, e.Ask.What)
			if e.Ask.Message != "" {
				fmt.Printf(" (%s)", e.Ask.Message)
			}
			fmt.Print("\n  [y]es [n]o [a]lways [s]kip: ")
			line, err := in.ReadString('\n')
			if err != nil && line == "" {
				return nil
			}
			ref := e.Session + "/" + e.Ask.ID
			var derr error
			switch strings.ToLower(strings.TrimSpace(line)) {
			case "y", "yes":
				derr = cmdDecide([]string{ref}, policy.Approved)
			case "a", "always":
				derr = cmdDecide([]string{"--always", ref}, policy.Approved)
			case "n", "no":
				derr = cmdDecide([]string{ref}, policy.Denied)
			default:
				fmt.Printf("  left pending: %s\n", e.Ask.Approve)
			}
			if derr != nil {
				fmt.Printf("  %v\n", derr)
			}
		case e.Kind == "session.start":
			fmt.Printf("%s %s started: %s\n", at, short, e.Target)
		case e.Kind == "session.end":
			fmt.Printf("%s %s ended (%s, %s): airbag review %s\n", at, short, e.Verdict, e.Reason, e.Session)
		case e.Kind == "ask.decided":
			fmt.Printf("%s %s %s %s\n", at, short, e.Verdict, e.Target)
		case verbose || e.Verdict == "deny" || e.Verdict == "cut" || e.Verdict == "taint" || e.Verdict == "untrusted" || e.Verdict == "defer":
			fmt.Printf("%s %s %-14s %-6s %s %s\n", at, short, e.Kind, e.Verdict, e.Target, e.Reason)
		}
	}
	return nil
}
