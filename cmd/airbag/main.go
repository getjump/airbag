// airbag runs a coding agent in a copy-on-write branch of your machine.
// Nothing it does reaches the real world until you review and apply it.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/getjump/airbag/internal/apply"
	"github.com/getjump/airbag/internal/control"
	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/outbox"
	"github.com/getjump/airbag/internal/policy"
	"github.com/getjump/airbag/internal/proxy"
	"github.com/getjump/airbag/internal/review"
	"github.com/getjump/airbag/internal/sandbox"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/internal/shim"
	"github.com/getjump/airbag/internal/steps"
)

const usage = `airbag — approve outcomes, not commands

  airbag run [--allow HOST]... [--no-home] -- AGENT [ARGS...]
      run the agent in a branch of the workspace and $HOME
  airbag review [ID]          what the agent changed, sent and queued
  airbag diff [ID] [PATH...]  unified diff of changed files
  airbag apply [ID] [-i] [--only PATH]... [--yes] [--force]
                              write the branch (or part of it) to the real files,
                              then run the outbox
  airbag discard [ID] [--yes] throw the branch away
  airbag ls                   list sessions
  airbag log [ID]             raw effect log
  airbag approve [ID]         list or approve requests blocked by an "ask" rule
  airbag doctor               check that this machine can run airbag

ID defaults to the newest open session of the current workspace.
`

func main() {
	switch name := filepath.Base(os.Args[0]); name {
	case "git":
		shim.Git(os.Args[1:])
		return
	case "bash", "sh":
		shim.Shell(name, os.Args[1:])
		return
	}
	if len(os.Args) >= 4 && os.Args[1] == "hook" {
		cmdHook(os.Args[2], os.Args[3])
		return
	}
	if len(os.Args) >= 3 && os.Args[1] == sandbox.InitArg {
		sandbox.Init(os.Args[2])
		return
	}
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	code := 0
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "run":
		code, err = cmdRun(args)
	case "review", "status":
		err = withSession(args, cmdReview)
	case "diff":
		err = cmdDiff(args)
	case "apply":
		err = cmdApply(args)
	case "discard":
		err = cmdDiscard(args)
	case "ls", "list":
		err = cmdList()
	case "log":
		err = withSession(args, cmdLog)
	case "doctor":
		err = cmdDoctor()
	case "approve":
		err = cmdApprove(args)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "airbag: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, strings.Split(v, ",")...); return nil }

func cmdRun(args []string) (int, error) {
	if os.Getenv("AIRBAG_SESSION") != "" {
		return 1, errors.New("already inside an airbag session")
	}
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var allow stringList
	fs.Var(&allow, "allow", "extra host to allow, e.g. api.github.com or *.example.com (repeatable)")
	noHome := fs.Bool("no-home", false, "do not branch $HOME (it stays read-only)")
	var passEnv stringList
	fs.Var(&passEnv, "pass-env", "give the agent this credential-like environment variable (repeatable)")
	strict := fs.Bool("strict", false, "keep the agent from creating user namespaces; breaks the agents' own sandboxes and Chromium's sandbox")
	_ = fs.Parse(args)
	argv := fs.Args()
	if len(argv) == 0 {
		return 2, errors.New("usage: airbag run [flags] -- AGENT [ARGS...]")
	}
	if env := os.Getenv("AIRBAG_ALLOW"); env != "" {
		allow = append(allow, strings.Split(env, ",")...)
	}
	cwd, _ := os.Getwd()
	home, err := os.UserHomeDir()
	if err != nil {
		return 1, err
	}
	ws := workspace(cwd)
	if ws == home || ws == "/" {
		return 1, fmt.Errorf("refusing to use %s as the workspace; cd into a project", ws)
	}
	pol, err := policy.Load(ws, home)
	if err != nil {
		return 1, fmt.Errorf("policy: %w", err)
	}
	allow = append(allow, pol.Allow...)
	s, err := session.Create(session.Meta{
		Workspace: ws, Home: home, OverHome: !*noHome,
		UID: os.Getuid(), GID: os.Getgid(), Argv: argv, Cwd: cwd,
		Allow:       append(append([]string{}, proxy.DefaultAllow...), allow...),
		Passthrough: sandbox.DefaultPassthrough, Hidden: sandbox.DefaultHidden,
		PassEnv: passEnv, Strict: *strict,
	})
	if err != nil {
		return 1, err
	}
	if filepath.Base(argv[0]) == "codex" && !slices.Contains(argv, "--dangerously-bypass-approvals-and-sandbox") && !slices.Contains(argv, "--yolo") {
		if *strict {
			fmt.Fprintln(os.Stderr, "airbag: warning: Codex's own sandbox cannot start under --strict (no user namespaces), so its commands will fail; airbag is the sandbox, run codex with --dangerously-bypass-approvals-and-sandbox")
		} else {
			fmt.Fprintln(os.Stderr, "airbag: tip: Codex's own sandbox asks per command and cuts the network; airbag already branches the machine, so --dangerously-bypass-approvals-and-sandbox leaves the review to the end")
		}
	}
	fmt.Fprintf(os.Stderr, "airbag: session %s · branch of %s%s · network: allowlist only\n",
		s.ID, ws, map[bool]string{true: " and ~", false: ""}[s.OverHome])
	var hidden []string
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		if sandbox.Credential(k, v) && !slices.Contains(passEnv, k) {
			hidden = append(hidden, k)
		}
	}
	if len(hidden) > 0 {
		fmt.Fprintf(os.Stderr, "airbag: hidden from the agent: %s (--pass-env NAME keeps one)\n", strings.Join(hidden, ", "))
	}
	if len(pol.Sources) > 1 {
		fmt.Fprintf(os.Stderr, "airbag: policy: %s\n", strings.Join(pol.Sources, " + "))
	}
	code, err := sandbox.Run(s, proxy.Allowlist(s.Allow), pol)
	if err != nil {
		return code, err
	}
	cs, _ := review.Scan(s)
	intents := listIntents(s)
	nws, nhome := 0, 0
	for _, c := range cs {
		if c.Layer == "ws" {
			nws++
		} else {
			nhome++
		}
	}
	fmt.Fprintf(os.Stderr, "airbag: session %s ended (exit %d): %d changes in the workspace, %d in ~, %d queued intents. Next: airbag review\n",
		s.ID, code, nws, nhome, len(intents))
	return code, nil
}

// cmdHook runs inside the sandbox as an agent hook. It always exits 0:
// exit 2 would block the agent's tool call, and enforcement does not
// live in hooks anyway.
func cmdHook(agent, event string) {
	payload, _ := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
	if out, err := control.Hook(agent, event, payload); err == nil && len(out) > 0 && string(out) != "{}" {
		_, _ = os.Stdout.Write(out)
	}
	os.Exit(0)
}

// workspace is the git toplevel, or the current directory.
func workspace(cwd string) string {
	out, err := exec.Command("git", "-C", cwd, "rev-parse", "--show-toplevel").Output()
	if err == nil {
		if p := strings.TrimSpace(string(out)); p != "" {
			return p
		}
	}
	return cwd
}

func findSession(id string) (*session.Session, error) {
	cwd, _ := os.Getwd()
	return session.Find(id, workspace(cwd))
}

func withSession(args []string, f func(*session.Session) error) error {
	id := ""
	if len(args) > 0 {
		id = args[0]
	}
	s, err := findSession(id)
	if err != nil {
		return err
	}
	return f(s)
}

func cmdReview(s *session.Session) error {
	cs, err := review.Scan(s)
	if err != nil {
		return err
	}
	effs, _ := effects.Read(s.EffectsPath())
	intents := listIntents(s)
	sts, _ := steps.Read(s)
	review.Render(os.Stdout, s, cs, effs, intents, sts)
	return nil
}

func cmdLog(s *session.Session) error {
	effs, err := effects.Read(s.EffectsPath())
	for _, e := range effs {
		fmt.Printf("%s  %-16s %-6s %s %s\n", e.Time.Format("15:04:05"), e.Kind, e.Verdict, e.Target, e.Reason)
	}
	return err
}

func cmdDiff(args []string) error {
	id := ""
	if len(args) > 0 && strings.HasPrefix(args[0], "s-") {
		id, args = args[0], args[1:]
	}
	s, err := findSession(id)
	if err != nil {
		return err
	}
	cs, err := review.Scan(s)
	if err != nil {
		return err
	}
	for _, c := range cs {
		if c.IsDir() || !matches(c, args) || (strings.HasPrefix(c.Rel, ".git/") && len(args) == 0) {
			continue
		}
		review.Diff(os.Stdout, c)
	}
	return nil
}

func matches(c review.Change, paths []string) bool {
	if len(paths) == 0 {
		return true
	}
	for _, p := range paths {
		p = strings.TrimPrefix(p, "~/")
		if abs, err := filepath.Abs(p); err == nil && strings.HasPrefix(c.Path, abs) {
			return true
		}
		if strings.HasPrefix(c.Rel, p) {
			return true
		}
	}
	return false
}

func cmdApply(args []string) error {
	fs := flag.NewFlagSet("apply", flag.ExitOnError)
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	force := fs.Bool("force", false, "overwrite files changed on the host during the session")
	inter := fs.Bool("i", false, "go through the changes one by one")
	var only stringList
	fs.Var(&only, "only", "apply only changes under this path (repeatable)")
	_ = fs.Parse(reorder(args))
	s, err := findSession(fs.Arg(0))
	if err != nil && fs.Arg(0) == "" {
		s, err = withPendingIntents()
	}
	if err != nil {
		return err
	}
	cs, err := review.Scan(s)
	if err != nil {
		return err
	}
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		return err
	}
	defer box.Close()
	return apply.Apply(s, cs, box, apply.Options{
		Yes: *yes, Force: *force, Interactive: *inter, Only: only, In: os.Stdin, Out: os.Stdout})
}

// listIntents reads a session's outbox; a session without one has none.
func listIntents(s *session.Session) []outbox.Intent {
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		return nil
	}
	defer box.Close()
	intents, _ := box.List()
	return intents
}

func cmdDiscard(args []string) error {
	fs := flag.NewFlagSet("discard", flag.ExitOnError)
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	_ = fs.Parse(reorder(args))
	s, err := findSession(fs.Arg(0))
	if err != nil {
		return err
	}
	if s.Status == session.StatusRunning {
		return fmt.Errorf("session %s is still running", s.ID)
	}
	if !*yes {
		fmt.Printf("Discard session %s and everything the agent did in it? [y/N] ", s.ID)
		var ans string
		_, _ = fmt.Scanln(&ans)
		if !strings.EqualFold(ans, "y") {
			return errors.New("aborted")
		}
	}
	if err := s.RemoveAll(); err != nil {
		return err
	}
	fmt.Printf("Discarded %s. Nothing happened.\n", s.ID)
	return nil
}

// cmdApprove lets a running agent continue past an "ask" rule:
// `airbag approve` lists pending requests, `airbag approve a-3` (or
// `all`) approves.
func cmdApprove(args []string) error {
	var id, sid string
	for _, a := range args {
		if strings.HasPrefix(a, "s-") {
			sid = a
		} else {
			id = a
		}
	}
	s, err := findSession(sid)
	if err != nil {
		return err
	}
	if id == "" {
		asks, _ := policy.ReadAsks(s.Dir)
		n := 0
		for _, a := range asks {
			if !a.Approved {
				fmt.Printf("%-5s %-24s %s  %s\n", a.ID, a.Rule, a.What, a.Message)
				n++
			}
		}
		if n == 0 {
			fmt.Println("No pending requests.")
		}
		return nil
	}
	done, err := policy.Approve(s.Dir, id)
	for _, a := range done {
		fmt.Printf("Approved %s: %s (%s). The agent can retry.\n", a.ID, a.What, a.Rule)
	}
	return err
}

// withPendingIntents finds an applied session of this workspace whose
// outbox still has intents waiting for confirmation.
func withPendingIntents() (*session.Session, error) {
	cwd, _ := os.Getwd()
	ws := workspace(cwd)
	all, err := session.List()
	if err != nil {
		return nil, err
	}
	for _, s := range all {
		if s.Workspace != ws || s.Status != session.StatusApplied {
			continue
		}
		intents := listIntents(s)
		for _, in := range intents {
			if in.Status == outbox.Pending {
				return s, nil
			}
		}
	}
	return nil, fmt.Errorf("no open session for %s", ws)
}

// reorder lets flags follow the positional ID: `airbag apply s-1 --yes`.
func reorder(args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case (a == "--only" || a == "-only") && i+1 < len(args):
			flags = append(flags, a, args[i+1])
			i++
		case strings.HasPrefix(a, "-"):
			flags = append(flags, a)
		default:
			pos = append(pos, a)
		}
	}
	return append(flags, pos...)
}

func cmdList() error {
	all, err := session.List()
	if err != nil {
		return err
	}
	for _, s := range all {
		fmt.Printf("%s  %-9s %s  %-30s %s\n", s.ID, s.Status, s.Created.Format("2006-01-02 15:04"), s.Workspace, strings.Join(s.Argv, " "))
	}
	return nil
}
