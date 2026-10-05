// airbag runs a coding agent in a copy-on-write branch of your machine.
// Nothing it does reaches the real world until you review and apply it.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	"github.com/getjump/airbag/internal/term"
)

// version is set at release: -ldflags "-X main.version=v0.1.0".
var version = "dev"

const usage = `airbag — approve outcomes, not commands

  airbag run [--allow HOST]... [--no-home] [--session ID|last] -- AGENT [ARGS...]
      run the agent in a branch of the workspace and $HOME (--session: on the
      branch of a stopped session, with its outbox and labels)
  airbag review [ID] [--json | --attention]
                              what the agent changed, sent and queued; --json for
                              tools, --attention for only what needs a decision
  airbag diff [ID] [PATH...]  unified diff of changed files
  airbag apply [ID] [-i] [--only PATH]... [--yes] [--force] [--trust-git]
                              write the branch (or part of it) to the real files,
                              then run the outbox
  airbag apply [ID] --branch NAME
                              put the result on a new git branch instead;
                              the working tree is not touched
  airbag rollback [ID]        undo the last apply; its changes go back to the session
  airbag discard [ID] [--yes] [--force]
                              throw the branch away; --force also when it holds
                              your versions of paths a rollback left
  airbag ls                   list sessions
  airbag log [ID]             raw effect log
  airbag approve [ID]         list or approve requests blocked by an "ask" rule
  airbag doctor               check that this machine can run airbag
  airbag capabilities [--json] describe the compiled execution boundary and limits

run: --backend=native|gvisor|microvm; --require-isolation=any|shared-kernel|application-kernel|virtual-machine
     unavailable backends and unmet requirements fail before creating a session

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
	if shim.IsDeferred(filepath.Base(os.Args[0])) {
		shim.Deferred(filepath.Base(os.Args[0]), os.Args[1:])
		return
	}
	if len(os.Args) >= 4 && os.Args[1] == "hook" {
		cmdHook(os.Args[2], os.Args[3])
		return
	}
	if len(os.Args) >= 3 && os.Args[1] == sandbox.InitArg {
		sandbox.Init(os.Args[2], len(os.Args) > 3 && os.Args[3] == "tty")
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == sandbox.GuestArg {
		os.Exit(sandbox.Guest(os.Args[2:]))
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
		err = cmdReviewArgs(args)
	case "diff":
		err = cmdDiff(args)
	case "apply":
		err = cmdApply(args)
	case "discard":
		err = cmdDiscard(args)
	case "rollback":
		err = cmdRollback(args)
	case "ls", "list":
		err = cmdList()
	case "log":
		err = withSession(args, cmdLog)
	case "doctor":
		err = cmdDoctor()
	case "capabilities":
		err = cmdCapabilities(args, os.Stdout)
	case "approve":
		err = cmdApprove(args)
	case "version", "--version":
		fmt.Println("airbag", version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "airbag: %s\n", term.String(err.Error()))
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
	backend := fs.String("backend", "native", "execution backend: native, gvisor or microvm")
	rootfs := fs.String("runtime-rootfs", "", "trusted root filesystem directory for an optional backend")
	runtimeBin := fs.String("runtime-bin", "", "operator-supplied runsc or Firecracker executable")
	kernel := fs.String("runtime-kernel", "", "microVM kernel image")
	requireIsolation := fs.String("require-isolation", "any", "require an exact isolation boundary; never fall back")
	var allow stringList
	fs.Var(&allow, "allow", "extra host to allow, e.g. api.github.com or *.example.com (repeatable)")
	noHome := fs.Bool("no-home", false, "do not branch $HOME (it stays read-only)")
	var passEnv stringList
	fs.Var(&passEnv, "pass-env", "give the agent this credential-like environment variable (repeatable)")
	strict := fs.Bool("strict", false, "keep the agent from creating user namespaces; breaks the agents' own sandboxes and Chromium's sandbox")
	resume := fs.String("session", "", "run on the branch of a stopped session (its ID, or last) instead of a new one")
	nixDaemon := fs.Bool("nix-daemon", false, "let the agent use the Nix daemon; its builds and substitutes reach the network outside airbag's proxy")
	_ = fs.Parse(args)
	argv := fs.Args()
	if len(argv) == 0 {
		return 2, errors.New("usage: airbag run [flags] -- AGENT [ARGS...]")
	}
	execution, err := sandbox.SelectBackend(*backend, *requireIsolation)
	if err != nil {
		return 2, err
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
	for _, c := range pol.Credentials {
		allow = append(allow, c.Hosts...) // a credential's hosts are reachable
	}
	allow, forwards, err := session.ParseForwards(allow)
	if err != nil {
		return 1, err
	}
	hidden := append(append([]string{}, sandbox.DefaultHidden...), pol.Hide...)
	var hiddenHost []string
	for _, p := range sandbox.HostSockets {
		if !(*nixDaemon && p == sandbox.NixDaemonSocket) {
			hiddenHost = append(hiddenHost, p)
		}
	}
	for i := 0; i < len(hidden); i++ {
		if filepath.IsAbs(hidden[i]) {
			hiddenHost = append(hiddenHost, hidden[i])
			hidden = slices.Delete(hidden, i, i+1)
			i--
		}
	}
	if runtime.GOOS == "linux" {
		// In a Linux VM on a Mac the Mac's homes are mounted too.
		hiddenHost = append(hiddenHost, sandbox.MacHomesHidden(sandbox.MacHomeRoots)...)
	}
	if *nixDaemon {
		fmt.Fprintln(os.Stderr, "airbag: warning: --nix-daemon: Nix builds and substitutes run outside the sandbox and reach the network without the proxy")
	}
	runtimeConfig, err := sandbox.PreflightRuntime(execution, session.RuntimeConfig{RootFS: *rootfs, Binary: *runtimeBin, Kernel: *kernel}, ws, !*noHome, *nixDaemon, len(forwards), pol)
	if err != nil {
		return 2, err
	}
	var s *session.Session
	if *resume != "" {
		// Same branch, same outbox and labels; this run's command, plus
		// whatever this run's flags add.
		if s, err = session.ResumeChecked(*resume, ws, func(s *session.Session) error {
			if err := validateExecution(s, execution, *requireIsolation); err != nil {
				return err
			}
			if s.Runtime != runtimeConfig {
				return errors.New("resume requires the same runtime rootfs, binary and kernel")
			}
			return nil
		}); err != nil {
			return 1, err
		}
		s.Backend, s.Isolation = execution.Name, execution.Isolation
		if s.RequireIsolation == "" || *requireIsolation != "any" {
			s.RequireIsolation = *requireIsolation
		}
		s.Argv, s.Cwd = argv, cwd
		for _, h := range allow {
			if !slices.Contains(s.Allow, h) {
				s.Allow = append(s.Allow, h)
			}
		}
		for _, k := range passEnv {
			if !slices.Contains(s.PassEnv, k) {
				s.PassEnv = append(s.PassEnv, k)
			}
		}
		s.Strict = s.Strict || *strict
		for _, f := range forwards {
			if !slices.Contains(s.Forwards, f) {
				s.Forwards = append(s.Forwards, f)
			}
		}
		if err := s.Save(); err != nil {
			return 1, err
		}
		fmt.Fprintf(os.Stderr, "airbag: resuming session %s (run %d) on its branch\n", s.ID, s.Runs)
	} else {
		meta := session.Meta{
			Backend: execution.Name, Isolation: execution.Isolation, RequireIsolation: *requireIsolation, Runtime: runtimeConfig,
			Workspace: ws, Home: home, OverHome: !*noHome,
			UID: os.Getuid(), GID: os.Getgid(), Argv: argv, Cwd: cwd,
			Allow:       append(append([]string{}, proxy.DefaultAllow...), allow...),
			Passthrough: sandbox.DefaultPassthrough, Hidden: hidden, HiddenHost: hiddenHost,
			PassEnv: passEnv, Strict: *strict, Forwards: forwards,
		}
		if execution.Name != "native" {
			meta.OverHome, meta.Clone, meta.Passthrough = false, true, nil
		}
		if runtime.GOOS == "darwin" {
			// The macOS prototype: the workspace branch is a clone, $HOME
			// has none (docs/macos.md).
			meta.OverHome, meta.Clone = false, true
		}
		s, err = session.Create(meta)
		if err != nil {
			return 1, err
		}
	}
	fmt.Fprintf(os.Stderr, "airbag: backend %s · isolation %s\n", execution.Name, execution.Isolation)
	if filepath.Base(argv[0]) == "codex" && !slices.Contains(argv, "--dangerously-bypass-approvals-and-sandbox") && !slices.Contains(argv, "--yolo") {
		if *strict {
			fmt.Fprintln(os.Stderr, "airbag: warning: Codex's own sandbox cannot start under --strict (no user namespaces), so its commands will fail; airbag is the sandbox, run codex with --dangerously-bypass-approvals-and-sandbox")
		} else {
			fmt.Fprintln(os.Stderr, "airbag: tip: Codex's own sandbox asks per command and cuts the network; airbag already branches the machine, so --dangerously-bypass-approvals-and-sandbox leaves the review to the end")
		}
	}
	fmt.Fprintf(os.Stderr, "airbag: session %s · branch of %s%s · network: allowlist only\n",
		s.ID, ws, map[bool]string{true: " and ~", false: ""}[s.OverHome])
	var hiddenEnv []string
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		if sandbox.Credential(k, v) && !slices.Contains(passEnv, k) {
			hiddenEnv = append(hiddenEnv, k)
		}
	}
	if len(hiddenEnv) > 0 {
		fmt.Fprintf(os.Stderr, "airbag: hidden from the agent: %s (--pass-env NAME keeps one)\n", strings.Join(hiddenEnv, ", "))
	}
	if len(pol.Sources) > 1 {
		fmt.Fprintf(os.Stderr, "airbag: policy: %s\n", strings.Join(pol.Sources, " + "))
	}
	// The current policy decides which programs get a shim, for a
	// resumed session too.
	if d := pol.DeferPrograms(); !slices.Equal(d, s.Deferred) {
		s.Deferred = d
		if err := s.Save(); err != nil {
			return 1, err
		}
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
	out, err := exec.CommandContext(context.Background(), "git", "-C", cwd, "rev-parse", "--show-toplevel").Output() //nolint:gosec // git in the user's own working directory
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

// cmdReviewArgs: review [ID] [--json | --attention].
func cmdReviewArgs(args []string) error {
	fs := flag.NewFlagSet("review", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print the review as JSON (schema "+review.Schema+")")
	attention := fs.Bool("attention", false, "print only what needs a decision")
	_ = fs.Parse(reorder(args))
	return withSession(fs.Args(), func(s *session.Session) error {
		cs, err := review.Scan(s)
		if err != nil {
			return err
		}
		effs, _ := effects.Read(s.EffectsPath())
		intents := listIntents(s)
		sts, _ := steps.Read(s)
		switch {
		case *asJSON:
			// JSON escapes control characters itself.
			return review.WriteJSON(os.Stdout, review.BuildReport(s, cs, effs, intents, sts))
		case *attention:
			out := term.Safe(os.Stdout)
			defer out.Flush()
			review.WriteAttention(out, review.BuildReport(s, cs, effs, intents, sts))
		default:
			out := term.Safe(os.Stdout)
			defer out.Flush()
			review.Render(out, s, cs, effs, intents, sts)
		}
		return nil
	})
}

func cmdLog(s *session.Session) error {
	effs, err := effects.Read(s.EffectsPath())
	out := term.Safe(os.Stdout)
	defer out.Flush()
	for _, e := range effs {
		fmt.Fprintf(out, "%s  %-16s %-6s %s %s\n", e.Time.Format("15:04:05"), e.Kind, e.Verdict, e.Target, e.Reason)
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
	out := term.Safe(os.Stdout)
	defer out.Flush()
	for _, c := range cs {
		if c.IsDir() || !matches(c, args) || (strings.HasPrefix(c.Rel, ".git/") && len(args) == 0) {
			continue
		}
		review.Diff(out, c)
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
	branch := fs.String("branch", "", "put the workspace result on this new git branch; the working tree is not touched")
	trustGit := fs.Bool("trust-git", false, "run the session's pushes although it changed .git/config or git hooks (hooks stay off)")
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
	defer func() { _ = box.Close() }()
	out := term.Safe(os.Stdout)
	defer out.Flush()
	return apply.Apply(s, cs, box, apply.Options{
		Yes: *yes, Force: *force, Interactive: *inter, Only: only, Branch: *branch, TrustGit: *trustGit, In: os.Stdin, Out: out})
}

// cmdRollback undoes the last apply: of session ID, or of the newest
// session of this workspace that was applied, fully or in part.
func cmdRollback(args []string) error {
	var s *session.Session
	var err error
	if len(args) > 0 {
		s, err = session.Load(filepath.Join(session.Root(), args[0]))
	} else {
		s, err = lastApplied()
	}
	if err != nil {
		return err
	}
	var done []string
	for _, it := range listIntents(s) {
		if it.Status == outbox.Done || it.Status == outbox.Unknown {
			done = append(done, fmt.Sprintf("intent %s `%s` (%s)", it.ID, strings.Join(it.Argv, " "), it.Status)) //nolint:gocritic // backquotes for display, as in apply's messages; %#q would switch to Go quoting
		}
	}
	out := term.Safe(os.Stdout)
	defer out.Flush()
	return apply.Rollback(s, done, out)
}

func lastApplied() (*session.Session, error) {
	cwd, _ := os.Getwd()
	ws := workspace(cwd)
	all, err := session.List()
	if err != nil {
		return nil, err
	}
	for _, s := range all {
		if s.Workspace != ws || s.Status == session.StatusDiscarded {
			continue
		}
		if _, err := os.Stat(filepath.Join(s.Dir, "undo")); err == nil {
			return s, nil
		}
	}
	return nil, fmt.Errorf("no applied session for %s", ws)
}

// listIntents reads a session's outbox; a session without one has none.
func listIntents(s *session.Session) []outbox.Intent {
	box, err := outbox.Open(s.EffectsPath())
	if err != nil {
		return nil
	}
	defer func() { _ = box.Close() }()
	intents, _ := box.List()
	return intents
}

func cmdDiscard(args []string) error {
	fs := flag.NewFlagSet("discard", flag.ExitOnError)
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	force := fs.Bool("force", false, "discard also the versions from before an apply that a rollback left in the session")
	_ = fs.Parse(reorder(args))
	s, err := findSession(fs.Arg(0))
	if err != nil {
		return err
	}
	if s.Status == session.StatusRunning {
		return fmt.Errorf("session %s is still running", s.ID)
	}
	if !*force {
		// After a partial rollback, or an apply that did not finish, the
		// session may hold the only copy of the user's own files.
		held, err := apply.HeldVersions(s)
		if err != nil {
			return fmt.Errorf("session %s: read its undo journal: %w; nothing discarded", s.ID, err)
		}
		if len(held) > 0 {
			var b strings.Builder
			for _, h := range held {
				fmt.Fprintf(&b, "\n  %s: kept at %s", h.Path, h.Saved)
			}
			return fmt.Errorf("session %s holds your versions from before an apply of paths that were not rolled back:%s\n"+
				"run `airbag rollback %s` once those paths are as the apply left them, or copy what you need from there; "+
				"`airbag discard --force %s` deletes them; nothing discarded", s.ID, b.String(), s.ID, s.ID)
		}
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
		asks, err := policy.ReadAsks(s.Dir)
		if err != nil {
			return err
		}
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
		case (a == "--only" || a == "-only" || a == "--branch" || a == "-branch") && i+1 < len(args):
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
	out := term.Safe(os.Stdout)
	defer out.Flush()
	for _, s := range all {
		fmt.Fprintf(out, "%s  %-9s %s  %-30s %s\n", s.ID, s.Status, s.Created.Format("2006-01-02 15:04"), s.Workspace, strings.Join(s.Argv, " "))
	}
	return nil
}
