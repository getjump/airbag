// Package session stores the state of one sandboxed agent run: the
// overlay layers, the effect log, the outbox and the metadata.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	StatusRunning   = "running"
	StatusStopped   = "stopped"
	StatusApplied   = "applied"
	StatusDiscarded = "discarded"
)

type Meta struct {
	// Execution boundary and the user's persisted requirement. Empty fields
	// identify legacy native sessions, not a stronger isolation guarantee.
	Backend          string    `json:"backend,omitempty"`
	Isolation        string    `json:"isolation,omitempty"`
	RequireIsolation string    `json:"require_isolation,omitempty"`
	ID               string    `json:"id"`
	Created          time.Time `json:"created"`
	Ended            time.Time `json:"ended,omitzero"`
	Workspace        string    `json:"workspace"`
	Home             string    `json:"home"`
	OverHome         bool      `json:"over_home"`
	UID              int       `json:"uid"`
	GID              int       `json:"gid"`
	Argv             []string  `json:"argv"`
	Cwd              string    `json:"cwd"`
	Status           string    `json:"status"`
	ExitCode         int       `json:"exit_code"`
	Allow            []string  `json:"allow"`
	// Paths under $HOME that bypass the branch (agent state, logs).
	Passthrough []string `json:"passthrough"`
	// Paths under $HOME hidden from the agent (credentials).
	Hidden []string `json:"hidden"`
	// Host paths hidden from the agent (daemon sockets outside /run).
	HiddenHost []string `json:"hidden_host,omitempty"`
	// Credential-like environment variables passed to the agent anyway.
	PassEnv []string `json:"pass_env,omitempty"`
	// Strict keeps the agent from creating user namespaces.
	Strict bool `json:"strict,omitempty"`
	// GitTouched: an apply of this session wrote .git/config or git
	// hooks into the real repository. It stays set for every later
	// apply, so the session's pushes keep running untrusted.
	GitTouched bool `json:"git_touched,omitempty"`
	// Branch: the workspace result went to this branch of the real
	// repository (apply --branch) instead of the working tree.
	Branch string `json:"branch,omitempty"`
	// Forwards: TCP ports the agent reaches on its own loopback
	// (tcp://HOST:PORT in allow), each relayed by airbag to HOST:PORT.
	Forwards []Forward `json:"forwards,omitempty"`
	// Credentials the agent uses through placeholders: names, hosts,
	// the variables it sees them in, and the placeholders, kept so a
	// resumed run uses the same ones. Values are never stored.
	Credentials []Credential `json:"credentials,omitempty"`
	// Deferred: programs with a shim in the sandbox, because a
	// `defer:` entry in airbag.yaml holds some of their calls.
	Deferred []string `json:"deferred,omitempty"`
	// Clone: the workspace branch is a full copy (an APFS clone on
	// macOS) at CloneDir, not an overlayfs upper layer.
	Clone bool `json:"clone,omitempty"`
	// Runs counts the agent runs on this branch; 0 or 1 for one run.
	Runs int `json:"runs,omitempty"`
	// Baseline: real files changed after this time conflict with the
	// branch. The session's start, or the last rollback, which put the
	// files back as they were.
	Baseline time.Time `json:"baseline,omitempty"`
}

type Credential struct {
	Name        string   `json:"name"`
	Hosts       []string `json:"hosts"`
	Env         []string `json:"env,omitempty"`
	Placeholder string   `json:"placeholder"`
}

type Session struct {
	Meta
	Dir string `json:"-"`
}

// Root is where sessions live. It must sit outside $HOME and the
// workspace: overlayfs refuses an upper dir inside its own lower dir.
func Root() string {
	if d := os.Getenv("AIRBAG_HOME"); d != "" {
		return d
	}
	return filepath.Join("/var/tmp", fmt.Sprintf("airbag-%d", os.Getuid()))
}

func newID() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return "s-" + hex.EncodeToString(b)
}

func Create(m Meta) (*Session, error) {
	root := Root()
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	for _, p := range []string{m.Workspace, m.Home} {
		if p != "" && within(root, p) {
			return nil, fmt.Errorf("session root %s is inside %s; set AIRBAG_HOME elsewhere", root, p)
		}
	}
	m.ID = newID()
	m.Created = time.Now()
	m.Status = StatusRunning
	m.Runs = 1
	s := &Session{Meta: m, Dir: filepath.Join(root, m.ID)}
	for _, d := range []string{
		s.WSUpper(), s.WSWork(), s.HomeUpper(), s.HomeWork(), s.EtcUpper(), s.EtcWork(),
		s.MountDir("ws"), s.MountDir("realhome"), s.RunDir(),
	} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	if err := s.Save(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Session) WSUpper() string             { return filepath.Join(s.Dir, "ws", "upper") }
func (s *Session) WSWork() string              { return filepath.Join(s.Dir, "ws", "work") }
func (s *Session) HomeUpper() string           { return filepath.Join(s.Dir, "home", "upper") }
func (s *Session) HomeWork() string            { return filepath.Join(s.Dir, "home", "work") }
func (s *Session) EtcUpper() string            { return filepath.Join(s.Dir, "etc", "upper") }
func (s *Session) EtcWork() string             { return filepath.Join(s.Dir, "etc", "work") }
func (s *Session) MountDir(name string) string { return filepath.Join(s.Dir, "mnt", name) }
func (s *Session) RunDir() string              { return filepath.Join(s.Dir, "run") }
func (s *Session) CloneDir() string            { return filepath.Join(s.Dir, "ws", "clone") }
func (s *Session) ForwardSock(i int) string {
	return filepath.Join(s.RunDir(), fmt.Sprintf("fwd-%d.sock", i))
}

// Forward is one tcp:// entry: the agent connects to 127.0.0.1:Port in
// the sandbox, airbag connects to Host:Port.
type Forward struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

func (f Forward) String() string {
	return fmt.Sprintf("tcp://%s", net.JoinHostPort(f.Host, strconv.Itoa(f.Port)))
}

// ParseForwards splits tcp:// entries off an allowlist.
func ParseForwards(allow []string) (hosts []string, fw []Forward, err error) {
	for _, a := range allow {
		rest, ok := strings.CutPrefix(a, "tcp://")
		if !ok {
			hosts = append(hosts, a)
			continue
		}
		h, p, err := net.SplitHostPort(rest)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: want tcp://HOST:PORT", a)
		}
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return nil, nil, fmt.Errorf("%s: bad port", a)
		}
		f := Forward{Host: h, Port: port}
		if !slices.Contains(fw, f) {
			fw = append(fw, f)
		}
	}
	return hosts, fw, nil
}

// WSBranch is where the agent's version of the workspace lives: the
// clone, or the overlayfs upper layer (changes only).
func (s *Session) WSBranch() string {
	if s.Clone {
		return s.CloneDir()
	}
	return s.WSUpper()
}
func (s *Session) ProxySock() string   { return filepath.Join(s.RunDir(), "proxy.sock") }
func (s *Session) ControlSock() string { return filepath.Join(s.RunDir(), "ctl.sock") }

// CACert and CABundle: the session CA's certificate, and the machine's
// roots with it, for tools in the sandbox to trust the hosts airbag
// intercepts. Public; the CA's key never leaves memory.
func (s *Session) CACert() string   { return filepath.Join(s.RunDir(), "ca.pem") }
func (s *Session) CABundle() string { return filepath.Join(s.RunDir(), "ca-bundle.pem") }

// EffectsPath is the session database: the effect log and the outbox.
func (s *Session) EffectsPath() string { return filepath.Join(s.Dir, "effects.db") }

func (s *Session) Save() error {
	b, err := json.MarshalIndent(s.Meta, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.Dir, "meta.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.Dir, "meta.json"))
}

func Load(dir string) (*Session, error) {
	b, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return nil, err
	}
	s := &Session{Dir: dir}
	return s, json.Unmarshal(b, &s.Meta)
}

// List returns sessions, newest first.
func List() ([]*Session, error) {
	ents, err := os.ReadDir(Root())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var out []*Session
	for _, e := range ents {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "s-") {
			continue
		}
		if s, err := Load(filepath.Join(Root(), e.Name())); err == nil {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out, nil
}

// Find resolves an id, or picks the newest open session for the
// workspace when id is empty.
func Find(id, workspace string) (*Session, error) {
	if id != "" {
		return Load(filepath.Join(Root(), id))
	}
	all, err := List()
	if err != nil {
		return nil, err
	}
	for _, s := range all {
		if s.Workspace == workspace && s.Status != StatusApplied && s.Status != StatusDiscarded {
			return s, nil
		}
	}
	return nil, fmt.Errorf("no open session for %s", workspace)
}

// Resume reopens a stopped session for another run on the same branch:
// the upper layers stay, overlayfs gets fresh work directories and the
// run directory loses the sockets of the previous run.
func Resume(id, workspace string) (*Session, error) {
	return ResumeChecked(id, workspace, nil)
}

// ResumeChecked validates the chosen execution boundary before changing the
// branch, run directory, counters or status of a stopped session.
func ResumeChecked(id, workspace string, validate func(*Session) error) (*Session, error) {
	var s *Session
	if id == "last" {
		all, err := List()
		if err != nil {
			return nil, err
		}
		for _, c := range all {
			if c.Workspace == workspace && c.Status == StatusStopped {
				s = c
				break
			}
		}
		if s == nil {
			return nil, fmt.Errorf("no stopped session to resume for %s", workspace)
		}
	} else {
		var err error
		if s, err = Load(filepath.Join(Root(), id)); err != nil {
			return nil, err
		}
	}
	switch {
	case s.Workspace != workspace:
		return nil, fmt.Errorf("session %s is a branch of %s, not of %s", s.ID, s.Workspace, workspace)
	case s.Status == StatusRunning:
		return nil, fmt.Errorf("session %s is running", s.ID)
	case s.Status != StatusStopped:
		return nil, fmt.Errorf("session %s is %s; only a stopped session can be resumed", s.ID, s.Status)
	}
	if validate != nil {
		if err := validate(s); err != nil {
			return nil, err
		}
	}
	for _, d := range []string{s.WSWork(), s.HomeWork(), s.EtcWork(), s.RunDir()} {
		_ = filepath.WalkDir(d, func(p string, de os.DirEntry, err error) error {
			if err == nil && de.IsDir() {
				_ = os.Chmod(p, 0o700) //nolint:gosec // a directory: the owner needs x to remove what is inside
			}
			return nil
		})
		if err := os.RemoveAll(d); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	s.Status = StatusRunning
	s.Runs = max(s.Runs, 1) + 1
	if err := s.Save(); err != nil {
		return nil, err
	}
	return s, nil
}

// RemoveAll deletes a session. Overlay leaves a mode-000 work dir
// behind, so permissions are fixed up before removal.
func (s *Session) RemoveAll() error {
	_ = filepath.WalkDir(s.Dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(p, 0o700) //nolint:gosec // a directory: the owner needs x to remove what is inside
		}
		return nil
	})
	return os.RemoveAll(s.Dir)
}

func within(parent, p string) bool {
	rel, err := filepath.Rel(p, parent)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}
