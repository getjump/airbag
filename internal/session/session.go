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
	"syscall"
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
	Egress           string    `json:"egress,omitempty"`
	RequireIsolation string    `json:"require_isolation,omitempty"`
	ID               string    `json:"id"`
	Created          time.Time `json:"created"`
	Ended            time.Time `json:"ended,omitzero"`
	Workspace        string    `json:"workspace"`
	Home             string    `json:"home"`
	// WorkspaceID and HomeID: the directories Workspace and Home were
	// when the session began. Apply writes nothing below one that is
	// another directory now.
	WorkspaceID DirID    `json:"workspace_id,omitzero"`
	HomeID      DirID    `json:"home_id,omitzero"`
	OverHome    bool     `json:"over_home"`
	UID         int      `json:"uid"`
	GID         int      `json:"gid"`
	Argv        []string `json:"argv"`
	Cwd         string   `json:"cwd"`
	Status      string   `json:"status"`
	ExitCode    int      `json:"exit_code"`
	Allow       []string `json:"allow"`
	// Paths under $HOME that bypass the branch (agent state, logs).
	Passthrough []string `json:"passthrough"`
	// BranchHoles: paths under a Passthrough directory that stay in the
	// branch anyway (so they are reviewed and dropped on discard), e.g.
	// the memory/ sub-directory of a passed-through transcript directory.
	BranchHoles []string `json:"branch_holes,omitempty"`
	// HostConfigs: agent config files (~/.claude.json) that were in the
	// real $HOME when a run of the session began, by real path. A branch
	// copy of one the host has removed since reads as a new file; apply
	// reports the removal instead of bringing the file back. A removal
	// apply itself carried out drops the entry.
	HostConfigs []string `json:"host_configs,omitempty"`
	// Paths under $HOME hidden from the agent (credentials).
	Hidden []string `json:"hidden"`
	// Host paths hidden from the agent (daemon sockets outside /run).
	HiddenHost []string `json:"hidden_host,omitempty"`
	// Credential-like environment variables passed to the agent anyway.
	PassEnv []string `json:"pass_env,omitempty"`
	// Strict keeps the agent from creating user namespaces.
	Strict     bool   `json:"strict,omitempty"`
	Launcher   string `json:"launcher,omitempty"`
	Trustd     bool   `json:"trustd,omitempty"`
	FilePolicy bool   `json:"file_policy,omitempty"`
	ExecPolicy bool   `json:"exec_policy,omitempty"`
	// RuntimeAudit is "durable" (also the legacy empty value) or "buffered".
	RuntimeAudit   string `json:"runtime_audit,omitempty"`
	FileCache      string `json:"file_cache,omitempty"`
	RuntimeProfile bool   `json:"runtime_profile,omitempty"`
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
	// Applied: when apply last wrote each real path (a directory stands
	// for what is below it). A path changed after that, rather than after
	// Baseline, conflicts: the apply's own write is not a host edit.
	Applied map[string]time.Time `json:"applied,omitempty"`
}

// DirID is a directory as a session found it: its path with links
// resolved, its device and inode, its creation time and inode
// generation where the filesystem records them, and the filesystem's ID
// from statfs where it gives one (0 for each where it does not). Path
// and inode tell it from a link or another directory at the same path;
// the creation time and the generation tell it from a new directory
// given a removed one's inode, which ext4 does at once. The device may
// change only when the creation time and the filesystem ID both say it
// is the same directory: the same filesystem mounted again (a WSL disk,
// a btrfs subvolume, an overlay) gets a new device number but keeps its
// ID, while another filesystem mounted at the path, whose root can share
// the inode, or a btrfs snapshot, which keeps the inode and the creation
// time, has another ID. A recorded ID must match whatever the device: a
// device formatted again keeps its number. Where a filesystem records
// neither a creation time nor a generation (NFS, FUSE), a directory
// removed and made again with the same inode number is not told apart.
// On an overlay the root is copied up before it is recorded (settle),
// so its creation time is the top layer's, which it keeps.
type DirID struct {
	Real string `json:"real"`
	Dev  uint64 `json:"dev"`
	Ino  uint64 `json:"ino"`
	Born int64  `json:"born,omitempty"`
	Gen  uint64 `json:"gen,omitempty"`
	FS   uint64 `json:"fs,omitempty"`
}

// RecordDirID is DirIDOf for a root a session begins with: a directory
// on an overlay is copied up first (settle). A root that cannot be (a
// read-only overlay, or one the user may not write), or that settle
// cannot tell is on an overlay or not, is refused: the first write below would
// change its creation time, an overlay records no generation, and
// without either a directory made again in its place, with the same
// inode number, would pass for it.
func RecordDirID(p string) (DirID, error) {
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return DirID{}, err
	}
	if err := settle(real); err != nil {
		return DirID{}, fmt.Errorf("%s: %w", p, err)
	}
	return DirIDOf(p)
}

// DirIDOf is the directory p names now.
func DirIDOf(p string) (DirID, error) {
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return DirID{}, err
	}
	fi, err := os.Stat(real)
	if err != nil {
		return DirID{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return DirID{}, fmt.Errorf("%s: no device and inode", p)
	}
	return DirID{Real: real, Dev: u64(st.Dev), Ino: u64(st.Ino), Born: born(real, st), Gen: gen(real), FS: fsID(real)}, nil
}

// Check refuses p when it is not the directory id was taken of: it
// leads elsewhere now, or another directory was made at its path.
func (id DirID) Check(p string) error {
	got, err := DirIDOf(p)
	switch {
	case err != nil:
		return fmt.Errorf("%s, a root of the session: %w", p, err)
	case got.Real != id.Real:
		return fmt.Errorf("%s leads to %s now, not to %s as when the session began", p, got.Real, id.Real)
	case got.Ino != id.Ino || id.Born != 0 && got.Born != id.Born || id.Gen != 0 && got.Gen != id.Gen:
		return fmt.Errorf("%s is another directory than when the session began: that one was moved or removed, or the filesystem gives new inode numbers on each mount (FAT, sshfs without use_ino)", p)
	case id.FS != 0 && got.FS != id.FS,
		got.Dev != id.Dev && (id.Born == 0 || id.FS == 0):
		return fmt.Errorf("%s is on another filesystem than when the session began: another one, or a snapshot of this one, is mounted there, "+
			"or this one was mounted again and records nothing that tells it is the same (macOS, NFS, FUSE; "+
			"xfs when its device is renumbered); "+
			"in that last case airbag cannot tell, so take what you need from airbag diff, then discard the session", p)
	}
	return nil
}

// CheckRoots checks the session's workspace and $HOME against what it
// recorded when it began; a session from before roots were recorded
// has none to check.
func (s *Session) CheckRoots() error {
	for _, r := range []struct {
		path string
		id   DirID
	}{{s.Workspace, s.WorkspaceID}, {s.Home, s.HomeID}} {
		if r.id.Real == "" {
			continue
		}
		if err := r.id.Check(r.path); err != nil {
			return err
		}
	}
	return nil
}

// HomeUnrecorded reports a $HOME the session records nothing for: one
// not branched, and not there (or not readable) when it began, or on
// Linux, where nothing writes in it. Nothing tells what is there now
// from what was, so run makes and opens nothing there. A session from
// before roots were recorded has no workspace recorded either, and
// keeps what it did then.
func (s *Session) HomeUnrecorded() bool {
	return s.Home != "" && s.HomeID.Real == "" && s.WorkspaceID.Real != ""
}

// u64 widens a stat field, whose type differs between Linux and macOS.
func u64[T int32 | uint32 | int64 | uint64](v T) uint64 { return uint64(v) }

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
	// Where the workspace and $HOME lead now; apply, run and resume
	// refuse them once they are other directories. The workspace, and a
	// $HOME that is branched, must be recorded, or the session is
	// refused. A $HOME that is not branched is written only on macOS
	// (Clone), for agent state: it is recorded where it can be, and one
	// that is not (not there, HOME=/nonexistent, say) gets nothing made or
	// written there (HomeUnrecorded). On Linux nothing writes in it, so
	// nothing is recorded or checked.
	for _, r := range []struct {
		path string
		id   *DirID
	}{{m.Workspace, &m.WorkspaceID}, {m.Home, &m.HomeID}} {
		if r.path == "" || r.id.Real != "" {
			continue
		}
		unbranched := r.id == &m.HomeID && !m.OverHome
		if unbranched && !m.Clone {
			continue
		}
		id, err := RecordDirID(r.path)
		if err != nil && unbranched {
			continue
		}
		if err != nil {
			return nil, err
		}
		*r.id = id
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
	for _, lock := range []string{s.lockPath(), s.AgentLockPath()} {
		if err := os.WriteFile(lock, nil, 0o600); err != nil {
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
func (s *Session) AgentStateDir() string       { return filepath.Join(s.Dir, "agent-state") }
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
	// Taken before the session says running and held while this process
	// runs it: a rollback cannot start in the time before the run's host
	// services answer, nor this run under a rollback. A resume refused
	// below lets it go.
	unlock, err := s.LockRun()
	switch {
	case errors.Is(err, ErrInUse):
		return nil, fmt.Errorf("session %s is in use by another airbag process (a rollback, say); resume it once that has ended", s.ID)
	case errors.Is(err, ErrAgentLives):
		return nil, fmt.Errorf("session %s: %w (on macOS one can outlive airbag; lsof %s finds it); resume once it has ended", s.ID, err, s.AgentLockPath())
	case err != nil:
		return nil, err
	}
	resumed := false
	defer func() {
		if !resumed {
			unlock()
		}
	}()
	// A run on a moved root would branch another tree, and its
	// passthrough paths would write where the root leads now.
	if err := s.CheckRoots(); err != nil {
		return nil, fmt.Errorf("%w; put the directory back to resume session %s", err, s.ID)
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
	resumed = true
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
