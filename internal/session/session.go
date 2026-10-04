// Package session stores the state of one sandboxed agent run: the
// overlay layers, the effect log, the outbox and the metadata.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	ID        string    `json:"id"`
	Created   time.Time `json:"created"`
	Ended     time.Time `json:"ended,omitzero"`
	Workspace string    `json:"workspace"`
	Home      string    `json:"home"`
	OverHome  bool      `json:"over_home"`
	UID       int       `json:"uid"`
	GID       int       `json:"gid"`
	Argv      []string  `json:"argv"`
	Cwd       string    `json:"cwd"`
	Status    string    `json:"status"`
	ExitCode  int       `json:"exit_code"`
	Allow     []string  `json:"allow"`
	// Paths under $HOME that bypass the branch (agent state, logs).
	Passthrough []string `json:"passthrough"`
	// Paths under $HOME hidden from the agent (credentials).
	Hidden []string `json:"hidden"`
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
	s := &Session{Meta: m, Dir: filepath.Join(root, m.ID)}
	for _, d := range []string{
		s.WSUpper(), s.WSWork(), s.HomeUpper(), s.HomeWork(), s.EtcUpper(), s.EtcWork(),
		s.MountDir("ws"), s.MountDir("realhome"), s.RunDir(),
	} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	return s, s.Save()
}

func (s *Session) WSUpper() string             { return filepath.Join(s.Dir, "ws", "upper") }
func (s *Session) WSWork() string              { return filepath.Join(s.Dir, "ws", "work") }
func (s *Session) HomeUpper() string           { return filepath.Join(s.Dir, "home", "upper") }
func (s *Session) HomeWork() string            { return filepath.Join(s.Dir, "home", "work") }
func (s *Session) EtcUpper() string            { return filepath.Join(s.Dir, "etc", "upper") }
func (s *Session) EtcWork() string             { return filepath.Join(s.Dir, "etc", "work") }
func (s *Session) MountDir(name string) string { return filepath.Join(s.Dir, "mnt", name) }
func (s *Session) RunDir() string              { return filepath.Join(s.Dir, "run") }
func (s *Session) ProxySock() string           { return filepath.Join(s.RunDir(), "proxy.sock") }
func (s *Session) ControlSock() string         { return filepath.Join(s.RunDir(), "ctl.sock") }
func (s *Session) EffectsPath() string         { return filepath.Join(s.Dir, "effects.jsonl") }
func (s *Session) OutboxPath() string          { return filepath.Join(s.Dir, "outbox.json") }

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

// RemoveAll deletes a session. Overlay leaves a mode-000 work dir
// behind, so permissions are fixed up before removal.
func (s *Session) RemoveAll() error {
	_ = filepath.WalkDir(s.Dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(p, 0o700)
		}
		return nil
	})
	return os.RemoveAll(s.Dir)
}

func within(parent, p string) bool {
	rel, err := filepath.Rel(p, parent)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}
