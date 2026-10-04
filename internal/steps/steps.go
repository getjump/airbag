// Package steps attributes branch changes to the agent's tool calls.
// After each tool call the upper layers are compared with the previous
// snapshot; what changed in between belongs to that call.
package steps

import (
	"bufio"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/getjump/airbag/internal/session"
)

type Step struct {
	N       int       `json:"n"`
	Time    time.Time `json:"t"`
	Tool    string    `json:"tool"`
	Summary string    `json:"summary"`
	ID      string    `json:"id,omitempty"`
	Changes []string  `json:"changes,omitempty"` // "+ws:path", "~home:.bashrc", "-ws:old"
}

type entry struct {
	mtime, size int64
	gone        bool // whiteout
}

type Tracker struct {
	mu   sync.Mutex
	s    *session.Session
	last map[string]entry
	n    int
	seen map[string]bool // tool_use_ids already recorded
}

func NewTracker(s *session.Session) *Tracker {
	t := &Tracker{s: s}
	// A resumed session numbers on from its last step.
	if prev, _ := Read(s); len(prev) > 0 {
		t.n = prev[len(prev)-1].N
	}
	t.last = t.snapshot()
	return t
}

func (t *Tracker) snapshot() map[string]entry {
	out := map[string]entry{}
	layers := map[string]string{"ws": t.s.WSUpper()}
	if t.s.OverHome {
		layers["home"] = t.s.HomeUpper()
	}
	for name, root := range layers {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil //nolint:nilerr // steps only attribute changes; the review still shows an entry left out here
			}
			info, err := d.Info()
			if err != nil {
				return nil //nolint:nilerr // gone since the walk listed it: nothing to attribute
			}
			rel, _ := filepath.Rel(root, p)
			e := entry{mtime: info.ModTime().UnixNano(), size: info.Size()}
			if st, ok := info.Sys().(*syscall.Stat_t); ok && info.Mode()&fs.ModeCharDevice != 0 && st.Rdev == 0 {
				e.gone = true
			}
			out[name+":"+rel] = e
			return nil
		})
	}
	return out
}

// Record closes a step: everything that changed since the last one.
func (t *Tracker) Record(tool, summary, id string) Step {
	t.mu.Lock()
	defer t.mu.Unlock()
	if id != "" && t.seen[id] {
		// The same call reported again (failure, then result).
		return t.record(tool, summary, id, true)
	}
	if t.seen == nil {
		t.seen = map[string]bool{}
	}
	t.seen[id] = true
	return t.record(tool, summary, id, false)
}

// Between records changes made outside tool calls (the agent's own
// config, background processes), if there are any.
func (t *Tracker) Between() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.record("-", "between tool calls", "", true)
}

func (t *Tracker) record(tool, summary, id string, onlyIfChanged bool) Step {
	now := t.snapshot()
	var ch []string
	for k, e := range now {
		old, had := t.last[k]
		switch {
		case !had && e.gone, had && !old.gone && e.gone:
			ch = append(ch, "-"+k)
		case !had:
			ch = append(ch, "+"+k)
		case old != e:
			ch = append(ch, "~"+k)
		}
	}
	for k, old := range t.last {
		if _, ok := now[k]; !ok && !old.gone {
			ch = append(ch, "-"+k) // created earlier in the session, removed now
		}
	}
	sort.Strings(ch)
	if onlyIfChanged && len(ch) == 0 {
		return Step{}
	}
	t.last = now
	t.n++
	st := Step{N: t.n, Time: time.Now(), Tool: tool, Summary: summary, ID: id, Changes: ch}
	if f, err := os.OpenFile(path(t.s), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		b, _ := json.Marshal(st)
		_, _ = f.Write(append(b, '\n'))
		f.Close()
	}
	return st
}

func path(s *session.Session) string { return filepath.Join(s.Dir, "steps.jsonl") }

func Read(s *session.Session) ([]Step, error) {
	f, err := os.Open(path(s))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Step
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		var st Step
		if json.Unmarshal(sc.Bytes(), &st) == nil {
			out = append(out, st)
		}
	}
	return out, sc.Err()
}
