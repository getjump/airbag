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
	"unicode/utf8"

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

// maxEntries bounds one snapshot of a layer (a variable for the tests).
var maxEntries = 1 << 20

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
	// A clone holds the whole workspace, not only what changed: a file
	// gone from it is a deletion, as a whiteout is in an upper layer.
	layers := map[string]string{"ws": t.s.WSBranch()}
	if t.s.OverHome {
		layers["home"] = t.s.HomeUpper()
	}
	for name, root := range layers {
		r, err := os.OpenRoot(root)
		if err != nil {
			continue
		}
		walk(r, func(rel string, info fs.FileInfo) {
			if info.IsDir() {
				return
			}
			e := entry{mtime: info.ModTime().UnixNano(), size: info.Size()}
			if st, ok := info.Sys().(*syscall.Stat_t); ok && info.Mode()&fs.ModeCharDevice != 0 && st.Rdev == 0 {
				e.gone = true
			}
			out[name+":"+rel] = e
		})
		_ = r.Close()
	}
	return out
}

// walk visits the entries of the tree under r, directories included, up
// to maxEntries of them: a tree of millions of files or empty directories
// stops the count, not the agent's tool call, and the review still shows
// every change. The agent writes the tree while the walk runs. Each
// directory is opened through r, so one swapped for a link out of the
// tree is an error here, not a walk of the host. Names go to the OS as
// they are: fs.WalkDir leaves out a directory whose name is not UTF-8,
// and everything under it. Each entry's type comes from lstat, not from
// readdir, which gives none on some filesystems. What cannot be listed,
// or is gone by the time it is looked at, is left out, since steps only
// attribute changes.
func walk(r *os.Root, visit func(rel string, info fs.FileInfo)) {
	n := 0
	dirs := []string{"."}
	for len(dirs) > 0 {
		dir := dirs[len(dirs)-1]
		dirs = dirs[:len(dirs)-1]
		f, err := r.Open(dir)
		if err != nil {
			continue
		}
		for {
			ents, err := f.ReadDir(1024)
			for _, d := range ents {
				if n++; n > maxEntries {
					_ = f.Close()
					return
				}
				info, err := d.Info()
				if err != nil {
					continue
				}
				rel := filepath.Join(dir, d.Name())
				visit(rel, info)
				if info.IsDir() {
					dirs = append(dirs, rel)
				}
			}
			if err != nil {
				break
			}
		}
		_ = f.Close()
	}
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
	// The record is best effort, like the attribution it serves: a step
	// that is not written still shows its changes in the review.
	if b, err := json.Marshal(stored(st)); err == nil {
		if f, err := os.OpenFile(path(t.s), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			_, _ = f.Write(append(b, '\n'))
			_ = f.Close()
		}
	}
	return st
}

func path(s *session.Session) string { return filepath.Join(s.Dir, "steps.jsonl") }

// record is a step as steps.jsonl keeps it. JSON strings hold UTF-8 only:
// a name that is not would come back with U+FFFD for its bytes, and two
// names could read as one. Such a change keeps its bytes beside it as
// well, by its index in Changes.
type record struct {
	Step
	Raw map[int][]byte `json:"changes_raw,omitempty"`
}

func stored(st Step) record {
	r := record{Step: st}
	for i, c := range st.Changes {
		if !utf8.ValidString(c) {
			if r.Raw == nil {
				r.Raw = map[int][]byte{}
			}
			r.Raw[i] = []byte(c)
		}
	}
	return r
}

func Read(s *session.Session) ([]Step, error) {
	f, err := os.Open(path(s))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []Step
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		var r record
		if json.Unmarshal(sc.Bytes(), &r) != nil {
			continue
		}
		for i, c := range r.Raw {
			if i >= 0 && i < len(r.Changes) {
				r.Changes[i] = string(c)
			}
		}
		out = append(out, r.Step)
	}
	return out, sc.Err()
}
