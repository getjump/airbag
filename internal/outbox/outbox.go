// Package outbox holds irreversible actions the agent asked for. They
// run on the host after the human approves them in review.
package outbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

const (
	Pending  = "pending"
	Done     = "done"
	Failed   = "failed"
	Rejected = "rejected"
)

type Intent struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"` // git.push
	Argv    []string  `json:"argv"`
	Cwd     string    `json:"cwd"`
	Created time.Time `json:"created"`
	Status  string    `json:"status"`
	Output  string    `json:"output,omitempty"`
}

type Box struct {
	mu   sync.Mutex
	path string
}

func Open(path string) *Box { return &Box{path: path} }

func (b *Box) List() ([]Intent, error) {
	data, err := os.ReadFile(b.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var out []Intent
	return out, json.Unmarshal(data, &out)
}

func (b *Box) Push(in Intent) (Intent, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	all, err := b.List()
	if err != nil {
		return in, err
	}
	in.ID = fmt.Sprintf("i-%d", len(all)+1)
	in.Created = time.Now()
	in.Status = Pending
	return in, b.write(append(all, in))
}

func (b *Box) Update(in Intent) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	all, err := b.List()
	if err != nil {
		return err
	}
	for i := range all {
		if all[i].ID == in.ID {
			all[i] = in
		}
	}
	return b.write(all)
}

func (b *Box) write(all []Intent) error {
	data, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return err
	}
	tmp := b.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, b.path)
}
