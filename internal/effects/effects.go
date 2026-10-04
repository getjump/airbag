// Package effects is the append-only effect log of a session.
package effects

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"
)

// Effect is a fact: something changed or something left the machine.
type Effect struct {
	Time    time.Time `json:"t"`
	Kind    string    `json:"kind"`              // net.egress, intent.git_push, ...
	Target  string    `json:"target"`            // host:port, argv, path
	Verdict string    `json:"verdict,omitempty"` // allow, deny, defer
	Reason  string    `json:"reason,omitempty"`
	// Predict: what a command model expects this command to do.
	Predict []string `json:"predict,omitempty"`
}

type Log struct {
	mu sync.Mutex
	f  *os.File
}

func Open(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Log{f: f}, nil
}

func (l *Log) Add(e Effect) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	b, _ := json.Marshal(e)
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.f.Write(append(b, '\n'))
}

func (l *Log) Close() error { return l.f.Close() }

func Read(path string) ([]Effect, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Effect
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var e Effect
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			out = append(out, e)
		}
	}
	return out, sc.Err()
}
