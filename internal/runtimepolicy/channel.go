// Package runtimepolicy carries observed attempts over a private inherited
// channel. The agent-facing control socket cannot submit runtime audit events.
package runtimepolicy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/getjump/airbag/internal/effects"
	"github.com/getjump/airbag/internal/models"
	"github.com/getjump/airbag/internal/policy"
)

type Request struct {
	Source string   `json:"source"`
	Kind   string   `json:"kind"`
	Target string   `json:"target"`
	Detail string   `json:"detail,omitempty"`
	PID    uint32   `json:"pid"`
	Argv   []string `json:"argv,omitempty"`
	// Secret is a taint notification made before an actual caller can read bytes.
	Secret bool `json:"secret,omitempty"`
}

type frame struct {
	ID       uint64
	Requests []Request
}
type response struct {
	ID      uint64
	Allow   bool
	Message string
}

const timeout = 30 * time.Second
const maxFrame = 128 * 1024
const maxChecks = 8
const maxPending = 64

// Serve evaluates frames in wire order, grouping already queued requests into a
// durable commit. There is no batching delay on the sequential path. All allows
// wait for the FULL WAL commit; audit failure denies the entire commit group.
func Serve(c net.Conn, gate *policy.Gate, log *effects.Log) error {
	defer c.Close()
	stop := make(chan struct{})
	defer close(stop)
	queue := make(chan frame, maxPending)
	readErr := make(chan error, 1)
	go func() {
		defer close(queue)
		scan := bufio.NewScanner(c)
		scan.Buffer(make([]byte, 4096), maxFrame)
		for scan.Scan() {
			var f frame
			if err := json.Unmarshal(scan.Bytes(), &f); err != nil {
				readErr <- err
				return
			}
			if f.ID == 0 || len(f.Requests) == 0 || len(f.Requests) > maxChecks {
				readErr <- fmt.Errorf("invalid runtime frame")
				return
			}
			select {
			case queue <- f:
			case <-stop:
				return
			}
		}
		readErr <- scan.Err()
	}()
	enc := json.NewEncoder(c)
	for first := range queue {
		group := []frame{first}
	drain:
		for len(group) < maxPending {
			select {
			case next, ok := <-queue:
				if !ok {
					break drain
				}
				group = append(group, next)
			default:
				break drain
			}
		}
		replies := make([]response, 0, len(group))
		var events []effects.Effect
		for _, f := range group {
			reply := response{ID: f.ID, Allow: true}
			for _, r := range f.Requests {
				if (r.Source != "fuse" && r.Source != "seccomp") || r.Kind == "" {
					return fmt.Errorf("invalid runtime event")
				}
				d := policy.Decision{Verdict: policy.Allow}
				if r.Secret {
					if r.Source != "fuse" || r.Kind != "secret.read" {
						return fmt.Errorf("invalid taint event")
					}
					gate.Taint(r.Target)
					d.Verdict = "taint"
					d.Message = r.Detail
				} else if r.Kind == "proc.exec.invalid" {
					d = policy.Decision{Verdict: policy.Deny, Message: r.Detail}
					reply.Message = "airbag: unreadable exec attempt: " + r.Detail
				} else {
					var id string
					d, id = gate.Check(policy.Input{Source: r.Source, Effect: models.Effect{Kind: r.Kind, Target: r.Target, Detail: r.Detail}, Argv: r.Argv})
					if d.Verdict != policy.Allow {
						reply.Message = policy.Explain(d, id)
					}
				}
				events = append(events, effects.Effect{Kind: r.Kind, Target: r.Target, Detail: r.Detail, Source: r.Source, PID: r.PID, Argv: r.Argv, Verdict: d.Verdict, Reason: d.Message})
				if d.Verdict != policy.Allow && !r.Secret {
					reply.Allow = false
					break
				}
			}
			replies = append(replies, reply)
		}
		if err := log.AddBatchChecked(events); err != nil {
			for i := range replies {
				replies[i].Allow = false
				replies[i].Message = "airbag: runtime audit commit failed: " + err.Error()
			}
		}
		if err := c.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		for _, reply := range replies {
			if err := enc.Encode(reply); err != nil {
				return err
			}
		}
	}
	return <-readErr
}

type Client struct {
	mu      sync.Mutex
	writeMu sync.Mutex
	conn    net.Conn
	enc     *json.Encoder
	pending map[uint64]chan response
	next    uint64
	err     error
	slots   chan struct{}
	done    chan struct{}
}

func NewClient(conn net.Conn) *Client {
	c := &Client{conn: conn, enc: json.NewEncoder(conn), pending: make(map[uint64]chan response), slots: make(chan struct{}, maxPending), done: make(chan struct{})}
	go c.read()
	return c
}

func (c *Client) fail(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err == nil {
		c.err = err
		close(c.done)
		c.conn.Close()
	}
}
func (c *Client) read() {
	scan := bufio.NewScanner(c.conn)
	scan.Buffer(make([]byte, 4096), maxFrame)
	for scan.Scan() {
		var reply response
		if err := json.Unmarshal(scan.Bytes(), &reply); err != nil {
			c.fail(err)
			return
		}
		c.mu.Lock()
		ch := c.pending[reply.ID]
		delete(c.pending, reply.ID)
		c.mu.Unlock()
		if ch == nil {
			c.fail(fmt.Errorf("invalid runtime reply id"))
			return
		}
		ch <- reply
	}
	err := scan.Err()
	if err == nil {
		err = fmt.Errorf("runtime supervisor disconnected")
	}
	c.fail(err)
}

// Check fails closed on transport loss, a malformed reply, or an audit error.
func (c *Client) Check(r Request) error { return c.CheckBatch([]Request{r}) }

// CheckBatch evaluates one operation's checks in order, stopping at the first
// denial. Distinct operations may be in flight together, each with its own ID.
func (c *Client) CheckBatch(requests []Request) error {
	if len(requests) == 0 || len(requests) > maxChecks {
		return fmt.Errorf("invalid runtime check count")
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case c.slots <- struct{}{}:
	case <-c.done:
		return c.failure()
	case <-timer.C:
		return fmt.Errorf("runtime queue timeout")
	}
	defer func() { <-c.slots }()
	c.mu.Lock()
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		return err
	}
	c.next++
	id := c.next
	ch := make(chan response, 1)
	c.pending[id] = ch
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pending, id); c.mu.Unlock() }()
	c.writeMu.Lock()
	err := c.conn.SetWriteDeadline(time.Now().Add(timeout))
	if err == nil {
		err = c.enc.Encode(frame{ID: id, Requests: requests})
	}
	c.writeMu.Unlock()
	if err != nil {
		c.fail(err)
		return err
	}
	select {
	case reply := <-ch:
		if !reply.Allow {
			if reply.Message == "" {
				reply.Message = "airbag: runtime operation denied"
			}
			fmt.Fprintln(os.Stderr, reply.Message)
			return fmt.Errorf("%s", reply.Message)
		}
		return nil
	case <-c.done:
		return c.failure()
	case <-timer.C:
		err := fmt.Errorf("runtime supervisor timeout")
		c.fail(err)
		return err
	}
}
func (c *Client) failure() error { c.mu.Lock(); defer c.mu.Unlock(); return c.err }
