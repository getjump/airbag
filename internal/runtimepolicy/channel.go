// Package runtimepolicy carries observed attempts over a private inherited
// channel. The agent-facing control socket cannot submit runtime audit events.
package runtimepolicy

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/getjump/airbag/internal/diagnostic"
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
	Profile  *ProfileSnapshot `json:",omitempty"`
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
	return ServeWithOptions(c, gate, log, Options{})
}

// BatchSink acknowledges accepted events. It may buffer them; a sink providing
// Flush() error is flushed before the separate durable secret-read barrier.
type BatchSink interface{ AddBatchChecked([]effects.Effect) error }

type Options struct {
	Audit   BatchSink
	Profile *Profile
}

// ServeWithOptions keeps policy checks synchronous in every audit mode. Secret
// notifications always flush preceding buffered events, commit to the original
// FULL-WAL log before acknowledging the caller. Taint applies immediately so
// later checks in the same group and concurrent proxy requests see the label.
func ServeWithOptions(c net.Conn, gate *policy.Gate, log *effects.Log, options Options) error {
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
			if f.ID == 0 || len(f.Requests) > maxChecks || (len(f.Requests) == 0 && f.Profile == nil) || (f.Profile != nil && (options.Profile == nil || len(f.Requests) != 0)) {
				readErr <- fmt.Errorf("invalid runtime frame")
				return
			}
			if f.Profile != nil {
				if err := f.Profile.validate(); err != nil {
					readErr <- err
					return
				}
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
	var auditErr error
	diagnostics := diagnostic.Config()
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
		var secrets []string
		for _, f := range group {
			reply := response{ID: f.ID, Allow: true}
			if f.Profile != nil {
				options.Profile.mergeChild(*f.Profile)
				replies = append(replies, reply)
				continue
			}
			options.Profile.Record("runtime.frames", 0, uint64(len(f.Requests)))
			for _, r := range f.Requests {
				if (r.Source != "fuse" && r.Source != "seccomp") || r.Kind == "" {
					return fmt.Errorf("invalid runtime event")
				}
				var gateStart time.Time
				if options.Profile != nil {
					gateStart = time.Now()
				}
				d := policy.Decision{Verdict: policy.Allow}
				if r.Secret {
					if r.Source != "fuse" || r.Kind != "secret.read" {
						return fmt.Errorf("invalid taint event")
					}
					secrets = append(secrets, r.Target)
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
				if options.Profile != nil {
					options.Profile.Record("runtime.gate."+r.Source+"."+r.Kind, time.Since(gateStart), 1)
					name := "runtime.decision." + r.Kind
					if len(r.Detail) <= 32 && validMetricName(r.Detail) {
						name += "." + r.Detail
					}
					options.Profile.Record(name+"."+d.Verdict, 0, 1)
				}
				events = append(events, effects.Effect{Kind: r.Kind, Target: r.Target, Detail: r.Detail, Source: r.Source, PID: r.PID, Argv: r.Argv, Verdict: d.Verdict, Reason: d.Message})
				if d.Verdict != policy.Allow && !r.Secret {
					reply.Allow = false
					break
				}
			}
			replies = append(replies, reply)
		}
		options.Profile.Record("runtime.groups", 0, uint64(len(group)))
		var auditStart time.Time
		if options.Profile != nil {
			auditStart = time.Now()
		}
		durable := len(secrets) > 0 || options.Audit == nil
		if auditErr == nil && len(events) > 0 {
			if len(secrets) > 0 {
				if buffered, ok := options.Audit.(interface{ Flush() error }); ok {
					auditErr = buffered.Flush()
				}
			}
			if auditErr == nil && (!diagnostics.SkipRuntimeAudit || len(secrets) > 0) {
				if durable {
					var commitStart time.Time
					if options.Profile != nil {
						commitStart = time.Now()
					}
					auditErr = log.AddBatchChecked(events)
					if options.Profile != nil {
						name := "runtime.audit.durable"
						if auditErr != nil {
							name += ".error"
						}
						options.Profile.Record(name, time.Since(commitStart), uint64(len(events)))
					}
				} else {
					auditErr = options.Audit.AddBatchChecked(events)
				}
			}
		}
		if options.Profile != nil {
			options.Profile.Record("runtime.audit.ack", time.Since(auditStart), uint64(len(events)))
		}
		if auditErr != nil {
			for i := range replies {
				if group[i].Profile != nil {
					continue
				}
				replies[i].Allow = false
				replies[i].Message = "airbag: runtime audit commit failed: " + auditErr.Error()
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
	return errors.Join(<-readErr, auditErr)
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
	profile *Profile
}

func NewClient(conn net.Conn) *Client {
	return NewClientWithProfile(conn, nil)
}

// NewClientWithProfile records end-to-end request wall time, including slot
// waits, serialization, policy, audit, and reply transport. It overlaps host
// metrics and callback duration; these totals are not additive.
func NewClientWithProfile(conn net.Conn, profile *Profile) *Client {
	c := &Client{conn: conn, enc: json.NewEncoder(conn), pending: make(map[uint64]chan response), slots: make(chan struct{}, maxPending), done: make(chan struct{}), profile: profile}
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
	return c.exchange(frame{Requests: requests})
}

// ReportProfile uses the same private supervisor channel and is accepted only
// by an explicitly profiled host. It cannot contain decisions or taint events.
func (c *Client) ReportProfile(snapshot ProfileSnapshot) error {
	if err := snapshot.validate(); err != nil {
		return err
	}
	return c.exchange(frame{Profile: &snapshot})
}

func (c *Client) exchange(f frame) (result error) {
	if c.profile != nil && f.Profile == nil {
		start := time.Now()
		defer func() {
			c.profile.Record("rpc.roundtrip", time.Since(start), uint64(len(f.Requests)))
			if result != nil {
				c.profile.Record("rpc.error", 0, uint64(len(f.Requests)))
			}
		}()
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
		f.ID = id
		err = c.enc.Encode(f)
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
