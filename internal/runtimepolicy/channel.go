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

type response struct {
	Allow   bool
	Message string
}

const timeout = 30 * time.Second
const maxFrame = 128 * 1024

// Serve is used only by the host supervisor on its socketpair endpoint.
func Serve(c net.Conn, gate *policy.Gate, log *effects.Log) error {
	defer c.Close()
	scan := bufio.NewScanner(c)
	scan.Buffer(make([]byte, 4096), maxFrame)
	enc := json.NewEncoder(c)
	for scan.Scan() {
		var r Request
		if err := json.Unmarshal(scan.Bytes(), &r); err != nil {
			return err
		}
		var reply response
		if (r.Source != "fuse" && r.Source != "seccomp") || r.Kind == "" {
			return fmt.Errorf("invalid runtime event")
		}
		d := policy.Decision{Verdict: policy.Allow}
		if r.Secret {
			if r.Source != "fuse" || r.Kind != "secret.read" {
				return fmt.Errorf("invalid taint event")
			}
			gate.Taint(r.Target) // closes existing tunnels synchronously
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
		err := log.AddChecked(effects.Effect{Kind: r.Kind, Target: r.Target, Detail: r.Detail, Source: r.Source, PID: r.PID, Argv: r.Argv, Verdict: d.Verdict, Reason: d.Message})
		reply.Allow = err == nil && (d.Verdict == policy.Allow || r.Secret)
		if err != nil {
			reply.Message = "airbag: runtime audit commit failed: " + err.Error()
		}
		if err := c.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		if err := enc.Encode(reply); err != nil {
			return err
		}
	}
	return scan.Err()
}

type Client struct {
	mu   sync.Mutex
	conn net.Conn
	scan *bufio.Scanner
	enc  *json.Encoder
}

func NewClient(c net.Conn) *Client {
	scan := bufio.NewScanner(c)
	scan.Buffer(make([]byte, 4096), maxFrame)
	return &Client{conn: c, scan: scan, enc: json.NewEncoder(c)}
}

// Check fails closed on transport loss, a malformed reply, or an audit error.
func (c *Client) Check(r Request) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if err := c.enc.Encode(r); err != nil {
		c.conn.Close()
		return err
	}
	if !c.scan.Scan() {
		c.conn.Close()
		if err := c.scan.Err(); err != nil {
			return err
		}
		return fmt.Errorf("runtime supervisor disconnected")
	}
	var reply response
	if err := json.Unmarshal(c.scan.Bytes(), &reply); err != nil {
		c.conn.Close()
		return err
	}
	if !reply.Allow {
		fmt.Fprintln(os.Stderr, reply.Message)
		return fmt.Errorf("%s", reply.Message)
	}
	return nil
}
