// Package audit defines records shared by collectors and audit storage.
// A record alone does not prove an operation completed or was durably saved.
package audit

import "time"

// Event records an observation or a decision: something changed or something left the machine,
// an observed attempt, or a command prediction.
type Event struct {
	Time    time.Time `json:"t"`
	Kind    string    `json:"kind"`              // net.egress, intent.git_push, ...
	Target  string    `json:"target"`            // host:port, argv, path
	Verdict string    `json:"verdict,omitempty"` // allow, deny, defer
	Reason  string    `json:"reason,omitempty"`
	// Predict: what a command model expects this command to do.
	Predict []string `json:"predict,omitempty"`
	// Runtime context of an observed attempt: the collector (fuse or
	// seccomp), the caller's PID, the operation, and an exec's argv.
	// Empty for predictions and other records.
	Source string   `json:"source,omitempty"`
	PID    uint32   `json:"pid,omitempty"`
	Detail string   `json:"detail,omitempty"`
	Argv   []string `json:"argv,omitempty"`
}

// Recorder receives records. Add has no durability acknowledgement; runtime
// admission barriers must use their dedicated synchronous protocol.
type Recorder interface{ Add(Event) }
