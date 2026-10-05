package operation

import "fmt"

type State string

const (
	Pending   State = "pending"
	Approved  State = "approved"
	Running   State = "running"
	Completed State = "done" // retain the existing outbox wire spelling
	Failed    State = "failed"
	Rejected  State = "rejected"
	Unknown   State = "unknown"
)

// Reduce is pure. Terminal states cannot resume, and a running action can
// become unknown but never pending: an uncertain external effect is not retried.
func Reduce(current, next State) (State, error) {
	valid := current == Pending && (next == Approved || next == Rejected) ||
		current == Approved && (next == Running || next == Rejected) ||
		current == Running && (next == Completed || next == Failed || next == Unknown)
	if !valid {
		return current, fmt.Errorf("invalid operation transition %s -> %s", current, next)
	}
	return next, nil
}

// Outcome distinguishes queuing from execution. A ticket is not a remote PR.
type Outcome string

const (
	Queued    Outcome = "queued"
	Denied    Outcome = "denied"
	Succeeded Outcome = "completed"
	Failure   Outcome = "failed"
	Uncertain Outcome = "unknown"
)

type Result struct {
	Outcome       Outcome `json:"outcome"`
	RequestDigest string  `json:"request_digest"`
	Ticket        string  `json:"ticket,omitempty"`
	Value         string  `json:"value,omitempty"`
	// RecordedBy "user": the user recorded the outcome of an unknown
	// request (airbag outbox resolve); no answer from the service attests
	// it, and Value is their note, not a URL.
	RecordedBy string `json:"recorded_by,omitempty"`
}
