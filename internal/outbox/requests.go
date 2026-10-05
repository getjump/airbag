package outbox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/getjump/airbag/internal/operation"
)

func decodeRequest(encoded, digest, kind string, request *operation.Request) error {
	d := json.NewDecoder(strings.NewReader(encoded))
	d.DisallowUnknownFields()
	if err := d.Decode(request); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("request contains trailing data")
	}
	got, err := request.Digest()
	if err != nil || got != digest || request.Kind != kind {
		return fmt.Errorf("invalid request or digest")
	}
	return nil
}

// TypedResult exposes execution evidence separately from the proposed request.
// An old/absent result is not invented into a success or a remote URL.
func (in Intent) TypedResult() *operation.Result {
	if in.Request == nil {
		return nil
	}
	r := operation.Result{Ticket: in.ID, RequestDigest: in.RequestDigest}
	switch in.Status {
	case Pending, string(operation.Approved):
		r.Outcome = operation.Queued
		return &r
	case Rejected:
		r.Outcome, r.Value = operation.Denied, in.Output
		return &r
	case Done, Unknown, Failed:
		if err := json.Unmarshal([]byte(in.Output), &r); err != nil {
			if in.Status == Unknown {
				return &operation.Result{Ticket: in.ID, RequestDigest: in.RequestDigest, Outcome: operation.Uncertain, Value: in.Output}
			}
			return nil
		}
		expected := map[string]operation.Outcome{Done: operation.Succeeded, Unknown: operation.Uncertain, Failed: operation.Failure}[in.Status]
		if r.Ticket != in.ID || r.RequestDigest != in.RequestDigest || r.Outcome != expected {
			return nil
		}
		return &r
	}
	return nil
}

// Approve binds a human decision to exactly the stored request. It cannot
// authorize different payload bytes, a different commit, or a terminal intent.
func (b *Box) Approve(id, digest string) error {
	return b.transition(id, digest, operation.Pending, operation.Approved, "")
}

// Claim durably consumes one approved request before the handler starts. The
// immediate transaction serializes competing processes sharing this database.
func (b *Box) Claim(id, digest string) error {
	return b.transition(id, digest, operation.Approved, operation.Running, "")
}

func (b *Box) transition(id, digest string, expected, next operation.State, output string) error {
	tx, err := b.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var encoded, storedDigest, kind, current string
	if err := tx.QueryRowContext(context.Background(), `SELECT r.request, r.digest, i.kind, s.status
		FROM intent_requests r JOIN intents i ON i.id = r.intent
		JOIN intent_status s ON s.seq = (SELECT max(seq) FROM intent_status WHERE intent = i.id)
		WHERE r.intent = ?`, id).Scan(&encoded, &storedDigest, &kind, &current); err != nil {
		return fmt.Errorf("load typed intent %s: %w", id, err)
	}
	var request operation.Request
	if err := decodeRequest(encoded, storedDigest, kind, &request); err != nil {
		return err
	}
	if digest != storedDigest {
		return fmt.Errorf("approval digest does not match intent %s", id)
	}
	if expected != "" && operation.State(current) != expected {
		return fmt.Errorf("intent %s is %s, expected %s", id, current, expected)
	}
	if _, err := operation.Reduce(operation.State(current), next); err != nil {
		return err
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO intent_status (intent, t, status, output) VALUES (?, ?, ?, ?)`,
		id, time.Now().UTC().Format(time.RFC3339Nano), string(next), output); err != nil {
		return err
	}
	return tx.Commit()
}

// Resolve records what the user found an intent whose outcome is unknown
// did, after checking the remote: done or failed. It runs nothing.
// Execution never resumes from unknown; this is the one way out of it,
// so that the intents queued after it can run.
func (b *Box) Resolve(id string, done bool) error {
	tx, err := b.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var current, digest string
	if err := tx.QueryRowContext(context.Background(), `SELECT s.status, coalesce(r.digest, '')
		FROM intents i
		JOIN intent_status s ON s.seq = (SELECT max(seq) FROM intent_status WHERE intent = i.id)
		LEFT JOIN intent_requests r ON r.intent = i.id
		WHERE i.id = ?`, id).Scan(&current, &digest); err != nil {
		return fmt.Errorf("intent %s: %w", id, err)
	}
	if current != Unknown {
		return fmt.Errorf("intent %s is %s; only an unknown outcome is recorded by hand", id, current)
	}
	status, outcome, output := Failed, operation.Failure, "recorded by the user: it did not take effect"
	if done {
		status, outcome, output = Done, operation.Succeeded, "recorded by the user: it took effect"
	}
	if digest != "" {
		r, err := json.Marshal(operation.Result{Outcome: outcome, Ticket: id, RequestDigest: digest, Value: output})
		if err != nil {
			return err
		}
		output = string(r)
	}
	if _, err := tx.ExecContext(context.Background(), `INSERT INTO intent_status (intent, t, status, output) VALUES (?, ?, ?, ?)`,
		id, time.Now().UTC().Format(time.RFC3339Nano), status, output); err != nil {
		return err
	}
	return tx.Commit()
}
