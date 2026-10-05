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
