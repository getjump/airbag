package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/getjump/airbag/internal/operation"
	"github.com/getjump/airbag/internal/outbox"
	"github.com/getjump/airbag/internal/session"
	"github.com/getjump/airbag/internal/term"
)

type outboxPreview struct {
	ID      string             `json:"id"`
	Status  string             `json:"status"`
	Preview *operation.Preview `json:"preview,omitempty"`
	Result  *operation.Result  `json:"result,omitempty"`
	Argv    []string           `json:"argv,omitempty"` // legacy commands have no typed preview
}

func cmdOutbox(args []string) error {
	if len(args) > 0 && args[0] == "resolve" {
		return cmdOutboxResolve(args[1:])
	}
	fs := flag.NewFlagSet("outbox", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print frozen requests as JSON, without executing them")
	if err := fs.Parse(reorder(args)); err != nil {
		return err
	}
	return withSession(fs.Args(), func(s *session.Session) error {
		box, err := outbox.Open(s.EffectsPath())
		if err != nil {
			return err
		}
		defer func() { _ = box.Close() }()
		intents, err := box.List()
		if err != nil {
			return err
		}
		rows, err := previewOutbox(intents)
		if err != nil {
			return err
		}
		if *asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(rows)
		}
		safe := term.Safe(os.Stdout)
		defer safe.Flush()
		for _, row := range rows {
			if row.Preview != nil {
				outbox.WritePreview(safe, row.ID, row.Status, *row.Preview)
				if row.Result != nil {
					fmt.Fprintf(safe, "  outcome: %s %s\n", row.Result.Outcome, row.Result.Value)
				}
			} else {
				fmt.Fprintf(safe, "%s [%s] %s (legacy command; no typed preview)\n", row.ID, row.Status, outbox.Line(row.Argv))
			}
		}
		return nil
	})
}

func previewOutbox(intents []outbox.Intent) ([]outboxPreview, error) {
	rows := make([]outboxPreview, 0, len(intents))
	for _, it := range intents {
		row := outboxPreview{ID: it.ID, Status: it.Status, Result: it.TypedResult()}
		if it.Request != nil {
			p, err := it.Request.Preview()
			if err != nil {
				return nil, err
			}
			row.Preview = &p
		} else {
			row.Argv = it.Argv
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// cmdOutboxResolve records, once the user has checked, what an intent
// whose outcome is unknown did: outbox resolve INTENT done|failed [ID].
func cmdOutboxResolve(args []string) error {
	if len(args) < 2 || args[1] != "done" && args[1] != "failed" {
		return fmt.Errorf("usage: airbag outbox resolve INTENT done|failed [ID]")
	}
	return withSession(args[2:], func(s *session.Session) error {
		box, err := outbox.Open(s.EffectsPath())
		if err != nil {
			return err
		}
		defer func() { _ = box.Close() }()
		lock, err := box.LockExecution() // not while an apply is running it
		if err != nil {
			return err
		}
		defer func() { _ = lock.Close() }()
		if err := box.Resolve(args[0], args[1] == "done"); err != nil {
			return err
		}
		fmt.Printf("intent %s recorded as %s; nothing was run. `airbag apply %s` runs the intents after it\n", args[0], args[1], s.ID)
		return nil
	})
}
