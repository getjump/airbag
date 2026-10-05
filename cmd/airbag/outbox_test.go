package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/getjump/airbag/operation"
	"github.com/getjump/airbag/outbox"
)

func TestOutboxPreviewIsMachineReadableWithoutCLIExecution(t *testing.T) {
	// No host programs are available. The interpreter needs only the request.
	t.Setenv("PATH", t.TempDir())
	r := &operation.Request{Schema: operation.Schema, Kind: operation.CreatePullRequest, PullRequest: &operation.PullRequest{Repository: "getjump/airbag", Base: "main", Head: "work", HeadCommit: strings.Repeat("a", 40), Title: "Fix", Body: "exact body\n"}}
	rows, err := previewOutbox([]outbox.Intent{{ID: "i-1", Status: outbox.Pending, Request: r}, {ID: "i-2", Status: outbox.Pending, Argv: []string{"pubtool", "release"}}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"body":"exact body\n"`) || rows[0].Preview.RequestDigest == "" || rows[1].Preview != nil {
		t.Fatalf("bad preview: %s", data)
	}
}
