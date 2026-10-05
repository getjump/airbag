// Package githubpr interprets a frozen pull-request operation. Credential and
// transport ownership stay with the trusted host embedding this handler.
package githubpr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"

	"github.com/getjump/airbag/operation"
)

// Call is a trusted GitHub API transport, bound to api.github.com. It must
// honor cancellation, bound responses and perform no implicit POST retries.
// Return an HTTPError only for an observed GitHub HTTP error response.
// Paths and payloads come from the validated operation, never captured argv.
type Call func(context.Context, string, string, []byte) ([]byte, error)

type Handler struct{ Call Call }

// Prepared holds a copy of the exact request and JSON payload. Preparation
// reads remote state; it does not publish, approve or consume an approval.
type Prepared struct {
	call    Call
	request operation.Request
	payload []byte
	digest  string
	once    sync.Once
	result  operation.Result
}

func (h Handler) Prepare(ctx context.Context, request operation.Request) (*Prepared, error) {
	if h.Call == nil {
		return nil, fmt.Errorf("GitHub API transport is required")
	}
	preview, err := request.Preview()
	if err != nil {
		return nil, err
	}
	request = preview.Request
	p := request.PullRequest
	data, err := h.Call(ctx, "GET", "repos/"+p.Repository+"/git/ref/heads/"+url.PathEscape(p.Head), nil)
	if err != nil {
		return nil, fmt.Errorf("cannot verify GitHub head: %w", err)
	}
	var ref struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := json.Unmarshal(data, &ref); err != nil || ref.Object.SHA != p.HeadCommit {
		return nil, fmt.Errorf("GitHub head does not match the approved commit; push that exact commit to %s first", p.Head)
	}
	payload, err := json.Marshal(struct {
		Title               string `json:"title"`
		Body                string `json:"body"`
		Head                string `json:"head"`
		Base                string `json:"base"`
		Draft               bool   `json:"draft"`
		MaintainerCanModify bool   `json:"maintainer_can_modify"`
	}{Title: p.Title, Body: p.Body, Head: p.Head, Base: p.Base, Draft: p.Draft})
	if err != nil {
		return nil, err
	}
	return &Prepared{call: h.Call, request: request, payload: payload, digest: preview.RequestDigest}, nil
}

// Publish must run only after a durable claim of Digest. One Prepared value
// invokes the POST at most once and returns the same result on repeated calls.
// Across processes/restarts the outbox remains the admission gate. An observed
// 4xx refusal fails; other errors/mismatching responses are unknown. Neither retries.
func (p *Prepared) Publish(ctx context.Context) operation.Result {
	if p == nil || p.call == nil {
		return operation.Result{Outcome: operation.Denied, Value: "request was not prepared"}
	}
	p.once.Do(func() {
		p.result = operation.Result{Outcome: operation.Uncertain, RequestDigest: p.digest}
		data, err := p.call(ctx, "POST", "repos/"+p.request.PullRequest.Repository+"/pulls", p.payload)
		var responseError *HTTPError
		if errors.As(err, &responseError) && responseError != nil && responseError.StatusCode >= 400 && responseError.StatusCode < 500 {
			p.result.Outcome, p.result.Value = operation.Failure, responseError.Error()
		} else if err != nil {
			p.result.Value = "publication may have reached GitHub; inspect the remote before making another request"
		} else if value, valid := MatchResponse(data, *p.request.PullRequest); valid {
			p.result.Outcome, p.result.Value = operation.Succeeded, value
		} else {
			p.result.Value = "GitHub response did not attest the exact request; reconcile the remote PR manually"
		}
	})
	return p.result
}

// Digest is the digest of the prepared request; "" when nothing was
// prepared, which no claim matches.
func (p *Prepared) Digest() string {
	if p == nil {
		return ""
	}
	return p.digest
}
