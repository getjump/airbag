// Package operation describes supported external actions as data. A Request is
// a proposal, not evidence that an action happened. Handlers decide when and
// how it executes; arbitrary subprocesses still need the sandbox's boundaries.
package operation

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

const Schema = "airbag.operation/v1"
const CreatePullRequest = "github.pull_request.create"
const MaxBody = 256 << 10

// Request is a closed, versioned sum of supported operations. Unknown variants
// are rejected. New variants need validation and an explicit trusted handler.
type Request struct {
	Schema      string       `json:"schema"`
	Kind        string       `json:"kind"`
	PullRequest *PullRequest `json:"pull_request,omitempty"`
}

type PullRequest struct {
	Repository string `json:"repository"`
	Base       string `json:"base"`
	Head       string `json:"head"`
	HeadCommit string `json:"head_commit"`
	Title      string `json:"title"`
	Body       string `json:"body"`
	Draft      bool   `json:"draft"`
}

// Authority describes the permission the handler uses, not a credential value
// or a claim that the user's token has no additional permissions.
type Authority struct {
	Service    string `json:"service"`
	Permission string `json:"permission"`
	Resource   string `json:"resource"`
}

func (r Request) Authority() Authority {
	if r.Kind == CreatePullRequest && r.PullRequest != nil {
		return Authority{Service: "github.com", Permission: "pull_requests:write", Resource: r.PullRequest.Repository}
	}
	return Authority{}
}

var repository = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$`)
var commit = regexp.MustCompile(`^[0-9a-f]{40}$`)

func (r Request) Validate() error {
	if r.Schema != Schema || r.Kind != CreatePullRequest || r.PullRequest == nil {
		return fmt.Errorf("unsupported operation schema or kind")
	}
	p := r.PullRequest
	if !repository.MatchString(p.Repository) || strings.HasSuffix(p.Repository, "/.") || strings.HasSuffix(p.Repository, "/..") {
		return fmt.Errorf("repository must be a GitHub owner/name")
	}
	if !ValidBranch(p.Base) || !ValidBranch(p.Head) || p.Base == p.Head {
		return fmt.Errorf("base and head must be distinct branch names (fork heads are not supported)")
	}
	if !commit.MatchString(p.HeadCommit) {
		return fmt.Errorf("head_commit must be a full lowercase SHA-1 object name")
	}
	if strings.TrimSpace(p.Title) == "" || len(p.Title) > 1024 || !utf8.ValidString(p.Title) || strings.ContainsAny(p.Title, "\x00\r\n") {
		return fmt.Errorf("title must be nonempty UTF-8, at most 1024 bytes, without line breaks")
	}
	if len(p.Body) > MaxBody || !utf8.ValidString(p.Body) || strings.ContainsRune(p.Body, '\x00') {
		return fmt.Errorf("body must be UTF-8, at most %d bytes, without NUL", MaxBody)
	}
	return nil
}

// ValidBranch validates a literal ref suffix. It is never interpreted as a
// revision expression, option, URL, or owner:branch shorthand.
func ValidBranch(s string) bool {
	if s == "" || len(s) > 240 || !utf8.ValidString(s) || strings.HasPrefix(s, "-") || strings.HasSuffix(s, ".") || strings.Contains(s, "..") || strings.Contains(s, "@{") || s == "@" {
		return false
	}
	for _, c := range s {
		if c <= ' ' || c == 0x7f || strings.ContainsRune("~^:?*[\\", c) {
			return false
		}
	}
	for _, part := range strings.Split(s, "/") {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
}

// Digest binds the complete validated request, including destination, commit
// and body bytes. Struct serialization gives a stable field order; version
// changes must use a new schema. This hash is not a signature or an access grant.
func (r Request) Digest() (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("encode operation: %w", err)
	}
	return Hash(b), nil
}

func Hash(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}
