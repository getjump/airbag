package agents

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

// HostLogin is an agent login that the host keeps where the sandbox hides
// it, such as the macOS Keychain, and that airbag can hand to the agent
// as a short-lived access token in an environment variable.
type HostLogin struct {
	// Agent is the base name of the command that starts the agent.
	Agent string
	// Service names the Keychain generic password that holds the login.
	Service string
	// Token and Expiry are JSON paths inside the stored login to the
	// access token and its expiry in milliseconds since the epoch.
	Token, Expiry []string
	// Env is the variable the agent reads an access token from.
	Env string
	// Override are variables that already log the agent in; when one is
	// set, airbag leaves the login to the user.
	Override []string
}

// HostLogins lists the logins airbag knows how to hand over. Only the
// access token is handed over: the refresh token stays on the host, so the
// agent cannot extend its own access, and a refresh inside the sandbox
// cannot rotate the host's login out from under it.
var HostLogins = []HostLogin{{
	Agent:    "claude",
	Service:  "Claude Code-credentials",
	Token:    []string{"claudeAiOauth", "accessToken"},
	Expiry:   []string{"claudeAiOauth", "expiresAt"},
	Env:      "CLAUDE_CODE_OAUTH_TOKEN",
	Override: []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"},
}}

// LoginFor returns the host login of the agent that argv starts.
func LoginFor(argv []string) (HostLogin, bool) {
	if len(argv) == 0 {
		return HostLogin{}, false
	}
	name := filepath.Base(argv[0])
	for _, l := range HostLogins {
		if l.Agent == name {
			return l, true
		}
	}
	return HostLogin{}, false
}

// ErrNoToken means the stored login has no access token at the expected path.
var ErrNoToken = errors.New("no access token in the stored login")

// AccessToken reads the access token and its expiry from a stored login.
// A missing expiry is the zero time.
func (l HostLogin) AccessToken(secret []byte) (string, time.Time, error) {
	var doc any
	if err := json.Unmarshal(secret, &doc); err != nil {
		return "", time.Time{}, fmt.Errorf("stored login is not JSON: %w", err)
	}
	token, _ := lookup(doc, l.Token).(string)
	if token == "" {
		return "", time.Time{}, ErrNoToken
	}
	var expires time.Time
	if ms, ok := lookup(doc, l.Expiry).(float64); ok && ms > 0 {
		expires = time.UnixMilli(int64(ms))
	}
	return token, expires, nil
}

func lookup(doc any, path []string) any {
	for _, k := range path {
		m, ok := doc.(map[string]any)
		if !ok {
			return nil
		}
		doc = m[k]
	}
	return doc
}
