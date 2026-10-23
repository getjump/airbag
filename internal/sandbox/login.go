//go:build darwin

package sandbox

import (
	"fmt"
	"time"

	"github.com/getjump/airbag/internal/agents"
)

// loginMargin: a token that runs out this soon would fail the agent in
// the middle of its first request, so it is not handed over.
const loginMargin = time.Minute

// hostLoginEnv hands the agent the access token of its login when the
// sandbox hides where the host keeps that login (the macOS Keychain).
// The agent gets the access token only, never the refresh token: it
// cannot extend its own access, and a refresh inside the sandbox cannot
// rotate the host's login. A variable the user set to log the agent in
// wins, and airbag then reads nothing. The returned note is for the user.
func hostLoginEnv(argv []string, getenv func(string) string, read func(service string) ([]byte, error), now time.Time) (map[string]string, string) {
	l, ok := agents.LoginFor(argv)
	if !ok {
		return nil, ""
	}
	for _, k := range l.Override {
		if getenv(k) != "" {
			return nil, ""
		}
	}
	hint := fmt.Sprintf("set %s or %s (docs/macos.md)", l.Env, l.Override[0])
	secret, err := read(l.Service)
	if err != nil {
		return nil, fmt.Sprintf("airbag: %s keeps its login in the Keychain, which the sandbox hides, and airbag could not read it (%v); %s", l.Agent, err, hint)
	}
	token, expires, err := l.AccessToken(secret)
	if err != nil {
		return nil, fmt.Sprintf("airbag: %s login in the Keychain: %v; %s", l.Agent, err, hint)
	}
	if !expires.IsZero() && expires.Before(now.Add(loginMargin)) {
		return nil, fmt.Sprintf("airbag: the %s login in the Keychain expired at %s; run %s once outside airbag to refresh it, or %s",
			l.Agent, expires.Local().Format("15:04"), l.Agent, hint)
	}
	note := fmt.Sprintf("airbag: %s login: its access token from the Keychain; the refresh token stays outside", l.Agent)
	if !expires.IsZero() {
		note = fmt.Sprintf("airbag: %s login: its access token from the Keychain, valid until %s; the refresh token stays outside",
			l.Agent, expires.Local().Format("15:04"))
	}
	return map[string]string{l.Env: token}, note
}
