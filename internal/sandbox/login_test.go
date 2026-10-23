//go:build darwin

package sandbox

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const storedLogin = `{"claudeAiOauth":{"accessToken":"fake-access-value","refreshToken":"fake-refresh-value",` +
	`"expiresAt":%d,"scopes":["user:inference"]}}`

func loginReader(secret string, calls *int) func(string) ([]byte, error) {
	return func(service string) ([]byte, error) {
		*calls++
		if service != "Claude Code-credentials" {
			return nil, errors.New("unexpected service " + service)
		}
		return []byte(secret), nil
	}
}

func noEnv(string) string { return "" }

func TestHostLoginHandsOverTheAccessTokenOnly(t *testing.T) {
	now := time.Now()
	secret := fmt.Sprintf(storedLogin, now.Add(2*time.Hour).UnixMilli())
	calls := 0
	env, note := hostLoginEnv([]string{"/usr/local/bin/claude", "-p", "hi"}, noEnv, loginReader(secret, &calls), now)
	if env["CLAUDE_CODE_OAUTH_TOKEN"] != "fake-access-value" || len(env) != 1 {
		t.Fatalf("env = %v, want only CLAUDE_CODE_OAUTH_TOKEN with the access token", env)
	}
	for k, v := range env {
		if strings.Contains(v, "refresh") || strings.Contains(k, "REFRESH") {
			t.Fatal("the refresh token must stay on the host")
		}
	}
	if !strings.Contains(note, "refresh token stays outside") || strings.Contains(note, "fake-access-value") {
		t.Fatalf("note = %q: must say what was handed over and never print a token", note)
	}
	if calls != 1 {
		t.Fatalf("Keychain read %d times, want 1", calls)
	}
}

func TestHostLoginLeavesAUserLoginAlone(t *testing.T) {
	for _, k := range []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"} {
		calls := 0
		getenv := func(name string) string {
			if name == k {
				return "user-set"
			}
			return ""
		}
		env, note := hostLoginEnv([]string{"claude"}, getenv, loginReader("{}", &calls), time.Now())
		if env != nil || note != "" || calls != 0 {
			t.Errorf("%s set: env=%v note=%q reads=%d; want nothing done and the Keychain not read", k, env, note, calls)
		}
	}
}

func TestHostLoginOnlyForAgentsThatHaveOne(t *testing.T) {
	calls := 0
	env, note := hostLoginEnv([]string{"codex", "exec"}, noEnv, loginReader("{}", &calls), time.Now())
	if env != nil || note != "" || calls != 0 {
		t.Fatalf("codex: env=%v note=%q reads=%d; want nothing", env, note, calls)
	}
}

func TestHostLoginExpired(t *testing.T) {
	now := time.Now()
	secret := fmt.Sprintf(storedLogin, now.Add(30*time.Second).UnixMilli())
	calls := 0
	env, note := hostLoginEnv([]string{"claude"}, noEnv, loginReader(secret, &calls), now)
	if env != nil {
		t.Fatalf("env = %v, want no token that runs out within a minute", env)
	}
	if !strings.Contains(note, "expired") || !strings.Contains(note, "CLAUDE_CODE_OAUTH_TOKEN") {
		t.Fatalf("note = %q, want the expiry and the variable to set", note)
	}
}

func TestHostLoginUnreadable(t *testing.T) {
	read := func(string) ([]byte, error) {
		return nil, errors.New("The specified item could not be found in the keychain.")
	}
	env, note := hostLoginEnv([]string{"claude"}, noEnv, read, time.Now())
	if env != nil || !strings.Contains(note, "could not read it") || !strings.Contains(note, "docs/macos.md") {
		t.Fatalf("env=%v note=%q; want no token and a pointer to the docs", env, note)
	}
	env, note = hostLoginEnv([]string{"claude"}, noEnv, func(string) ([]byte, error) { return []byte("not json"), nil }, time.Now())
	if env != nil || note == "" {
		t.Fatalf("garbage login: env=%v note=%q; want no token and a note", env, note)
	}
}
