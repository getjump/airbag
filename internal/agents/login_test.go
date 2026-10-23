package agents

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLoginFor(t *testing.T) {
	for _, tc := range []struct {
		argv []string
		want bool
	}{
		{[]string{"claude", "-p", "hi"}, true},
		{[]string{"/Users/me/.local/bin/claude"}, true},
		{[]string{"codex"}, false},
		{[]string{"claude-wrapper"}, false},
		{nil, false},
	} {
		l, ok := LoginFor(tc.argv)
		if ok != tc.want {
			t.Errorf("LoginFor(%q) = %v, want %v", tc.argv, ok, tc.want)
		}
		if ok && l.Env != "CLAUDE_CODE_OAUTH_TOKEN" {
			t.Errorf("LoginFor(%q).Env = %q", tc.argv, l.Env)
		}
	}
}

func TestAccessTokenKeepsRefreshTokenOut(t *testing.T) {
	l, _ := LoginFor([]string{"claude"})
	secret := `{"claudeAiOauth":{"accessToken":"fake-access-value","refreshToken":"fake-refresh-value",` +
		`"expiresAt":1792800000000,"scopes":["user:inference"]}}`
	token, expires, err := l.AccessToken([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if token != "fake-access-value" {
		t.Fatalf("token = %q, want the access token", token)
	}
	if strings.Contains(token, "refresh") {
		t.Fatal("the refresh token must never be handed over")
	}
	if want := time.UnixMilli(1792800000000); !expires.Equal(want) {
		t.Fatalf("expires = %v, want %v", expires, want)
	}
}

func TestAccessTokenErrors(t *testing.T) {
	l, _ := LoginFor([]string{"claude"})
	for _, secret := range []string{"", "not json", `{}`, `{"claudeAiOauth":{}}`, `{"claudeAiOauth":{"accessToken":7}}`, `[]`} {
		if _, _, err := l.AccessToken([]byte(secret)); err == nil {
			t.Errorf("AccessToken(%q) gave no error", secret)
		}
	}
	_, _, err := l.AccessToken([]byte(`{"claudeAiOauth":{"refreshToken":"r"}}`))
	if !errors.Is(err, ErrNoToken) {
		t.Fatalf("err = %v, want ErrNoToken", err)
	}
	_, expires, err := l.AccessToken([]byte(`{"claudeAiOauth":{"accessToken":"a"}}`))
	if err != nil || !expires.IsZero() {
		t.Fatalf("missing expiry: %v, %v; want the zero time and no error", expires, err)
	}
}

// The stored login comes from the host's Keychain, but a parser must not
// panic on any bytes, and a token it returns is never empty.
func FuzzAccessToken(f *testing.F) {
	f.Add([]byte(`{"claudeAiOauth":{"accessToken":"a","expiresAt":1}}`))
	f.Add([]byte(`{"claudeAiOauth":[]}`))
	f.Add([]byte(`null`))
	l, _ := LoginFor([]string{"claude"})
	f.Fuzz(func(t *testing.T, b []byte) {
		token, _, err := l.AccessToken(b)
		if err == nil && token == "" {
			t.Fatal("no error but an empty token")
		}
	})
}
