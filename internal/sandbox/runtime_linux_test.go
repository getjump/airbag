//go:build linux

package sandbox

import (
	"testing"

	"github.com/getjump/airbag/internal/session"
)

// Only the opt-in runtime options give the sandbox a runtime channel;
// the audit and cache modes alone do not, since they act only through
// a policy.
func TestRuntimeChannelOnlyWithOptions(t *testing.T) {
	cases := []struct {
		meta session.Meta
		want bool
	}{
		{session.Meta{}, false},
		{session.Meta{RuntimeAudit: "buffered", FileCache: "sealed", Strict: true}, false},
		{session.Meta{FilePolicy: true}, true},
		{session.Meta{ExecPolicy: true}, true},
		{session.Meta{RuntimeProfile: true}, true},
	}
	for _, c := range cases {
		if got := runtimeOn(&session.Session{Meta: c.meta}); got != c.want {
			t.Errorf("runtimeOn(%+v) = %v, want %v", c.meta, got, c.want)
		}
	}
}
