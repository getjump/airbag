package main

import (
	"runtime/debug"
	"testing"
)

// A release stamps the version with -ldflags; go install ...@vX does
// not, and airbag version must still print vX from the build info.
func TestBuildVersion(t *testing.T) {
	info := func(v string, ok bool) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) {
			if !ok {
				return nil, false
			}
			return &debug.BuildInfo{Main: debug.Module{Path: "github.com/getjump/airbag", Version: v}}, true
		}
	}
	for _, tc := range []struct {
		name    string
		stamped string
		module  string
		ok      bool
		want    string
	}{
		{"go install @tag", "dev", "v0.1.0", true, "v0.1.0"},
		{"pre-release tag", "dev", "v0.1.0-rc.1", true, "v0.1.0-rc.1"},
		{"checkout between tags", "dev", "v0.1.1-0.20261005101200-0123456789ab+dirty", true, "v0.1.1-0.20261005101200-0123456789ab+dirty"},
		{"ldflags win", "v0.2.0", "v0.1.0", true, "v0.2.0"},
		{"no vcs stamp", "dev", "(devel)", true, "dev"},
		{"empty module version", "dev", "", true, "dev"},
		{"no build info", "dev", "", false, "dev"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildVersion(tc.stamped, info(tc.module, tc.ok)); got != tc.want {
				t.Errorf("buildVersion(%q) with module version %q = %q, want %q", tc.stamped, tc.module, got, tc.want)
			}
		})
	}
}
