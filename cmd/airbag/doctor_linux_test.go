//go:build linux

package main

import "testing"

// A pipe or a socket core_pattern is flagged as one the agent's core
// dumps may reach; a file pattern is not.
func TestCorePattern(t *testing.T) {
	for _, c := range []struct {
		pattern string
		covered bool
	}{
		{"core", true},
		{"/var/crash/core.%e.%p", true},
		{"|/usr/lib/systemd/systemd-coredump %P %u %g %s %t %c %h", false},
		{"|/usr/share/apport/apport -p%p -s%s -c%c -d%d -P%P -u%u -g%g -- %E", false},
		{"@/run/systemd/coredump.socket", false},
		{"@@/run/systemd/coredump.socket", false},
	} {
		if covered, _ := corePattern(c.pattern); covered != c.covered {
			t.Errorf("%q: covered=%v, want %v", c.pattern, covered, c.covered)
		}
	}
}
