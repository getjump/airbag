package shim

import "testing"

func TestSubcommand(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"push", "origin", "main"}, "push"},
		{[]string{"-C", "/repo", "push"}, "push"},
		{[]string{"-c", "user.name=x", "--no-pager", "push", "-f"}, "push"},
		{[]string{"--git-dir=/x/.git", "status"}, "status"},
		{[]string{"--version"}, ""},
	} {
		if got, _ := subcommand(tc.args); got != tc.want {
			t.Errorf("subcommand(%v) = %q, want %q", tc.args, got, tc.want)
		}
	}
}
