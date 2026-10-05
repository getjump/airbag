//go:build darwin

package sandbox

import (
	"fmt"
	"os"
)

// ExecInit exists on Linux only: cmdRun refuses --exec-policy elsewhere.
func ExecInit(string, []string) {
	fmt.Fprintln(os.Stderr, "airbag: exec policy requires Linux")
	os.Exit(125)
}
