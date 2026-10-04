//go:build darwin

package sandbox

import (
	"fmt"
	"os"
)

const ExecInitArg = "__airbag_exec_init"

func ExecInit(_ string, _ []string) {
	fmt.Fprintln(os.Stderr, "airbag: exec policy requires Linux")
	os.Exit(125)
}
