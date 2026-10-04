//go:build darwin

package shim

import "golang.org/x/sys/unix"

const ioctlGetTermios = unix.TIOCGETA
