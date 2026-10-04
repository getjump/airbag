//go:build linux

package shim

import "golang.org/x/sys/unix"

const ioctlGetTermios = unix.TCGETS
