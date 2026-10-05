//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func prepareVM() error {
	for _, d := range []string{"/dev", "/proc", "/sys", "/tmp", "/work"} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	for _, m := range [][3]string{
		{"devtmpfs", "/dev", "devtmpfs"}, {"proc", "/proc", "proc"},
		{"sysfs", "/sys", "sysfs"}, {"tmpfs", "/tmp", "tmpfs"},
		{"/dev/vdb", "/work", "ext4"},
	} {
		if err := syscall.Mount(m[0], m[1], m[2], 0, ""); err != nil {
			// This kernel mounts devtmpfs before starting PID 1. Other mount
			// failures still fail the experiment rather than hide guest setup errors.
			if m[1] == "/dev" && errors.Is(err, syscall.EBUSY) {
				continue
			}
			return fmt.Errorf("mount %s: %w", m[1], err)
		}
	}
	return nil
}

func stopVM() {
	syscall.Sync()
	// Firecracker detects the keyboard reboot (reboot=k); POWER_OFF merely
	// halts this guest while leaving the host VMM running.
	if err := syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART); err != nil {
		fmt.Fprintln(os.Stderr, "stop VM:", err)
		os.Exit(1)
	}
}
