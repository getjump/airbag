//go:build linux

package main

import (
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
			return fmt.Errorf("mount %s: %w", m[1], err)
		}
	}
	return nil
}

func poweroff() {
	syscall.Sync()
	if err := syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF); err != nil {
		fmt.Fprintln(os.Stderr, "poweroff:", err)
		os.Exit(1)
	}
}
