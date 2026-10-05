//go:build linux && !386

package main

// socketcall is an i386-only multiplexer; on other ABIs there is nothing
// to probe.
func socketcallSocket() string { return "n/a" }
