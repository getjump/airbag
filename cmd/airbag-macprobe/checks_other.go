//go:build !darwin

package main

import "runtime"

var checks []func(*probe) Result

// probe holds what main sets; the checks, and the state they keep,
// are macOS-only (probe_darwin.go).
type probe struct {
	opts options
	dir  string
	home string
}

func (p *probe) cleanup() error { return nil }

func systemVersion() string { return runtime.GOOS }
