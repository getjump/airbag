//go:build !darwin

package main

import "runtime"

var checks []func(*probe) Result

func (p *probe) cleanup() error { return nil }

func systemVersion() string { return runtime.GOOS }
