//go:build !darwin

package main

import "runtime"

var checks []func(*probe) Result

func (p *probe) cleanup() {}

func systemVersion() string { return runtime.GOOS }
