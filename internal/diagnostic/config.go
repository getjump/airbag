//go:build !airbag_bench

// Package diagnostic exposes runtime ablations only in a deliberately separate
// benchmark binary. Production binaries do not consult diagnostic environment.
package diagnostic

type RuntimeConfig struct {
	SkipFileGate     bool
	SkipRuntimeAudit bool
}

func Config() RuntimeConfig { return RuntimeConfig{} }
