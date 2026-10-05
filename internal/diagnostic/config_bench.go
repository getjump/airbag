//go:build airbag_bench

package diagnostic

import "os"

type RuntimeConfig struct {
	SkipFileGate     bool
	SkipRuntimeAudit bool
}

// Secret-read notifications always keep their durable barrier; the runtime
// channel enforces that independently of this diagnostic configuration.
func Config() RuntimeConfig {
	switch os.Getenv("AIRBAG_BENCH_RUNTIME_STAGE") {
	case "plain-fuse":
		return RuntimeConfig{SkipFileGate: true, SkipRuntimeAudit: true}
	case "policy-no-audit":
		return RuntimeConfig{SkipRuntimeAudit: true}
	default:
		return RuntimeConfig{}
	}
}
