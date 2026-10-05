//go:build !airbag_bench

package diagnostic

import "testing"

func TestProductionIgnoresBenchmarkStage(t *testing.T) {
	for _, stage := range []string{"plain-fuse", "policy-no-audit"} {
		t.Setenv("AIRBAG_BENCH_RUNTIME_STAGE", stage)
		if got := Config(); got != (RuntimeConfig{}) {
			t.Fatalf("production honored diagnostic stage %q: %+v", stage, got)
		}
	}
}
