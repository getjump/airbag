//go:build darwin

package sandbox

import "fmt"

func Guest([]string) int { fmt.Println("airbag: optional runtime guest requires Linux"); return 125 }

// PreflightRuntime rejects non-Linux providers before reaching host readiness.
func optionalHostReady(string) error { return nil }
