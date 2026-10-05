//go:build darwin

package sandbox

import "fmt"

func Guest([]string) int { fmt.Println("airbag: optional runtime guest requires Linux"); return 125 }

func optionalHostReady(string) error { return fmt.Errorf("optional execution requires Linux") }
