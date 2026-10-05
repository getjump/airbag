package sandbox

import "testing"

func TestNativeBoundaries(t *testing.T) {
	linux, mac := nativeBackend("linux"), nativeBackend("darwin")
	if linux.Isolation != "shared-kernel" || mac.Isolation != "shared-kernel" {
		t.Fatal("native must not claim a separate application or guest kernel")
	}
	if !linux.HomeBranch || mac.HomeBranch || mac.WorkspaceBranch != "clone" {
		t.Fatal("platform filesystem guarantees differ")
	}
	for _, b := range []Backend{linux, mac} {
		for _, required := range []string{"application-kernel", "virtual-machine", "typo"} {
			if b.Require(required) == nil {
				t.Fatalf("%s accepted %s", b.Platform, required)
			}
		}
	}
}
