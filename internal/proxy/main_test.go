package proxy

import (
	"testing"

	"go.uber.org/goleak"
)

// Each package's tests end with no goroutine left over: one would be a
// connection, server or database the tests or the code did not close.
func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }
