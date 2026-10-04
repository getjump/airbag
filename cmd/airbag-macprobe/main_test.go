package main

import (
	"testing"

	"go.uber.org/goleak"
)

// Each package's tests end with no goroutine left over: one would be a
// connection, server or database the tests or the code did not close.
// The exception is the NFS client library the tests use to talk to the
// probe's server: every Target it makes starts a cache cleaner that
// nothing can stop.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m, goleak.IgnoreAnyFunction("github.com/willscott/go-nfs-client/nfs.(*Target).cleanupCache"))
}
