#!/bin/sh
# Compile and run a client outside Airbag's module/internal import boundary.
set -eu
project=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
client_dir=$(mktemp -d "${TMPDIR:-/tmp}/airbag-sdk-XXXXXX")
trap 'rm -rf "$client_dir"' EXIT HUP INT TERM
cp "$project/test/sdk-client/client_test.go" "$client_dir/client_test.go"
cd "$client_dir"
export GOWORK=off
go mod init example.com/airbag-client
go mod edit -go=1.27.1 -require=github.com/getjump/airbag@v0.0.0 -replace="github.com/getjump/airbag=$project"
go test -mod=mod -race -v ./...
# The reusable packages must not acquire dependencies on session/runtime code.
if go list -mod=mod -deps github.com/getjump/airbag/operation github.com/getjump/airbag/policy github.com/getjump/airbag/outbox github.com/getjump/airbag/proxy github.com/getjump/airbag/githubpr |
	grep '^github.com/getjump/airbag/internal/' | grep -q -v '^github.com/getjump/airbag/internal/netcap$'; then
	echo 'public SDK depends on Airbag session/runtime internals' >&2
	exit 1
fi
