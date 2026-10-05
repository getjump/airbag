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
# The client needs at least the Go version airbag's go.mod names.
gover=$(sed -n 's/^go \([0-9][0-9.]*\).*/\1/p' "$project/go.mod")
[ -n "$gover" ] || {
	echo "no go line in $project/go.mod" >&2
	exit 1
}
go mod edit -go="$gover" -require=github.com/getjump/airbag@v0.0.0 -replace="github.com/getjump/airbag=$project"
# -race needs cgo and a C compiler; where there is none (the WSL job) the
# client still has to build and pass.
race=-race
if [ "$(go env CGO_ENABLED)" != 1 ] || ! command -v "$(go env CC)" >/dev/null 2>&1; then
	echo "SKIP: -race (no cgo here)"
	race=
fi
go test -mod=mod $race -v ./...
# The reusable packages must not acquire dependencies on session/runtime code.
if go list -mod=mod -deps github.com/getjump/airbag/operation github.com/getjump/airbag/policy github.com/getjump/airbag/outbox github.com/getjump/airbag/proxy github.com/getjump/airbag/githubpr |
	grep '^github.com/getjump/airbag/internal/' | grep -q -v '^github.com/getjump/airbag/internal/netcap$'; then
	echo 'public SDK depends on Airbag session/runtime internals' >&2
	exit 1
fi
