#!/bin/sh
# The checks CI runs besides the tests, with the same pinned tools:
#
#   hygiene  gofmt, go mod tidy and verify, go vet for Linux and macOS
#   lint     golangci-lint (.golangci.yml) for Linux and macOS
#   vuln     govulncheck for Linux and macOS
#   shell    shellcheck on the shell scripts
#   actions  actionlint on .github/workflows
#   race     go test -race
#   fuzz [TIME]  every Fuzz target for TIME (default 20s)
#
# With no argument it runs hygiene, lint, vuln, shell and actions. Go
# tools are built on first use with this repository's toolchain into
# $AIRBAG_TOOLS (default ~/.cache/airbag-check); shellcheck is
# downloaded and checked against its hash.
set -eu

# The versions CI uses: it runs this script, so change them here.
golangci_lint=v2.14.0
govulncheck=v1.8.0
actionlint=v1.7.12
shellcheck=v0.11.0

# The release archive of shellcheck for this machine, in $build, and
# its sha256, in $sum.
shellcheck_release() {
	case $(uname -s)/$(uname -m) in
	Linux/x86_64) build=linux.x86_64 sum=8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198 ;;
	Linux/aarch64 | Linux/arm64) build=linux.aarch64 sum=12b331c1d2db6b9eb13cfca64306b1b157a86eb69db83023e261eaa7e7c14588 ;;
	Darwin/x86_64) build=darwin.x86_64 sum=3c89db4edcab7cf1c27bff178882e0f6f27f7afdf54e859fa041fca10febe4c6 ;;
	Darwin/arm64) build=darwin.aarch64 sum=56affdd8de5527894dca6dc3d7e0a99a873b0f004d7aabc30ae407d3f48b0a79 ;;
	*) die "no shellcheck $shellcheck build for $(uname -sm)" ;;
	esac
}

die() {
	echo "check: $*" >&2
	exit 1
}

cd "$(dirname "$0")/.."
# The toolchain go.mod selects; the Go tools are built with it, so they
# can load code that needs it.
gover=$(go env GOVERSION)
toolchain=$gover
case $gover in
go[0-9]*) ;;
*) toolchain=local gover=$(echo "$gover" | tr -c 'A-Za-z0-9.\n-' _) ;; # a development build
esac
tools=${AIRBAG_TOOLS:-${XDG_CACHE_HOME:-$HOME/.cache}/airbag-check}
case $tools in
/*) ;;
*) die "AIRBAG_TOOLS must be an absolute path" ;;
esac

# gotool PKG VERSION prints the path of PKG's command, built first if
# this version is not there yet.
gotool() {
	dir=$tools/${1##*/}-$2-$gover
	if [ ! -x "$dir/${1##*/}" ]; then
		echo "check: building $1@$2 with $gover" >&2
		GOTOOLCHAIN=$toolchain GOFLAGS='' GOBIN=$dir go install "$1@$2" >&2
	fi
	echo "$dir/${1##*/}"
}

shellcheck_path() {
	shellcheck_release
	dir=$tools/shellcheck-$shellcheck-$build
	if [ ! -x "$dir/shellcheck" ]; then
		echo "check: downloading shellcheck $shellcheck" >&2
		mkdir -p "$dir"
		curl -fsSL -o "$dir/shellcheck.tar.xz" \
			"https://github.com/koalaman/shellcheck/releases/download/$shellcheck/shellcheck-$shellcheck.$build.tar.xz"
		if command -v sha256sum >/dev/null; then
			got=$(sha256sum "$dir/shellcheck.tar.xz")
		else
			got=$(shasum -a 256 "$dir/shellcheck.tar.xz")
		fi
		if [ "${got%% *}" != "$sum" ]; then
			rm -f "$dir/shellcheck.tar.xz"
			die "shellcheck $shellcheck.$build: sha256 ${got%% *}, want $sum"
		fi
		tar -xJf "$dir/shellcheck.tar.xz" -C "$dir" --strip-components=1 "shellcheck-$shellcheck/shellcheck"
		rm -f "$dir/shellcheck.tar.xz"
	fi
	echo "$dir/shellcheck"
}

check_hygiene() {
	echo "== gofmt"
	out=$("$(go env GOROOT)/bin/gofmt" -l .)
	[ -z "$out" ] || die "not gofmt'ed:
$out"
	echo "== go mod tidy, verify"
	go mod tidy -diff
	go mod verify
	for os in linux darwin; do
		echo "== go vet GOOS=$os"
		GOOS=$os go vet ./...
	done
}

check_lint() {
	bin=$(gotool github.com/golangci/golangci-lint/v2/cmd/golangci-lint "$golangci_lint")
	for os in linux darwin; do
		echo "== golangci-lint GOOS=$os"
		GOOS=$os "$bin" run ./...
	done
}

check_vuln() {
	bin=$(gotool golang.org/x/vuln/cmd/govulncheck "$govulncheck")
	for os in linux darwin; do
		echo "== govulncheck GOOS=$os"
		GOOS=$os "$bin" ./...
	done
}

check_shell() {
	sc=$(shellcheck_path)
	echo "== shellcheck"
	"$sc" test/*.sh install.sh demo/*.sh .github/scripts/*.sh
}

check_actions() {
	bin=$(gotool github.com/rhysd/actionlint/cmd/actionlint "$actionlint")
	sc=$(shellcheck_path)
	echo "== actionlint"
	"$bin" -shellcheck="$sc"
}

check_race() {
	echo "== go test -race"
	go test -race ./...
}

# check_fuzz runs each Fuzz target on its own: go test -fuzz takes one
# target in one package.
check_fuzz() {
	targets=$(grep -rn --include='*_test.go' '^func Fuzz' . |
		sed 's|^\./\(.*\)/[^/]*:[0-9]*:func \(Fuzz[A-Za-z0-9_]*\)(.*|\1:\2|')
	[ -n "$targets" ] || die "no Fuzz targets found"
	echo "== fuzz: $(echo "$targets" | wc -l | tr -d ' ') targets, $1 each"
	for t in $targets; do
		echo "== ./${t%%:*} ${t#*:}"
		go test -run='^$' -fuzz="^${t#*:}\$" -fuzztime="$1" "./${t%%:*}"
	done
}

[ $# -gt 0 ] || set -- hygiene lint vuln shell actions
while [ $# -gt 0 ]; do
	case $1 in
	hygiene | lint | vuln | shell | actions | race)
		"check_$1"
		shift
		;;
	fuzz)
		shift
		t=20s
		case ${1:-} in
		[0-9]*)
			t=$1
			shift
			;;
		esac
		check_fuzz "$t"
		;;
	*) die "unknown check $1; see the top of $0" ;;
	esac
done
