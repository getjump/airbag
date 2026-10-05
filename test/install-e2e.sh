#!/bin/sh
# install.sh against a fake release. curl, uname, cosign and gh are stubs
# on a PATH of their own, so nothing is downloaded and a real cosign or gh
# is never used. The installer must install with the checksum alone and
# say so, or with cosign or gh verifying. It must refuse a bad signature,
# a missing attestation, a tampered archive, an odd AIRBAG_VERSION and
# AIRBAG_VERIFY=require with no verifier, and a download cut short must
# run no part of it. INSTALL_SH picks the shell (default: sh).
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
shell=$(command -v "${INSTALL_SH:-sh}")
T=$(mktemp -d "${TMPDIR:-/tmp}/airbag-install-e2e.XXXXXX")
trap 'rm -rf "$T"' EXIT
fail() {
	echo "FAIL: $*"
	exit 1
}

sum() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$@"
	else
		shasum -a 256 "$@"
	fi
}

# The release: an archive with a stand-in airbag, its checksum and a
# signature bundle that only the cosign stub reads.
mkdir -p "$T/pkg" "$T/rel"
cat >"$T/pkg/airbag" <<'EOF'
#!/bin/sh
case $1 in
version) echo "airbag v0.1.0" ;;
doctor) echo "stand-in doctor ran" ;;
esac
EOF
chmod 755 "$T/pkg/airbag"
cp "$root/LICENSE" "$root/README.md" "$T/pkg/"
tar -czf "$T/rel/airbag_linux_amd64.tar.gz" -C "$T/pkg" airbag LICENSE README.md
cp "$root/install.sh" "$T/rel/"
(cd "$T/rel" && sum airbag_linux_amd64.tar.gz install.sh >checksums.txt)
echo '{"stand-in": "bundle"}' >"$T/rel/checksums.txt.sigstore.json"
# The same release with the archive changed after checksums.txt was made.
cp -R "$T/rel" "$T/tampered"
printf x >>"$T/tampered/airbag_linux_amd64.tar.gz"

# The tools the installer may use, and nothing else.
mkdir -p "$T/tools"
for t in awk cat cp cut gzip install mkdir mktemp rm sha256sum shasum tar tr; do
	p=$(command -v "$t" 2>/dev/null) && ln -s "$p" "$T/tools/$t"
done
cat >"$T/tools/uname" <<'EOF'
#!/bin/sh
case $1 in -s) echo Linux ;; -m) echo x86_64 ;; esac
EOF
# curl serves the release's files for HTTPS with TLS 1.2 only.
cat >"$T/tools/curl" <<'EOF'
#!/bin/sh
out= url= proto= tls=
while [ $# -gt 0 ]; do
	case $1 in
	-o | --proto | --retry) [ "$1" = -o ] && out=$2; [ "$1" = --proto ] && proto=$2; shift 2 ;;
	--tlsv1.2) tls=1; shift ;;
	-*) shift ;;
	*) url=$1; shift ;;
	esac
done
echo "curl $url" >>"$STUBLOG"
[ "$proto" = =https ] && [ -n "$tls" ] || { echo "curl stub: not limited to HTTPS and TLS 1.2" >&2; exit 2; }
case $url in
https://github.com/getjump/airbag/releases/latest/download/* | \
https://github.com/getjump/airbag/releases/download/v0.1.0/*)
	[ -f "$REL/${url##*/}" ] || exit 22
	cp "$REL/${url##*/}" "$out" ;;
*) exit 22 ;;
esac
EOF
# stub DIR NAME BODY writes a stub command NAME into $T/DIR.
stub() {
	mkdir -p "$T/$1"
	printf '#!/bin/sh\n%s\n' "$3" >"$T/$1/$2"
	chmod 755 "$T/$1/$2"
}
chmod 755 "$T/tools/uname" "$T/tools/curl"
# shellcheck disable=SC2016 # the stubs expand these
cosign_stub() { # cosign_stub VERSION EXIT
	printf 'case $1 in version) echo "GitVersion:    %s"; exit 0 ;; esac\necho "cosign $*" >>"$STUBLOG"\n[ %s = 0 ] || echo "Error: none of the expected identities matched" >&2\nexit %s' "$1" "$2" "$2"
}
# shellcheck disable=SC2016 # the stubs expand these
gh_stub() { # gh_stub AUTH-EXIT VERIFY-EXIT
	printf 'case "$1 $2" in "auth status") exit %s ;; esac\ncase " $* " in *" --help "*) exit 0 ;; esac\necho "gh $*" >>"$STUBLOG"\nexit %s' "$1" "$2"
}
stub cosign cosign "$(cosign_stub v3.0.6 0)"
stub cosign2 cosign "$(cosign_stub v2.6.1 0)"
stub cosignbad cosign "$(cosign_stub v3.0.6 1)"
stub gh gh "$(gh_stub 0 0)"
stub ghbad gh "$(gh_stub 0 1)"
stub ghnoauth gh "$(gh_stub 1 0)"

# inst [DIR] [VAR=VALUE]...: runs install.sh with the stubs in $T/DIR
# ahead of the tools, in an empty environment and a fresh $HOME.
inst() {
	path=$T/tools
	case ${1:-} in *=* | '') ;; *)
		path=$T/$1:$path
		shift
		;;
	esac
	rm -rf "${T:?}/home" "$T/tmp"
	mkdir -p "$T/home" "$T/tmp"
	: >"$T/log"
	rc=0
	env -i HOME="$T/home" TMPDIR="$T/tmp" STUBLOG="$T/log" REL="$T/rel" PATH="$path" "$@" \
		"$shell" "$root/install.sh" >"$T/out" 2>&1 || rc=$?
	[ -z "$(ls -A "$T/tmp")" ] || fail "the installer left files in TMPDIR: $(ls -A "$T/tmp")"
}
bin=$T/home/.local/bin/airbag
installed() {
	[ "$rc" -eq 0 ] && [ -x "$bin" ] || fail "$1: not installed ($rc): $(cat "$T/out")"
	grep -q 'stand-in doctor ran' "$T/out" || fail "$1: airbag doctor did not run: $(cat "$T/out")"
}
refused() {
	[ "$rc" -ne 0 ] && [ ! -e "$bin" ] || fail "$1: installed anyway: $(cat "$T/out")"
	grep -q "$2" "$T/out" || fail "$1: no \"$2\" in: $(cat "$T/out")"
}
said() { grep -q -- "$2" "$T/out" || fail "$1: no \"$2\" in: $(cat "$T/out")"; }
logged() { grep -q -- "$2" "$T/log" || fail "$1: no \"$2\" in the log: $(cat "$T/log")"; }
fetched_nothing() { [ ! -s "$T/log" ] || fail "$1: downloaded anyway: $(cat "$T/log")"; }

# Neither cosign nor gh: the checksum only, and the installer says so.
inst
installed "checksum only"
said "checksum only" "only the SHA-256"
logged "checksum only" "curl https://github.com/getjump/airbag/releases/latest/download/airbag_linux_amd64.tar.gz"
logged "checksum only" "curl https://github.com/getjump/airbag/releases/latest/download/checksums.txt"
[ "$(grep -c . "$T/log")" -eq 2 ] || fail "checksum only: fetched more than the archive and checksums.txt: $(cat "$T/log")"

# cosign, for a pinned release: the exact workflow identity of its tag.
inst cosign AIRBAG_VERSION=v0.1.0
installed "cosign"
said "cosign" "cosign checked the release workflow's signature"
logged "cosign" "curl https://github.com/getjump/airbag/releases/download/v0.1.0/checksums.txt.sigstore.json"
logged "cosign" "--certificate-identity https://github.com/getjump/airbag/.github/workflows/release.yml@refs/tags/v0.1.0 "
logged "cosign" "--certificate-oidc-issuer https://token.actions.githubusercontent.com "
logged "cosign" "--bundle $T/tmp/airbag-install\..*/checksums.txt.sigstore.json"
if grep -q -- "only the SHA-256" "$T/out"; then fail "cosign: said only the checksum was checked"; fi

# cosign, for the latest release: any v* tag of this repository's
# release workflow, and nothing else.
inst cosign
installed "cosign latest"
re=$(sed -n 's/.*--certificate-identity-regexp \([^ ]*\) .*/\1/p' "$T/log")
[ -n "$re" ] || fail "cosign latest: no --certificate-identity-regexp: $(cat "$T/log")"
for id in v0.1.0 v0.1.0-rc.1 v1.2.3+meta; do
	echo "https://github.com/getjump/airbag/.github/workflows/release.yml@refs/tags/$id" | grep -Eq "$re" ||
		fail "cosign latest: $re does not match the tag $id"
done
for id in https://github.com/getjump/airbag/.github/workflows/release.yml@refs/heads/main \
	https://github.com/getjump/airbag/.github/workflows/ci.yml@refs/tags/v0.1.0 \
	https://github.com/evil/airbag/.github/workflows/release.yml@refs/tags/v0.1.0 \
	https://github.com/getjump/airbag/.github/workflows/release.yml@refs/tags/v0.1.0/x \
	https://githubXcom/getjump/airbag/.github/workflows/release.yml@refs/tags/v0.1.0; do
	if echo "$id" | grep -Eq "$re"; then fail "cosign latest: $re matches $id"; fi
done

# cosign 2 reads the bundle with --new-bundle-format.
inst cosign2 AIRBAG_VERSION=v0.1.0
installed "cosign 2"
logged "cosign 2" "cosign verify-blob --new-bundle-format "

# A signature cosign rejects stops the install, with cosign's reason.
inst cosignbad
refused "bad signature" "the signature on checksums.txt does not verify"
said "bad signature" "none of the expected identities matched"

# gh, logged in and without cosign: the build attestation of the archive.
inst gh AIRBAG_VERSION=v0.1.0
installed "gh"
said "gh" "gh checked the release workflow's build attestation"
logged "gh" "gh attestation verify $T/tmp/airbag-install\..*/airbag_linux_amd64.tar.gz --repo getjump/airbag --signer-workflow getjump/airbag/.github/workflows/release.yml --source-ref refs/tags/v0.1.0"
inst ghbad
refused "no attestation" "has no valid build attestation"

# gh that is not logged in is no verifier.
inst ghnoauth
installed "gh not logged in"
said "gh not logged in" "only the SHA-256"

# AIRBAG_VERIFY=require without a verifier refuses before downloading.
inst AIRBAG_VERIFY=require
refused "require, none" "neither cosign nor a logged-in gh"
fetched_nothing "require, none"
inst ghnoauth AIRBAG_VERIFY=require
refused "require, gh not logged in" "neither cosign nor a logged-in gh"
inst cosign AIRBAG_VERIFY=require
installed "require, cosign"
inst AIRBAG_VERIFY=yes
refused "AIRBAG_VERIFY=yes" "AIRBAG_VERIFY is either require or unset"

# An archive that is not the one checksums.txt lists, with and without a
# good signature on checksums.txt.
inst cosign REL="$T/tampered"
refused "tampered, cosign" "checksum mismatch for airbag_linux_amd64.tar.gz"
inst REL="$T/tampered"
refused "tampered" "checksum mismatch for airbag_linux_amd64.tar.gz"
# An archive checksums.txt does not list.
grep -v airbag_linux_amd64 "$T/rel/checksums.txt" >"$T/tampered/checksums.txt"
cp "$T/rel/airbag_linux_amd64.tar.gz" "$T/tampered/"
inst REL="$T/tampered"
refused "not listed" "checksum mismatch"

# AIRBAG_VERSION must look like a tag; it goes into URLs and the identity.
# shellcheck disable=SC2016 # a literal $ in a tag
for v in 0.1.0 v v.1 'v0.1.0/../x' 'v1;id' 'v1 2' 'v0.1.0$x'; do
	inst cosign AIRBAG_VERSION="$v"
	refused "AIRBAG_VERSION=$v" "AIRBAG_VERSION is a release tag"
	fetched_nothing "AIRBAG_VERSION=$v"
done
# A release that does not exist.
inst AIRBAG_VERSION=v9.9.9
refused "missing release" "could not download"

# AIRBAG_BIN, outside the PATH.
inst AIRBAG_BIN="$T/home/bin"
[ "$rc" -eq 0 ] && [ -x "$T/home/bin/airbag" ] || fail "AIRBAG_BIN: not installed there: $(cat "$T/out")"
said "AIRBAG_BIN" "add $T/home/bin to your PATH"

# A download cut short runs no part of the script: no request, no
# install. (Cut right after "main", it runs all of it.)
size=$(wc -c <"$root/install.sh")
for n in 200 $((size / 3)) $((size / 2)) $((size - 12)) $((size - 3)); do
	rm -rf "${T:?}/home" && mkdir -p "$T/home" && : >"$T/log"
	head -c "$n" "$root/install.sh" |
		env -i HOME="$T/home" TMPDIR="$T/tmp" STUBLOG="$T/log" REL="$T/rel" PATH="$T/tools" "$shell" >"$T/out" 2>&1 || :
	fetched_nothing "cut after $n bytes"
	[ ! -e "$bin" ] || fail "cut after $n bytes: installed anyway"
done

echo "PASS: install.sh"
