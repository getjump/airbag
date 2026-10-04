#!/bin/sh
# Installs the latest airbag release into ~/.local/bin (or $AIRBAG_BIN):
#   curl -fsSL https://raw.githubusercontent.com/getjump/airbag/main/install.sh | sh
# AIRBAG_VERSION=v0.1.0 picks a release. The binary is checked against
# the release's SHA256SUMS before it is installed.
set -eu

repo=getjump/airbag
bin=${AIRBAG_BIN:-$HOME/.local/bin}
os=$(uname -s | tr '[:upper:]' '[:lower:]')
case $(uname -m) in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) echo "airbag: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
case $os in
	linux) ;;
	darwin)
		# The release binaries are built with a Go that needs macOS 13.
		v=$(sw_vers -productVersion)
		[ "${v%%.*}" -ge 13 ] || { echo "airbag: needs macOS 13 or later, this is $v" >&2; exit 1; }
		;;
	*) echo "airbag: unsupported system $os" >&2; exit 1 ;;
esac

if [ -n "${AIRBAG_VERSION:-}" ]; then
	base="https://github.com/$repo/releases/download/$AIRBAG_VERSION"
else
	base="https://github.com/$repo/releases/latest/download"
fi
name="airbag-$os-$arch"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -fsSL -o "$tmp/$name" "$base/$name"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"
want=$(grep " $name\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)
if command -v sha256sum >/dev/null; then
	got=$(sha256sum "$tmp/$name" | cut -d' ' -f1)
else
	got=$(shasum -a 256 "$tmp/$name" | cut -d' ' -f1)
fi
[ -n "$want" ] && [ "$want" = "$got" ] || { echo "airbag: checksum mismatch for $name" >&2; exit 1; }

mkdir -p "$bin"
install -m 755 "$tmp/$name" "$bin/airbag"
echo "airbag installed to $bin/airbag"
case ":$PATH:" in *":$bin:"*) ;; *) echo "add $bin to your PATH" ;; esac
"$bin/airbag" doctor || true
