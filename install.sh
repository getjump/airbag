#!/bin/sh
# Installs airbag from a release into ~/.local/bin (or $AIRBAG_BIN), never
# with sudo:
#   curl --proto '=https' --tlsv1.2 -fsSL https://github.com/getjump/airbag/releases/latest/download/install.sh | sh
#
# AIRBAG_VERSION=v0.1.0  installs that release instead of the latest one.
# AIRBAG_VERIFY=require  refuses to install unless cosign or a logged-in gh
#                        has checked that the release workflow built the
#                        archive.
#
# By default the script makes that check when cosign or a logged-in gh is
# installed, and stops if the check fails. Without either, it checks the
# archive's SHA-256 against the release's checksums.txt only, and says so.
# docs/verify.md shows the same checks by hand. Everything runs in main,
# called on the last line, so a download cut short runs no part of it.
set -eu

repo=getjump/airbag

die() {
	echo "airbag: $*" >&2
	exit 1
}

# fetch NAME downloads the release's file NAME into $tmp.
fetch() {
	curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$tmp/$1" "$base/$1" ||
		die "could not download $base/$1"
}

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | cut -d' ' -f1
	else
		die "needs sha256sum or shasum to check the download"
	fi
}

main() {
	bin=${AIRBAG_BIN:-$HOME/.local/bin}
	case ${AIRBAG_VERIFY:-} in
	'' | require) ;;
	*) die "AIRBAG_VERIFY is either require or unset, not $AIRBAG_VERIFY" ;;
	esac

	os=$(uname -s | tr '[:upper:]' '[:lower:]')
	case $(uname -m) in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) die "unsupported architecture $(uname -m)" ;;
	esac
	case $os in
	linux) ;;
	darwin)
		# The release binaries are built with a Go that needs macOS 13.
		v=$(/usr/bin/sw_vers -productVersion 2>/dev/null || :)
		[ "${v%%.*}" -ge 13 ] 2>/dev/null || die "needs macOS 13 or later, this is ${v:-unknown}"
		;;
	*) die "unsupported system $os" ;;
	esac

	# Where the files are, and the identity cosign wants on the signature:
	# the release workflow, run for this tag (or for a v* tag, for the
	# latest release).
	if [ -n "${AIRBAG_VERSION:-}" ]; then
		case $AIRBAG_VERSION in
		*[!A-Za-z0-9.+-]* | [!v]* | v | v[!0-9]*)
			die "AIRBAG_VERSION is a release tag such as v0.1.0, not $AIRBAG_VERSION"
			;;
		esac
		base=https://github.com/$repo/releases/download/$AIRBAG_VERSION
		idflag=--certificate-identity
		id=https://github.com/$repo/.github/workflows/release.yml@refs/tags/$AIRBAG_VERSION
	else
		base=https://github.com/$repo/releases/latest/download
		idflag=--certificate-identity-regexp
		id="^https://github\\.com/$repo/\\.github/workflows/release\\.yml@refs/tags/v[0-9][A-Za-z0-9.+-]*\$"
	fi

	# What can check who built the release.
	verifier=
	if command -v cosign >/dev/null 2>&1; then
		verifier=cosign
	elif command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1 &&
		gh attestation verify --help >/dev/null 2>&1; then
		verifier=gh
	elif [ "${AIRBAG_VERIFY:-}" = require ]; then
		die "AIRBAG_VERIFY=require, but neither cosign nor a logged-in gh is installed"
	fi

	archive=airbag_${os}_${arch}.tar.gz
	tmp=$(mktemp -d "${TMPDIR:-/tmp}/airbag-install.XXXXXX")
	trap 'rm -rf "$tmp"' EXIT
	trap 'exit 1' HUP INT TERM
	fetch "$archive"
	fetch checksums.txt

	# 1. Who built it. A verifier that is there and says no is fatal.
	case $verifier in
	cosign)
		fetch checksums.txt.sigstore.json
		# cosign 3 writes the bundle; cosign 2 reads it with this flag.
		newbundle=
		case $(cosign version 2>/dev/null | awk '$1 == "GitVersion:" { print $2 }') in
		v2.*) newbundle=--new-bundle-format ;;
		esac
		if ! out=$(cosign verify-blob ${newbundle:+"$newbundle"} \
			--bundle "$tmp/checksums.txt.sigstore.json" \
			"$idflag" "$id" \
			--certificate-oidc-issuer https://token.actions.githubusercontent.com \
			"$tmp/checksums.txt" 2>&1); then
			echo "$out" >&2
			die "cosign: the signature on checksums.txt does not verify; not installing"
		fi
		how="cosign checked the release workflow's signature on checksums.txt"
		;;
	gh)
		set -- --signer-workflow "$repo/.github/workflows/release.yml"
		[ -z "${AIRBAG_VERSION:-}" ] || set -- "$@" --source-ref "refs/tags/$AIRBAG_VERSION"
		if ! out=$(gh attestation verify "$tmp/$archive" --repo "$repo" "$@" 2>&1); then
			echo "$out" >&2
			die "gh: $archive has no valid build attestation from the release workflow; not installing"
		fi
		how="gh checked the release workflow's build attestation of $archive"
		;;
	esac

	# 2. The archive is the one checksums.txt lists.
	want=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/checksums.txt")
	got=$(sha256 "$tmp/$archive")
	[ -n "$want" ] && [ "$want" = "$got" ] || die "checksum mismatch for $archive; not installing"

	tar -xzf "$tmp/$archive" -C "$tmp" airbag
	mkdir -p "$bin"
	install -m 755 "$tmp/airbag" "$bin/airbag"
	echo "airbag installed to $bin/airbag"
	if [ -n "$verifier" ]; then
		echo "$how, and its SHA-256"
	else
		echo "note: only the SHA-256 in the release's checksums.txt was checked. That shows"
		echo "the download is intact, not who built it. Install cosign or log in with gh,"
		echo "then run this again to check that too (docs/verify.md)."
	fi
	case ":$PATH:" in *":$bin:"*) ;; *) echo "add $bin to your PATH" ;; esac
	"$bin/airbag" doctor || true
}

main "$@"
