# Verifying a release

airbag stands between a coding agent and your machine, so you should be able
to check what you install. Every release is built by
[.github/workflows/release.yml](../.github/workflows/release.yml) from a tag on
`main`, on GitHub's runners, and then published as an immutable release: once
it is out, its tag and its files cannot change.

`install.sh` runs the first checks below itself (see the README's Install
section). This page shows how to run all of them by hand. The examples use
v0.1.0 on Linux amd64; any other release and platform work the same way.

## What a release holds

| File | What it is |
|---|---|
| `airbag_<os>_<arch>.tar.gz` | the binary, with `LICENSE` and `README.md`, for `linux` and `darwin` on `amd64` and `arm64` |
| `airbag_<os>_<arch>.tar.gz.sbom.json` | the archive's SBOM (SPDX JSON): the Go modules in the binary |
| `install.sh` | the installer |
| `checksums.txt` | the SHA-256 of each file above |
| `checksums.txt.sigstore.json` | a Sigstore bundle with the release workflow's keyless signature over `checksums.txt` |

GitHub keeps two attestations beside the files: the build provenance of every
file that `checksums.txt` lists, and the release attestation of the immutable
release.

Download the files:

```console
$ tag=v0.1.0 file=airbag_linux_amd64.tar.gz
$ for f in $file checksums.txt checksums.txt.sigstore.json; do
>   curl --proto '=https' --tlsv1.2 -fsSLO "https://github.com/getjump/airbag/releases/download/$tag/$f"
> done
```

`gh release download $tag --repo getjump/airbag` downloads every file.

## The checksum: the file is intact

```console
$ grep " $file\$" checksums.txt | sha256sum --check
airbag_linux_amd64.tar.gz: OK
```

On macOS, use `shasum -a 256 --check`. This shows that the archive is the one
that `checksums.txt` lists, but not who wrote `checksums.txt`. The signature
and the attestations below show that.

## cosign: the release workflow signed it

With cosign 3 (a recent cosign 2 reads the bundle with `--new-bundle-format`):

```console
$ cosign verify-blob --bundle checksums.txt.sigstore.json \
    --certificate-identity "https://github.com/getjump/airbag/.github/workflows/release.yml@refs/tags/$tag" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    checksums.txt
Verified OK
```

Sigstore issued the bundle's certificate to this repository's release workflow
for this tag, and the signature is in the public Rekor log. With the checksum
step above, this ties the archive to that workflow run. `install.sh` makes
this check whenever cosign is installed.

## gh attestation: how and where it was built

With `gh` logged in (`gh auth login`):

```console
$ gh attestation verify $file --repo getjump/airbag \
    --signer-workflow getjump/airbag/.github/workflows/release.yml \
    --source-ref refs/tags/$tag
```

This checks the build provenance that the release job recorded for the
archive's digest: the repository, the workflow, the commit and the tag.
`--format json` prints all of it. It works for the SBOMs and `install.sh`
too. `install.sh` makes this check when cosign is missing and `gh` is logged
in.

## gh release verify: the release is the one that was published

```console
$ gh release verify $tag --repo getjump/airbag
$ gh release verify-asset $tag $file --repo getjump/airbag
```

The first command checks GitHub's attestation of the immutable release: the
tag's commit and the digest of each file when it was published. The second
checks that your copy of a file is one of them.

## The SBOM

`airbag_linux_amd64.tar.gz.sbom.json` lists the modules and versions that syft
found in the binary. `checksums.txt` lists it, so the signature covers it too.
`go version -m airbag` prints the same list from the binary itself, with the
commit it was built from (`vcs.revision`).

## Rebuild it from source

The binaries are reproducible. They are built with `-trimpath`, without cgo,
from a clean checkout of the tag, so the same Go gives the same bytes. The
same Go is the version `go.mod` names, which `go version -m` prints for the
release binary:

```console
$ tar -xzf $file airbag
$ go version -m airbag | head -n 1
airbag: go1.27.1
$ git clone --branch $tag https://github.com/getjump/airbag airbag-src
$ cd airbag-src
$ GOTOOLCHAIN=go1.27.1 CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w -X main.version=$tag" -o ../airbag.rebuilt ./cmd/airbag
$ cd .. && sha256sum airbag airbag.rebuilt
```

The two hashes match. Build in a git checkout with no untracked files, not
in an unpacked source archive, because Go stamps the commit, and whether the
tree was modified, into the binary.

The archives are reproducible too, since every file in them gets the
commit's time. In the checkout, the GoReleaser version that `release.yml`
pins writes the same archives to `dist/`:

```console
$ goreleaser release --snapshot --clean --skip=sign,sbom
$ grep '\.tar\.gz$' dist/checksums.txt
```

Compare those lines with the release's `checksums.txt`.

## `go install` and Nix

`go install github.com/getjump/airbag/cmd/airbag@v0.1.0` builds from the
module proxy, and the Go checksum database guarantees that everyone gets the
same source for v0.1.0 (see [go.dev/ref/mod](https://go.dev/ref/mod#authenticating)).
`nix run github:getjump/airbag/v0.1.0` builds from the tag with the
dependencies that `vendorHash` in `flake.nix` pins.
