#!/bin/sh
# Package managers inside the sandbox go through http://airbag.mirror:
# every package and version lands in the effect log, artifacts are
# cached across sessions, and a session that read a secret gets only
# what is cached. Parts whose tool is missing are skipped.
set -eu
AIRBAG=${AIRBAG:-airbag}
T=$(mktemp -d "$HOME/.airbag-mirror-e2e.XXXXXX")
trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*"; exit 1; }

mkdir "$T/proj" && cd "$T/proj"
git init -q -b main && git config user.email e2e@example.com && git config user.name e2e
echo hi > README.md && git add -A && git commit -qm init

want=""
script=""
if command -v go >/dev/null; then
	script="$script mkdir gm && cd gm && go mod init example.com/x >/dev/null 2>&1 && GOTOOLCHAIN=local GOFLAGS=-modcacherw GOMODCACHE=\$PWD/.modcache go get golang.org/x/text@v0.14.0 >/dev/null 2>&1 || echo 'LEAK: go get failed'; cd ..;"
	want="$want|go golang.org/x/text@v0.14.0"
fi
if command -v npm >/dev/null; then
	script="$script npm pack --silent left-pad@1.3.0 >/dev/null 2>&1 || echo 'LEAK: npm pack failed';"
	want="$want|npm left-pad left-pad-1.3.0.tgz"
fi
if python3 -m pip --version >/dev/null 2>&1; then
	script="$script python3 -m pip download -q --no-deps six==1.16.0 -d dl >/dev/null 2>&1 || echo 'LEAK: pip download failed';"
	want="$want|pypi six-1.16.0"
fi
[ -n "$script" ] || { echo "SKIP: no go, npm or pip"; exit 0; }

out=$("$AIRBAG" run -- sh -c "$script" 2>&1)
echo "$out" | grep -q LEAK && fail "$out"
rev=$("$AIRBAG" review)
echo "$want" | tr '|' '\n' | while read -r w; do
	[ -z "$w" ] && continue
	echo "$rev" | grep -qF "$w" || fail "review lacks '$w': $rev"
done
"$AIRBAG" log | grep -q 'net.egress.*proxy.golang.org\|net.egress.*registry.npmjs.org' && fail "a package manager bypassed the mirror"
"$AIRBAG" discard --yes >/dev/null

# Second session: the same artifacts come from the cache, also after
# the session read a secret; anything new is refused then, and the
# registries themselves are reachable only through the mirror. Reading
# the secret needs FUSE (without it the file is hidden and nothing taints).
if [ ! -w /dev/fuse ]; then
	echo "SKIP: tainted part (/dev/fuse not writable)"
	echo PASS
	exit 0
fi
printf 'API_TOKEN=sk-mirror-0123456789\n' > .env
out=$("$AIRBAG" run -- sh -c "cat .env >/dev/null; $script
	curl -s -o /dev/null --max-time 5 https://registry.npmjs.org/left-pad; true" 2>&1)
echo "$out" | grep -q LEAK && fail "cached packages not served after taint: $out"
log=$("$AIRBAG" log)
echo "$log" | grep 'pkg.fetch' | grep -v 'cached' | grep -qv 'secret-taint' && fail "artifacts fetched again: $(echo "$log" | grep pkg.fetch)"
echo "$log" | grep -q 'registry.npmjs.org:443.*registry: use the mirror' || fail "direct registry access not refused: $log"
"$AIRBAG" discard --yes >/dev/null
if command -v npm >/dev/null; then
	"$AIRBAG" run -- sh -c "cat .env >/dev/null; npm pack --silent is-number@7.0.0 >/dev/null 2>&1 && echo LEAK; true" >"$T/out" 2>&1
	grep -q LEAK "$T/out" && fail "a tainted session fetched a new package"
	"$AIRBAG" log | grep 'pkg.fetch' | grep -q 'deny.*secret-taint' || fail "refused fetch not logged: $("$AIRBAG" log)"
	"$AIRBAG" discard --yes >/dev/null

	# What the real workspace's lock file pins still installs after the
	# secret read. A fresh mirror cache makes it a real fetch.
	mkdir pinned && cat > pinned/package.json <<'EOJ'
{"name":"pinned","version":"1.0.0","dependencies":{"is-plain-obj":"4.1.0"}}
EOJ
	cat > pinned/package-lock.json <<'EOJ'
{"name":"pinned","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{
 "":{"name":"pinned","version":"1.0.0","dependencies":{"is-plain-obj":"4.1.0"}},
 "node_modules/is-plain-obj":{"version":"4.1.0",
  "resolved":"https://registry.npmjs.org/is-plain-obj/-/is-plain-obj-4.1.0.tgz",
  "integrity":"sha512-+Pgi+vMuUNkJyExiMBt5IlFoMyKnr5zhJ4Uspz58WOhBF5QoIZkFyNHIbBAtHwzVAgk5RtndVNsDRN61/mmDqg=="}}}
EOJ
	fresh=$(mktemp -d /var/tmp/airbag-pins.XXXXXX)
	AIRBAG_HOME=$fresh "$AIRBAG" run -- sh -c "cat .env >/dev/null; cd pinned && npm ci --no-audit --no-fund >/dev/null 2>&1 && echo INSTALLED; true" >"$T/out" 2>&1
	grep -q INSTALLED "$T/out" || fail "a lock-pinned package did not install after the secret read: $(cat "$T/out")"
	AIRBAG_HOME=$fresh "$AIRBAG" log | grep -q 'pkg.fetch.*is-plain-obj.*pinned by pinned/package-lock.json' || fail "pinned fetch not logged: $(AIRBAG_HOME=$fresh "$AIRBAG" log | grep pkg)"
	AIRBAG_HOME=$fresh "$AIRBAG" discard --yes >/dev/null
	rm -rf "$fresh"
fi
echo PASS
