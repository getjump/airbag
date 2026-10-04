package mirror

import (
	"bufio"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Pins are the artifact URLs the workspace's lock files name, read from
// the real workspace before the agent starts. A session that read a
// secret may still fetch these: the URL of each was fixed before the
// session, so the request carries nothing the session learned, and the
// package managers check the lock file's hash on what arrives (npm's
// integrity, go.sum, uv's hashes). The agent's own edits to lock files
// are in its branch and do not change the set.
//
// Read: package-lock.json and npm-shrinkwrap.json (v1 to v3), yarn.lock
// (v1), go.sum, uv.lock. Not yet: pnpm-lock.yaml, poetry.lock and
// requirements files with hashes (they name files, not URLs).
type Pins map[string]string // upstream URL -> the lock file that names it

func (p Pins) Has(url string) (string, bool) {
	f, ok := p[url]
	return f, ok
}

// FindPins walks the workspace for lock files.
func FindPins(workspace string) Pins {
	pins := Pins{}
	_ = filepath.WalkDir(workspace, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable entry pins nothing, and fewer pins only make the mirror stricter
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", ".venv", "venv", "target", "dist", "build":
				if path != workspace {
					return filepath.SkipDir
				}
			}
			return nil
		}
		rel, _ := filepath.Rel(workspace, path)
		switch d.Name() {
		case "package-lock.json", "npm-shrinkwrap.json":
			npmLock(path, rel, pins)
		case "yarn.lock":
			yarnLock(path, rel, pins)
		case "go.sum":
			goSum(path, rel, pins)
		case "uv.lock":
			uvLock(path, rel, pins)
		}
		return nil
	})
	return pins
}

// npmURL normalizes a tarball URL to the form the mirror fetches.
func npmURL(u string) string {
	u = strings.Replace(u, "https://registry.yarnpkg.com/", "https://registry.npmjs.org/", 1)
	if i := strings.IndexAny(u, "#?"); i >= 0 {
		u = u[:i]
	}
	return strings.ReplaceAll(u, "%2f", "/")
}

func npmLock(path, rel string, pins Pins) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var lock struct {
		Packages     map[string]struct{ Resolved string } `json:"packages"`
		Dependencies map[string]json.RawMessage           `json:"dependencies"`
	}
	if json.Unmarshal(b, &lock) != nil {
		return
	}
	for _, p := range lock.Packages {
		if strings.HasPrefix(p.Resolved, "https://registry.npmjs.org/") {
			pins[npmURL(p.Resolved)] = rel
		}
	}
	// v1: nested dependencies.
	var walk func(map[string]json.RawMessage)
	walk = func(deps map[string]json.RawMessage) {
		for _, raw := range deps {
			var d struct {
				Resolved     string                     `json:"resolved"`
				Dependencies map[string]json.RawMessage `json:"dependencies"`
			}
			if json.Unmarshal(raw, &d) != nil {
				continue
			}
			if strings.HasPrefix(d.Resolved, "https://registry.npmjs.org/") {
				pins[npmURL(d.Resolved)] = rel
			}
			walk(d.Dependencies)
		}
	}
	walk(lock.Dependencies)
}

var yarnResolved = regexp.MustCompile(`^\s+resolved "(https://registry\.(?:yarnpkg\.com|npmjs\.org)/[^"]+)"`)

func yarnLock(path, rel string, pins Pins) {
	eachLine(path, func(l string) {
		if m := yarnResolved.FindStringSubmatch(l); m != nil {
			pins[npmURL(m[1])] = rel
		}
	})
}

// goSum pins the .zip, .mod and .info of every module version; the
// go command checks the h1: hashes itself.
func goSum(path, rel string, pins Pins) {
	eachLine(path, func(l string) {
		f := strings.Fields(l)
		if len(f) != 3 || !strings.HasPrefix(f[2], "h1:") {
			return
		}
		mod, ver := escapeGo(f[0]), f[1]
		base := "https://proxy.golang.org/" + mod + "/@v/"
		if v, ok := strings.CutSuffix(ver, "/go.mod"); ok {
			pins[base+v+".mod"] = rel
			pins[base+v+".info"] = rel
			return
		}
		pins[base+ver+".zip"] = rel
		pins[base+ver+".info"] = rel
	})
}

// escapeGo applies the module proxy's case escaping (A -> !a).
func escapeGo(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + 'a' - 'A')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

var uvURL = regexp.MustCompile(`url = "(https://files\.pythonhosted\.org/[^"]+)"`)

func uvLock(path, rel string, pins Pins) {
	eachLine(path, func(l string) {
		for _, m := range uvURL.FindAllStringSubmatch(l, -1) {
			pins[m[1]] = rel
		}
	})
}

func eachLine(path string, f func(string)) {
	fh, err := os.Open(path)
	if err != nil {
		return
	}
	defer func() { _ = fh.Close() }() // read only
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		f(sc.Text())
	}
}
