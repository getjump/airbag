package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/getjump/airbag/internal/secretfs"
	"github.com/getjump/airbag/proxy/simulate"
)

// decodeStubs reads the simulate: entries of a policy file. They are
// decoded strictly, apart from the rest of the file: a misspelled field
// (bodyfile:) would otherwise leave a stub that answers something the
// user did not write.
func decodeStubs(b []byte) ([]simulate.Stub, error) {
	var raw struct {
		Simulate yaml.Node `yaml:"simulate"`
	}
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	if raw.Simulate.Kind == 0 {
		return nil, nil
	}
	out, err := yaml.Marshal(&raw.Simulate)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(out))
	dec.KnownFields(true)
	var stubs []simulate.Stub
	if err := dec.Decode(&stubs); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return stubs, nil
}

// AddSimulation adds the stubs of a file given with --simulate, which
// holds only simulate:. They are tried before those of the user's own
// file. The user names the file on the host, so it is trusted as that
// file is, and the agent, which writes only to its branch, cannot change
// it; its body files are read now, from its directory.
func (p *Policy) AddSimulation(path, home string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var f struct {
		Simulate []simulate.Stub `yaml:"simulate"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s: %w (a --simulate file holds only simulate:)", path, err)
	}
	if len(f.Simulate) == 0 {
		return fmt.Errorf("%s: simulate names no stubs", path)
	}
	if err := p.addStubs(path, f.Simulate, home, true); err != nil {
		return err
	}
	p.Sources = append(p.Sources, path)
	return nil
}

// addStubs reads the body files of stubs from src, names the unnamed
// ones after src and their place in it, and compiles every stub so far:
// any problem fails the load.
func (p *Policy) addStubs(src string, stubs []simulate.Stub, home string, first bool) error {
	if len(stubs) == 0 {
		return nil
	}
	resolved := make([]simulate.Stub, 0, len(stubs))
	for i, st := range stubs {
		if st.Name == "" {
			st.Name = defaultName(src, i)
		}
		if st.Respond.BodyFile != "" {
			if st.Respond.Body != "" {
				return fmt.Errorf("%s: simulate: stub %s: body and body_file: one or the other", src, st.Name)
			}
			b, err := stubBody(src, st.Respond.BodyFile, home)
			if err != nil {
				return fmt.Errorf("%s: simulate: stub %s: %w", src, st.Name, err)
			}
			st.Respond.Body, st.Respond.BodyFile = string(b), ""
		}
		resolved = append(resolved, st)
	}
	var all []simulate.Stub
	if first {
		all = append(append(all, resolved...), p.Stubs...)
	} else {
		all = append(append(all, p.Stubs...), resolved...)
	}
	set, err := simulate.Compile(all)
	if err != nil {
		return fmt.Errorf("%s: simulate: %w", src, err)
	}
	p.Stubs, p.Simulation = all, set
	return nil
}

// defaultName is "FILE#N", as for an unnamed rule, in the characters a
// stub's name may hold.
func defaultName(src string, i int) string {
	base := []byte(filepath.Base(src))
	for j, c := range base {
		if c <= ' ' || c > '~' {
			base[j] = '_'
		}
	}
	if len(base) > 48 {
		base = base[:48]
	}
	return string(base) + "#" + strconv.Itoa(i+1)
}

// stubBody reads a stub's body_file, named relative to the directory of
// src, the file that names it. A stub serves the agent what the file
// holds, so the file must stay inside that directory (os.Root: no ..,
// no absolute path, no link out of it), be a regular file and not a
// secret file by name: a stub must not hand the agent a .env that FUSE
// would have watched, or a key from elsewhere on the machine. It is
// read once, here, on the host.
func stubBody(src, name, home string) ([]byte, error) {
	dir := filepath.Dir(src)
	if filepath.IsAbs(name) || strings.HasPrefix(name, "~") {
		return nil, fmt.Errorf("body_file %q: name a file relative to %s, the directory of the file that names it", name, dir)
	}
	if home != "" && sameDir(dir, home) {
		return nil, fmt.Errorf("body_file %q: %s is your home directory, and everything in it would be in reach; keep stub files in a directory of their own", name, dir)
	}
	if secretfs.IsSecret(strings.ToLower(filepath.Base(name))) {
		return nil, fmt.Errorf("body_file %q is a secret file; a stub does not serve one to the agent", name)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	fi, err := root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("body_file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("body_file %q is not a regular file (a link is not followed)", name)
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("body_file: %w", err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, simulate.MaxBody+1))
	if err != nil {
		return nil, fmt.Errorf("body_file %q: %w", name, err)
	}
	if len(b) > simulate.MaxBody {
		return nil, fmt.Errorf("body_file %q is larger than %d bytes", name, simulate.MaxBody)
	}
	return b, nil
}

func sameDir(a, b string) bool {
	ra, err1 := filepath.EvalSymlinks(a)
	rb, err2 := filepath.EvalSymlinks(b)
	if err1 != nil || err2 != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return ra == rb
}
