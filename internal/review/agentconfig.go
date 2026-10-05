package review

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"github.com/getjump/airbag/internal/session"
)

// Agents keep some state in a JSON file in $HOME that they rewrite every
// run: ~/.claude.json holds counters, a machine id and migration markers
// next to things that steer later runs (MCP servers, tool permissions,
// per-project trust). The whole file goes through the branch, so none of
// it reaches the real file until review — but that would raise a
// persistence alarm on every single session over counters the user does
// not care about.
//
// jsonConfigs resolves that without any agent-specific logic in the code
// path. Each entry names a file and lists key PATHS in two classes:
//
//   - writeBack: benign keys the CLI rewrites on its own every run. A
//     change confined to them is copied to the real file at session end
//     and then drops out of review.
//   - persist: keys that start commands or change trust. A change to one
//     stays in the branch and is flagged "persist".
//
// Any other changed key is unknown: it stays in the branch and review
// lists it by name. A path is dot-separated top-level keys, and one
// segment may be "*", which matches any key at that level, so
// "projects.*.lastCost" covers every project's entry. A key whose
// sub-keys are listed (projects) is compared sub-key by sub-key; a key
// with no listed sub-keys is compared whole. The agent name appears only
// here, as data, like the persist tables.
//
// writeBack is an ALLOWLIST, built from what Claude Code 2.1.x was
// observed to write on its own, in a non-interactive run and in
// interactive runs driven through a pseudo-terminal: an unknown key is
// not on it, so it costs a review entry, never a silent write.
type jsonConfig struct {
	path      string   // relative to $HOME
	writeBack []string // benign key paths copied back to the real file
	persist   []string // key paths that run code or change trust
}

var jsonConfigs = []jsonConfig{
	{
		path: ".claude.json",
		writeBack: []string{
			// Written by a non-interactive `claude -p` run on its own.
			"firstStartTime", "firstStartVersion", "machineID", "userID",
			"migrationVersion", "opusProMigrationComplete", "sonnet1m45MigrationComplete",
			"seenNotifications", "hasResetAutoModeOptInForDefaultOffer", "pluginUsage",
			// Written by interactive sessions: startup, onboarding and tip
			// counters, and markers of what was already shown.
			"numStartups", "hasCompletedOnboarding", "lastOnboardingVersion",
			"tipsHistory", "tipLifetimeShownCounts", "tipsHistoryByCommand",
			"lastReleaseNotesSeen", "lastClawdEntranceVersion",
			// Per-project counters an interactive session rewrites on exit.
			"projects.*.lastSessionId", "projects.*.lastStartTime", "projects.*.lastVersionBase",
			"projects.*.lastGracefulShutdown", "projects.*.lastCost", "projects.*.lastDuration",
			"projects.*.lastAPIDuration", "projects.*.lastAPIDurationWithoutRetries",
			"projects.*.lastToolDuration", "projects.*.lastFpsAverage", "projects.*.lastFpsLow1Pct",
			"projects.*.lastLinesAdded", "projects.*.lastLinesRemoved",
			"projects.*.lastTotalInputTokens", "projects.*.lastTotalOutputTokens",
			"projects.*.lastTotalCacheCreationInputTokens", "projects.*.lastTotalCacheReadInputTokens",
			"projects.*.lastTotalWebSearchRequests", "projects.*.lastModelUsage",
			"projects.*.lastSessionMetrics",
		},
		persist: []string{
			"mcpServers", "enabledMcpjsonServers", "disabledMcpjsonServers", "mcpContextUris",
			"permissions", "allowedTools", "hooks", "env", "apiKeyHelper",
			// Answers to "use this API key from the environment?", and the
			// account a login inside the session recorded: which account
			// (and organization, whose managed settings later sessions
			// fetch) the host's next session uses.
			"customApiKeyResponses", "oauthAccount",
			// Per project: tool permissions, MCP servers, folder trust, and
			// approval of CLAUDE.md imports from outside the project.
			"projects.*.allowedTools", "projects.*.mcpServers", "projects.*.mcpContextUris",
			"projects.*.enabledMcpjsonServers", "projects.*.disabledMcpjsonServers",
			"projects.*.hasTrustDialogAccepted", "projects.*.hasClaudeMdExternalIncludesApproved",
		},
	},
}

func configFor(rel string) *jsonConfig {
	for i := range jsonConfigs {
		if jsonConfigs[i].path == rel {
			return &jsonConfigs[i]
		}
	}
	return nil
}

type keyClass int

const (
	classUnknown keyClass = iota
	classWriteBack
	classPersist
)

// keyChange is one changed key path, at the depth the table describes.
type keyChange struct {
	path  []string // concrete keys from the top level down
	class keyClass
}

// String renders a path for review: keys that are plain identifiers
// joined with dots, any other key in brackets, since project keys are
// paths (projects[/home/me/api].allowedTools). Names only, never values.
func (k keyChange) String() string {
	if len(k.path) == 0 {
		return "(whole file)"
	}
	var b strings.Builder
	for i, seg := range k.path {
		switch {
		case i == 0:
			b.WriteString(seg)
		case plainKey(seg):
			b.WriteString("." + seg)
		default:
			b.WriteString("[" + seg + "]")
		}
	}
	return b.String()
}

func plainKey(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r == '_' || r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}

func patternMatch(pat []string, path []string) bool {
	if len(pat) != len(path) {
		return false
	}
	for i := range pat {
		if pat[i] != "*" && pat[i] != path[i] {
			return false
		}
	}
	return true
}

// class returns the class of an exact path, and whether the table lists
// any path below it (so it is compared key by key).
func (cf *jsonConfig) class(path []string) (c keyClass, listed, below bool) {
	for _, set := range []struct {
		pats []string
		c    keyClass
	}{{cf.writeBack, classWriteBack}, {cf.persist, classPersist}} {
		for _, p := range set.pats {
			pat := strings.Split(p, ".")
			if patternMatch(pat, path) {
				c, listed = set.c, true
			}
			if len(pat) > len(path) && patternMatch(pat[:len(path)], path) {
				below = true
			}
		}
	}
	return c, listed, below
}

// diff lists the changed key paths between a (the real file) and b (the
// branch), at the depth the table describes: a listed path is one change,
// a path with listed sub-paths is compared key by key, anything else is
// one unknown change.
func (cf *jsonConfig) diff(prefix []string, a, b json.RawMessage) []keyChange {
	if canon(a) == canon(b) {
		return nil
	}
	c, listed, below := cf.class(prefix)
	if listed {
		return []keyChange{{prefix, c}}
	}
	if len(prefix) == 0 || below {
		am, aok := object(a)
		bm, bok := object(b)
		if aok && bok {
			var out []keyChange
			for _, k := range unionKeys(am, bm) {
				out = append(out, cf.diff(append(slices.Clip(prefix), k), am[k], bm[k])...)
			}
			return out
		}
	}
	return []keyChange{{prefix, classUnknown}}
}

// WriteBackConfigs copies the agent's changes to writeBack paths of each
// jsonConfig to the real file, atomically, at session end. It runs only
// when $HOME was branched (otherwise there is no branch copy to read, and
// nothing reached the real file to begin with). Any other change is left
// in the branch for review; a malformed or non-regular file on either
// side is left untouched. It returns one human-readable line per file it
// wrote, for the caller to print. It never changes a key the agent did
// not, never writes a deletion back (a removed key stays in the branch
// for review), and re-reads the real file so a concurrent host edit to a
// different key is kept. What it wrote is recorded in s.WroteBack, so
// apply's conflict check knows the write was airbag's; when the host had
// also edited the file during the session, nothing is recorded and apply
// reports the conflict as before.
func WriteBackConfigs(s *session.Session) []string {
	if !s.OverHome {
		return nil // no branch of $HOME: the real file was never shadowed
	}
	since := s.Created
	if !s.Baseline.IsZero() {
		since = s.Baseline
	}
	var msgs []string
	saved := false
	for i := range jsonConfigs {
		msg, changed := writeBack(s, &jsonConfigs[i], since)
		if msg != "" {
			msgs = append(msgs, msg)
		}
		saved = saved || changed
	}
	if saved {
		if err := s.Save(); err != nil {
			msgs = append(msgs, fmt.Sprintf("could not record the write-back: %v", err))
		}
	}
	return msgs
}

// SnapshotConfigs records, before a run, what each jsonConfig file holds
// in the real $HOME, as the base of WriteBackConfigs' three-way merge:
// only a key the agent changed from the base is written back, so a key
// the host changed meanwhile keeps the host's value. The base is taken
// while the branch has no copy of the file yet (an overlay copies it up
// on the agent's first write), and kept while it has one.
func SnapshotConfigs(s *session.Session) {
	if !s.OverHome {
		return
	}
	for i := range jsonConfigs {
		cf := &jsonConfigs[i]
		if _, err := os.Lstat(filepath.Join(s.HomeUpper(), cf.path)); err == nil {
			continue // the branch has its copy; its base stays
		}
		base := basePath(s, cf)
		raw, err := readRegular(filepath.Join(s.Home, cf.path))
		absent := errors.Is(err, fs.ErrNotExist)
		if err != nil && !absent {
			_ = os.Remove(base) // not a readable regular file: no base, a two-way merge
			_ = os.Remove(base + absentSuffix)
			continue
		}
		// No real file yet: every key the agent writes is its own, and
		// a marker beside the (empty) base records the absence.
		if err := os.MkdirAll(filepath.Dir(base), 0o700); err == nil && os.WriteFile(base, raw, 0o600) == nil {
			if absent {
				_ = os.WriteFile(base+absentSuffix, nil, 0o600)
			} else {
				_ = os.Remove(base + absentSuffix)
			}
		}
	}
}

// RemovedOnHost reports whether path is an agent config that existed
// when the session's last run began and is gone from the real $HOME
// now: the host removed it, so the branch copy is not a new file.
func RemovedOnHost(s *session.Session, path string) bool {
	for i := range jsonConfigs {
		cf := &jsonConfigs[i]
		if filepath.Join(s.Home, cf.path) != path {
			continue
		}
		if _, err := readRegular(basePath(s, cf)); err != nil || absentAtStart(s, cf) {
			return false
		}
		_, err := os.Lstat(path)
		return errors.Is(err, fs.ErrNotExist)
	}
	return false
}

// absentSuffix names the marker beside a base whose real file did not
// exist when the run began (an existing file may be empty too).
const absentSuffix = ".absent"

func absentAtStart(s *session.Session, cf *jsonConfig) bool {
	_, err := os.Lstat(basePath(s, cf) + absentSuffix)
	return err == nil
}

func basePath(s *session.Session, cf *jsonConfig) string {
	return filepath.Join(s.Dir, "base", cf.path)
}

// errChanged: the real file changed between reading it and replacing it.
var errChanged = errors.New("changed while being written back")

// writeBack does WriteBackConfigs for one file. It reads the real file,
// merges the benign keys in, and replaces it only if the file is still
// as read (inode, size, change time); otherwise it starts over, a few
// times, so a concurrent host write is never lost. changed reports that
// s.WroteBack changed.
func writeBack(s *session.Session, cf *jsonConfig, since time.Time) (msg string, changed bool) {
	branchPath := filepath.Join(s.HomeUpper(), cf.path)
	branchRaw, err := readRegular(branchPath)
	if err != nil {
		return "", false // not changed, or not a regular file the agent could point elsewhere
	}
	branch, err := topLevel(branchRaw)
	if err != nil {
		return "", false // malformed in the branch: leave it there for review
	}
	realPath := filepath.Join(s.Home, cf.path)
	// The base: what the real file held when the branch took its copy.
	// A session from before bases were kept has none; the real file
	// stands in, as a two-way merge.
	baseRaw, err := readRegular(basePath(s, cf))
	haveBase := err == nil
	absent := haveBase && absentAtStart(s, cf) // the real file did not exist when the run began
	if haveBase && len(baseRaw) == 0 {
		baseRaw = []byte("{}") // absent, or an empty file
	}
	if haveBase {
		if _, err := topLevel(baseRaw); err != nil {
			return "", false
		}
	}
	// saveBase keeps base as the merge base of later runs.
	saveBase := func(base map[string]json.RawMessage) {
		out, err := marshalJSON(base, "  ")
		if err != nil || os.MkdirAll(filepath.Dir(basePath(s, cf)), 0o700) != nil {
			return
		}
		out = append(out, '\n')
		if os.WriteFile(basePath(s, cf), out, 0o600) == nil {
			_ = os.Remove(basePath(s, cf) + absentSuffix) // the real file exists by now
			baseRaw, haveBase, absent = out, true, false
		}
	}
	for range 3 {
		before, exists, err := fileState(realPath)
		if err != nil {
			return "", false // a symlink or other non-regular file: leave it alone
		}
		if !exists && haveBase && !absent {
			// The file was there when the run began (its base is not
			// empty): the host removed it since. That is a host edit;
			// write nothing back, and the branch copy waits for review
			// (apply reports the removal, RemovedOnHost).
			return "", false
		}
		realRaw := []byte("{}")
		real := map[string]json.RawMessage{}
		if exists {
			if realRaw, err = readRegular(realPath); err != nil {
				return "", false
			}
			if real, err = topLevel(realRaw); err != nil {
				return "", false // malformed real file: never corrupt it
			}
		}
		// The host edited the real file during the session if it changed
		// after the session began and is not exactly what airbag wrote
		// back in an earlier run of this session.
		prev, had := s.WroteBack[realPath]
		hostEdited := exists && before.ctime > since.UnixNano() &&
			!(had && prev.SHA256 == digest(realRaw) && prev.Ctime == before.ctime)
		// The base is parsed afresh on every attempt, and never shares
		// its maps with real: it takes a written value only once the
		// write has landed.
		base, _ := topLevel(realRaw)
		if haveBase {
			base, _ = topLevel(baseRaw)
		}
		type kv struct {
			path []string
			v    json.RawMessage
		}
		var wrote []string
		var written []kv
		rebased := false
		for _, ch := range cf.diff(nil, realRaw, branchRaw) {
			if ch.class != classWriteBack {
				continue
			}
			v, ok := getPath(branch, ch.path)
			bv, inBase := getPath(base, ch.path)
			if !ok {
				// Missing from the branch: the agent removed it (a change
				// for review, never written back), or the host added it
				// during the run, which the branch copy takes.
				if rv, inReal := getPath(real, ch.path); !inBase && inReal && setPath(branch, ch.path, rv) == nil {
					_ = setPath(base, ch.path, rv)
					rebased = true
				}
				continue
			}
			if canon(v) == canon(bv) {
				// The agent did not change it; the host did. The host's
				// value, or its removal, stays, and the branch copy and
				// the base take it, so review shows only what the agent
				// changed, now and in a later run.
				if rv, ok := getPath(real, ch.path); !ok {
					deletePath(branch, ch.path)
					deletePath(base, ch.path)
					rebased = true
				} else if setPath(branch, ch.path, rv) == nil {
					_ = setPath(base, ch.path, rv)
					rebased = true
				}
				continue
			}
			if rv, _ := getPath(real, ch.path); canon(rv) != canon(bv) {
				continue // both changed it: the agent's value waits for review
			}
			if err := setPath(real, ch.path, v); err == nil {
				wrote = append(wrote, ch.String())
				written = append(written, kv{ch.path, v})
			}
		}
		if rebased {
			if out, err := marshalJSON(branch, "  "); err == nil {
				out = append(out, '\n')
				if err := writeAtomic(branchPath, out, func() bool { return true }); err == nil {
					branchRaw = out
					saveBase(base)
				}
			}
		}
		if len(wrote) == 0 {
			dropIfSame(cf, realPath, branchPath, branchRaw)
			return "", false
		}
		out, err := marshalJSON(real, "  ")
		if err != nil {
			return fmt.Sprintf("could not write ~/%s back: %v", cf.path, err), false
		}
		out = append(out, '\n')
		installed, err := replaceIf(realPath, out, realRaw, exists, filepath.Join(s.Dir, "displaced"), func() bool {
			now, nowExists, err := fileState(realPath)
			return err == nil && nowExists == exists && now == before
		})
		if errors.Is(err, errChanged) {
			continue
		}
		if errors.Is(err, errNoAtomic) {
			return fmt.Sprintf("~/%s not written back (%v); its changes stay in the branch", cf.path, err), false
		}
		if err != nil {
			return fmt.Sprintf("could not write ~/%s back: %v", cf.path, err), false
		}
		// The base now holds what was written back, so a later run does
		// not take it for the agent's change again.
		for _, w := range written {
			_ = setPath(base, w.path, w.v)
		}
		saveBase(base)
		// Record the write: the bytes airbag wrote and the change time
		// right after, unless the host had edited the file too, or wrote
		// it again just now.
		if s.WroteBack == nil {
			s.WroteBack = map[string]session.WriteStamp{}
		}
		// The record is airbag's bytes with the change time the file had
		// as it took its place: any later change, a host chmod or xattr
		// included, moves the change time, and apply sees a conflict.
		beforeStamp()
		if !hostEdited && installed != 0 {
			s.WroteBack[realPath] = session.WriteStamp{SHA256: digest(out), Ctime: installed}
		} else {
			delete(s.WroteBack, realPath)
		}
		dropIfSame(cf, realPath, branchPath, branchRaw)
		sort.Strings(wrote)
		return fmt.Sprintf("~/%s: wrote back %d benign key(s): %s", cf.path, len(wrote), strings.Join(wrote, ", ")), true
	}
	return fmt.Sprintf("~/%s kept changing on the host; its changes stay in the branch", cf.path), false
}

// dropIfSame removes the branch copy when it now matches the real file:
// only benign keys differed, so review shows nothing for this file.
func dropIfSame(cf *jsonConfig, realPath, branchPath string, branchRaw []byte) {
	after, err := readRegular(realPath)
	if err != nil || len(cf.diff(nil, after, branchRaw)) != 0 {
		return
	}
	// The same keys with another mode is still a change for review.
	ri, rerr := os.Lstat(realPath)
	bi, berr := os.Lstat(branchPath)
	if rerr == nil && berr == nil && ri.Mode().Perm() == bi.Mode().Perm() {
		_ = os.Remove(branchPath)
	}
}

// state identifies a version of a file for a compare-and-replace.
type state struct {
	ino   uint64
	size  int64
	ctime int64
}

// fileState returns the state of a regular file; exists is false when
// there is none. Anything else (a symlink, a directory) is an error.
func fileState(path string) (st state, exists bool, err error) {
	var s unix.Stat_t
	if err := unix.Lstat(path, &s); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return state{}, false, nil
		}
		return state{}, false, err
	}
	if s.Mode&unix.S_IFMT != unix.S_IFREG {
		return state{}, false, errNotRegular
	}
	return state{ino: uint64(s.Ino), size: s.Size, ctime: s.Ctim.Nano()}, true, nil //nolint:unconvert // Ino is uint32 on some platforms
}

// digest is the hex SHA-256 of b, as recorded in session.WroteBack.
func digest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// stamp reads a regular file's content digest and change time.
func stamp(path string) (session.WriteStamp, bool) {
	b, err := readRegular(path)
	if err != nil {
		return session.WriteStamp{}, false
	}
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return session.WriteStamp{}, false
	}
	return session.WriteStamp{SHA256: digest(b), Ctime: st.Ctim.Nano()}, true
}

// OwnWrite reports whether the file at path is exactly as
// WriteBackConfigs left it in this session: the same content and the
// same change time, so no host edit since, a chmod included. Its newer
// change time is then airbag's and not a host edit.
// RecordOwnWrite records an agent config apply has just written as
// airbag's own write, so a later run of the session does not take it
// for a host edit.
func RecordOwnWrite(s *session.Session, path string) {
	for i := range jsonConfigs {
		if filepath.Join(s.Home, jsonConfigs[i].path) != path {
			continue
		}
		if st, ok := stamp(path); ok {
			if s.WroteBack == nil {
				s.WroteBack = map[string]session.WriteStamp{}
			}
			s.WroteBack[path] = st
		}
	}
}

func OwnWrite(s *session.Session, path string) bool {
	want, ok := s.WroteBack[path]
	if !ok {
		return false
	}
	got, ok := stamp(path)
	return ok && got == want
}

// configChanges lists a config file's changed key paths for review (names
// only, never values). ok is false when the change is not a config file;
// readable is false when either side is not a readable regular JSON file.
func configChanges(c Change) (changes []keyChange, readable, ok bool) {
	if c.Layer != "home" || c.IsDir() {
		return nil, false, false
	}
	cf := configFor(filepath.ToSlash(c.Rel))
	if cf == nil {
		return nil, false, false
	}
	branchRaw, err := readRegular(c.Upper)
	if err != nil {
		return nil, false, true
	}
	if _, err := topLevel(branchRaw); err != nil {
		return nil, false, true
	}
	realRaw, err := readRegular(c.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		realRaw = []byte("{}")
	case err != nil:
		return nil, false, true
	}
	return cf.diff(nil, realRaw, branchRaw), true, true
}

// configKeyChange is configChanges as names, and whether any is persist.
func configKeyChange(c Change) (keys []string, persist bool, ok bool) {
	changes, _, ok := configChanges(c)
	for _, ch := range changes {
		keys = append(keys, ch.String())
		if ch.class == classPersist {
			persist = true
		}
	}
	return keys, persist, ok
}

// configFlags are review's flags for a config file change, one per
// class, each naming its keys: "persist" and "persist key(s): …" for keys
// that run code or change trust, "unknown key(s): …" for keys the table
// does not list (shown plainly, not as persistence), and "benign key(s):
// …" for listed benign keys that were not written back (removed by the
// agent, or the real file could not be written). nil when c is not a
// config file.
func configFlags(c Change) []string {
	changes, readable, ok := configChanges(c)
	if !ok {
		return nil
	}
	if !readable {
		// Nothing can be told about its keys, so it counts as the worst.
		return []string{"persist", "not a readable regular JSON file"}
	}
	byClass := map[keyClass][]string{}
	for _, ch := range changes {
		byClass[ch.class] = append(byClass[ch.class], ch.String())
	}
	var out []string
	if k := byClass[classPersist]; len(k) > 0 {
		out = append(out, "persist", "persist key(s): "+strings.Join(k, ", "))
	}
	if k := byClass[classUnknown]; len(k) > 0 {
		out = append(out, "unknown key(s): "+strings.Join(k, ", "))
	}
	if k := byClass[classWriteBack]; len(k) > 0 {
		out = append(out, "benign key(s): "+strings.Join(k, ", "))
	}
	return out
}

// topLevel parses a config file, which must be a JSON object: null or
// any other value is malformed, so it stays in the branch for review. So
// is text Go's decoder would change while reading: invalid UTF-8, and
// escaped UTF-16 surrogates, which it turns into U+FFFD, so two keys the
// agent's CLI tells apart could compare equal here.
func topLevel(b []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(b) || surrogateEscape(b) {
		return nil, errNotText
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m == nil {
		return nil, errNotObject
	}
	return m, nil
}

// errNotRegular: the path is a symlink, a whiteout or another
// non-regular file.
var errNotRegular = errors.New("not a regular file")

// errNotText: a config file holds bytes or escapes that would not
// survive decoding unchanged.
var errNotText = errors.New("not plain UTF-8 JSON text")

// errTooLarge: a config file larger than maxConfig is not read at all,
// rather than cut off where a prefix might still parse.
var errTooLarge = errors.New("larger than airbag reads")

const maxConfig = 16 << 20

// surrogateEscape reports a \uD800-\uDFFF escape anywhere in b.
func surrogateEscape(b []byte) bool {
	for i := bytes.Index(b, []byte(`\u`)); i >= 0; {
		if r := b[i+2:]; len(r) >= 2 && (r[0] == 'd' || r[0] == 'D') && strings.IndexByte("89abcdefABCDEF", r[1]) >= 0 {
			return true
		}
		j := bytes.Index(b[i+2:], []byte(`\u`))
		if j < 0 {
			break
		}
		i += 2 + j
	}
	return false
}

// readRegular reads a file only if it is a regular file, without
// following a symlink. The branch is written by the agent, so a symlink
// there could point host-side airbag at any file the agent chose; it
// opens with O_NOFOLLOW and checks the opened file, so a swap between
// the check and the read does not help either.
func readRegular(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, errNotRegular
		}
		return nil, err
	}
	defer func() { _ = f.Close() }() // read only
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errNotRegular
	}
	b, err := io.ReadAll(io.LimitReader(f, maxConfig+1))
	if err == nil && len(b) > maxConfig {
		return nil, errTooLarge
	}
	return b, err
}

// object parses an object value; an absent value counts as an empty
// object, so a key added or removed on one side is compared by sub-key.
// A present null is not an object: replacing an object with null is one
// change of the whole subtree, never a deletion of each key in it.
func object(b json.RawMessage) (map[string]json.RawMessage, bool) {
	if len(b) == 0 {
		return map[string]json.RawMessage{}, true
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil || m == nil {
		return nil, false
	}
	return m, true
}

func unionKeys(a, b map[string]json.RawMessage) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range []map[string]json.RawMessage{a, b} {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}

var errNotObject = errors.New("not an object")

func getPath(m map[string]json.RawMessage, path []string) (json.RawMessage, bool) {
	if len(path) == 0 {
		return nil, false
	}
	v, ok := m[path[0]]
	if !ok || len(path) == 1 {
		return v, ok
	}
	child, isObj := object(v)
	if !isObj {
		return nil, false
	}
	return getPath(child, path[1:])
}

// setPath sets a value at path, creating objects on the way; it refuses
// to replace a non-object on the way.
func setPath(m map[string]json.RawMessage, path []string, v json.RawMessage) error {
	if len(path) == 0 {
		return errNotObject
	}
	if len(path) == 1 {
		m[path[0]] = v
		return nil
	}
	child, ok := object(m[path[0]])
	if !ok {
		return errNotObject
	}
	if err := setPath(child, path[1:], v); err != nil {
		return err
	}
	b, err := marshalJSON(child, "")
	if err != nil {
		return err
	}
	m[path[0]] = b
	return nil
}

// deletePath removes the value at path, if there is one.
func deletePath(m map[string]json.RawMessage, path []string) {
	if len(path) == 0 {
		return
	}
	if len(path) == 1 {
		delete(m, path[0])
		return
	}
	child, ok := object(m[path[0]])
	if !ok {
		return
	}
	if _, has := getPath(child, path[1:]); !has {
		return
	}
	deletePath(child, path[1:])
	if b, err := marshalJSON(child, ""); err == nil {
		m[path[0]] = b
	}
}

// marshalJSON encodes without HTML escaping, so values carried through
// as json.RawMessage keep their characters; indent "" is compact.
func marshalJSON(v any, indent string) ([]byte, error) {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if indent != "" {
		enc.SetIndent("", indent)
	}
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(strings.TrimSuffix(b.String(), "\n")), nil
}

// canon returns a value's canonical form (object keys sorted), so two
// configs compare by meaning, not by formatting. A nil or unparsable
// value canonicalizes to "", so a missing key differs from any present
// one.
func canon(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return string(b)
	}
	out, err := json.Marshal(v)
	if err != nil {
		return string(b)
	}
	return string(out)
}

// writeAtomic writes data to path through a temp file in the same
// directory, synced, and a rename, keeping the file's mode. unchanged is
// checked right before the rename; when it reports false, nothing is
// replaced and the error is errChanged.
func writeAtomic(path string, data []byte, unchanged func() bool) error {
	tmp, _, err := writeTemp(path, data)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp) }() // gone after the rename; otherwise a scratch file
	if !unchanged() {
		return errChanged
	}
	return os.Rename(tmp, path)
}

// replaceIf is writeAtomic for the real file, as a compare-and-swap:
// the replacement happens only while path still holds want, with the
// same mode (existed), or is still absent (!existed). A rename cannot
// compare, so the new file is swapped in atomically and what it
// displaced is checked after; when that is not want, the host wrote in
// between, and the swap is undone. Without an atomic swap or create
// the filesystem gets no write-back at all (errNoAtomic). A file this
// displaces that is not airbag's own is never deleted: if one is left
// over, it is moved to keepDir and reported as a *keptError.
//
// installed is the replacement's change time, read through a descriptor
// right after it took its place: any later change to the file, data or
// metadata, moves the change time past it.
func replaceIf(path string, data, want []byte, existed bool, keepDir string, unchanged func() bool) (installed int64, err error) {
	tmp, mode, err := writeTemp(path, data)
	if err != nil {
		return 0, err
	}
	if existed {
		// The replacement is a new inode: it carries the file's extended
		// attributes (ACLs, labels, the user's own) or nothing is written.
		if err := copyXattrs(path, tmp); err != nil {
			_ = os.Remove(tmp)
			return 0, fmt.Errorf("%w: its extended attributes cannot be carried over (%w)", errNoAtomic, err)
		}
	}
	f, err := os.Open(tmp) // follows the replacement's inode wherever it is renamed
	if err != nil {
		_ = os.Remove(tmp)
		return 0, err
	}
	defer func() { _ = f.Close() }() // read only
	ctime := func() int64 {
		var st unix.Stat_t
		if unix.Fstat(int(f.Fd()), &st) != nil {
			return 0
		}
		return st.Ctim.Nano()
	}
	accepted := false
	defer func() {
		if got, rerr := readRegular(tmp); rerr == nil && !accepted && !bytes.Equal(got, data) {
			kept, kerr := keepAside(tmp, keepDir)
			if kerr != nil {
				kept = tmp // another filesystem, say: it stays beside the config
			}
			err = &keptError{kept}
			return
		}
		_ = os.Remove(tmp)
	}()
	if !unchanged() {
		return 0, errChanged
	}
	if !existed {
		err := renameNoReplace(tmp, path)
		installed = ctime()
		switch {
		case errors.Is(err, fs.ErrExist):
			return 0, errChanged // the host created it meanwhile
		case cannotSwap(err):
			return 0, errNoAtomic
		case err != nil:
			return 0, err
		}
		return installed, nil
	}
	err = renameExchange(tmp, path)
	installed = ctime()
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return 0, errChanged // the host removed it meanwhile
	case cannotSwap(err):
		return 0, errNoAtomic
	case err != nil:
		return 0, err
	}
	// What was displaced must be what this attempt read, with the mode
	// and extended attributes the replacement was given: a host chmod or
	// xattr change in between is a change too.
	if got, err := readRegular(tmp); err == nil && bytes.Equal(got, want) && sameXattrs(tmp, path) {
		if fi, err := os.Lstat(tmp); err == nil && fi.Mode().Perm() == mode {
			accepted = true
			return installed, nil
		}
	}
	afterSwap()
	// Put the host's write back. If the host replaced airbag's file in
	// the meantime, the swap brings back airbag's file instead of the
	// newer host write: swap once more, so the newer write is at path.
	// Whatever host write ends up displaced is kept, not deleted.
	if err := renameExchange(tmp, path); err != nil {
		return 0, err
	}
	if got, err := readRegular(tmp); err != nil || !bytes.Equal(got, data) {
		if err := renameExchange(tmp, path); err != nil {
			return 0, err
		}
	}
	return 0, errChanged
}

// errNoAtomic: the file cannot be replaced atomically and whole.
var errNoAtomic = errors.New("this filesystem cannot replace it atomically")

// copyXattrs gives to every extended attribute from has, with its
// value; one that to has already with the same value is left alone
// (a default security label, say).
func copyXattrs(from, to string) error {
	names, err := listXattrs(from)
	if err != nil {
		return err
	}
	for _, name := range names {
		v, err := getXattr(from, name)
		if err != nil {
			return err
		}
		if cur, err := getXattr(to, name); err == nil && bytes.Equal(cur, v) {
			continue
		}
		if err := unix.Lsetxattr(to, name, v, 0); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

// sameXattrs reports whether a and b have the same extended attributes
// with the same values.
func sameXattrs(a, b string) bool {
	an, aerr := listXattrs(a)
	bn, berr := listXattrs(b)
	if aerr != nil || berr != nil || len(an) != len(bn) {
		return false
	}
	for _, name := range an {
		av, aerr := getXattr(a, name)
		bv, berr := getXattr(b, name)
		if aerr != nil || berr != nil || !bytes.Equal(av, bv) {
			return false
		}
	}
	return true
}

func listXattrs(path string) ([]string, error) {
	n, err := unix.Llistxattr(path, nil)
	if errors.Is(err, unix.ENOTSUP) {
		return nil, nil // no extended attributes on this filesystem
	}
	if err != nil || n == 0 {
		return nil, err
	}
	buf := make([]byte, n)
	if n, err = unix.Llistxattr(path, buf); err != nil {
		return nil, err
	}
	var names []string
	for _, name := range bytes.Split(buf[:n], []byte{0}) {
		if len(name) > 0 {
			names = append(names, string(name))
		}
	}
	return names, nil
}

func getXattr(path, name string) ([]byte, error) {
	n, err := unix.Lgetxattr(path, name, nil)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, n)
	n, err = unix.Lgetxattr(path, name, buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// keptError reports a host write that a write-back displaced and could
// not put back, kept at path.
type keptError struct{ path string }

func (e *keptError) Error() string {
	return "a version written on the host meanwhile is kept in " + e.path
}

// keepAside moves a displaced file into dir under a new name.
func keepAside(tmp, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, "displaced-*")
	if err != nil {
		return "", err
	}
	_ = f.Close()
	if err := os.Rename(tmp, f.Name()); err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// afterSwap is a test hook: a host write between the swap and its undo.
var afterSwap = func() {}

// beforeStamp is a test hook: a host edit between the write-back and its
// record.
var beforeStamp = func() {}

func cannotSwap(err error) bool {
	return errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.ENOTSUP)
}

// writeTemp writes data, synced, to a new file beside path with path's
// permissions (0600 if there is none), and returns its name and mode.
func writeTemp(path string, data []byte) (string, os.FileMode, error) {
	mode := os.FileMode(0o600)
	if fi, err := os.Lstat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".airbag-cfg-*")
	if err != nil {
		return "", 0, err
	}
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(mode)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return "", 0, err
	}
	return tmp.Name(), mode, nil
}

// holdsMemory reports whether a home directory the agent deleted or
// replaced (~/.claude, ~/.claude/projects or a project directory) has a
// project memory directory in the real $HOME: that change removes
// instructions too.
func holdsMemory(realPath, rel string) bool {
	parts := strings.Split(strings.TrimSuffix(filepath.ToSlash(rel), "/"), "/")
	if parts[0] != ".claude" || len(parts) > 3 || len(parts) >= 2 && parts[1] != "projects" {
		return false
	}
	pattern := map[int]string{1: "projects/*/memory", 2: "*/memory", 3: "memory"}[len(parts)]
	m, _ := filepath.Glob(filepath.Join(realPath, pattern))
	return len(m) > 0
}

// agentMemory reports whether a home path is inside a Claude Code project
// memory directory (~/.claude/projects/<slug>/memory/…), which later
// sessions load as instructions.
func agentMemory(rel string) bool {
	parts := strings.Split(strings.TrimSuffix(filepath.ToSlash(rel), "/"), "/")
	return len(parts) >= 4 && parts[0] == ".claude" && parts[1] == "projects" && parts[3] == "memory"
}
