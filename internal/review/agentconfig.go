package review

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/getjump/airbag/internal/session"
)

// Agents keep some state in a JSON file in $HOME that they rewrite every
// run: ~/.claude.json holds counters, a machine id and migration markers
// next to things that steer later runs (MCP servers, tool permissions,
// per-project trust). The whole file goes through the branch like any
// other, so none of it reaches the real file until apply. Review shows it
// by the names of the keys that changed, never their values, which may
// carry tokens; flagging every such change as persistence would raise an
// alarm on every single session over counters the user does not care
// about.
//
// jsonConfigs resolves that without any agent-specific logic in the code
// path. Each entry names a file and lists key PATHS in two classes:
//
//   - benign: keys the CLI rewrites on its own every run. Review lists
//     them, but a change confined to them needs no decision.
//   - persist: keys that start commands or change trust. A change to one
//     is flagged "persist".
//
// Any other changed key is unknown: review lists it by name as needing a
// decision, though not as persistence. A path is dot-separated top-level
// keys, and one segment may be "*", which matches any key at that level,
// so "projects.*.lastCost" covers every project's entry. A key whose
// sub-keys are listed (projects) is compared sub-key by sub-key; a key
// with no listed sub-keys is compared whole. The agent name appears only
// here, as data, like the persist tables.
//
// benign is an ALLOWLIST, built from what Claude Code 2.1.x was observed
// to write on its own, in a non-interactive run and in interactive runs
// driven through a pseudo-terminal: a key not on it costs a decision in
// review, never a silent pass.
type jsonConfig struct {
	path    string   // relative to $HOME
	benign  []string // key paths the CLI rewrites on its own
	persist []string // key paths that run code or change trust
}

var jsonConfigs = []jsonConfig{
	{path: ".claude.json", benign: claudeBenign, persist: claudePersist},
	// The legacy place, which Claude Code still reads first when it exists.
	{path: ".claude/.config.json", benign: claudeBenign, persist: claudePersist},
}

// claudeBenign and claudePersist are Claude Code's global config keys,
// the same in both places the file may be.
var (
	claudeBenign = []string{
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
	}
	claudePersist = []string{
		"mcpServers", "enabledMcpjsonServers", "disabledMcpjsonServers", "mcpContextUris",
		"permissions", "allowedTools", "hooks", "env", "apiKeyHelper",
		// Answers to "use this API key from the environment?", and the
		// account a login inside the session recorded: which account
		// (and organization, whose managed settings later sessions
		// fetch) the host's next session uses.
		"customApiKeyResponses", "oauthAccount", "primaryApiKey",
		// The answer to the bypass-permissions dialog: the host's next
		// --dangerously-skip-permissions run no longer asks.
		"bypassPermissionsModeAccepted",
		// Per project: tool permissions, MCP servers, folder trust, and
		// approval of CLAUDE.md imports from outside the project.
		"projects.*.allowedTools", "projects.*.mcpServers", "projects.*.mcpContextUris",
		"projects.*.enabledMcpjsonServers", "projects.*.disabledMcpjsonServers",
		"projects.*.hasTrustDialogAccepted", "projects.*.hasClaudeMdExternalIncludesApproved",
	}
)

// NoteHostConfigs records, before a run, which jsonConfig files exist in
// the real $HOME (session.Meta.HostConfigs). The agent's CLI rewrites
// them every run, so the branch copies one up; if the host removes the
// real file later, that copy reads as a new file, and the record is how
// apply tells the two apart.
func NoteHostConfigs(s *session.Session) {
	if !s.OverHome {
		return
	}
	for i := range jsonConfigs {
		p := filepath.Join(s.Home, jsonConfigs[i].path)
		if _, err := os.Lstat(p); err == nil && !slices.Contains(s.HostConfigs, p) {
			s.HostConfigs = append(s.HostConfigs, p)
		}
	}
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
	classBenign
	classPersist
)

// keyChange is one changed key path, at the depth the table describes.
type keyChange struct {
	path  []string // concrete keys from the top level down
	class keyClass
}

// String renders a path for review: keys that are plain identifiers
// joined with dots, any other key quoted in brackets, since project
// keys are paths (projects["/home/me/api"].allowedTools). The agent
// names the keys, so a key that is not a plain identifier is always
// quoted: it stays on one line and cannot pass for a path of several
// keys or a list of them. Names only, never values.
func (k keyChange) String() string {
	if len(k.path) == 0 {
		return "(whole file)"
	}
	var b strings.Builder
	for i, seg := range k.path {
		switch {
		case plainKey(seg) && i == 0:
			b.WriteString(seg)
		case plainKey(seg):
			b.WriteString("." + seg)
		default:
			b.WriteString("[" + strconv.Quote(seg) + "]")
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
	}{{cf.benign, classBenign}, {cf.persist, classPersist}} {
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
		if empty(a) && empty(b) {
			return nil // a listed key the CLI writes with its default, as a new project's entry has
		}
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

// empty reports an absent value or an empty one: [], {}, false or "".
// For a key the table lists, going from one to another adds nothing: an
// empty permission list allows nothing, and an empty deny list is no list.
// null is not empty, as in object.
func empty(v json.RawMessage) bool {
	switch canon(v) {
	case "", "[]", "{}", "false", `""`:
		return true
	}
	return false
}

// configAt returns the jsonConfig a home change is: the config itself,
// or the file a real config that is a symlink points to inside $HOME (a
// dotfiles directory, say), which the agent's CLI writes through the
// link. nil when it is neither.
func configAt(c Change) *jsonConfig {
	if cf := configFor(filepath.ToSlash(c.Rel)); cf != nil {
		return cf
	}
	home, ok := strings.CutSuffix(c.Path, string(filepath.Separator)+c.Rel)
	if !ok {
		return nil
	}
	for i := range jsonConfigs {
		real := filepath.Join(home, jsonConfigs[i].path)
		t, err := os.Readlink(real)
		if err != nil {
			continue
		}
		if !filepath.IsAbs(t) {
			t = filepath.Join(filepath.Dir(real), t)
		}
		if filepath.Clean(t) == c.Path {
			return &jsonConfigs[i]
		}
	}
	return nil
}

// configChanges lists a config file's changed key paths for review (names
// only, never values). ok is false when the change is not a config file;
// readable is false when either side is not a readable regular JSON file
// (a directory where the config was is not).
func configChanges(c Change) (changes []keyChange, readable, ok bool) {
	if c.Layer != "home" {
		return nil, false, false
	}
	cf := configAt(c)
	if cf == nil {
		return nil, false, false
	}
	if c.IsDir() {
		return nil, false, true
	}
	branchRaw, err := readRegular(c.Upper)
	if err != nil {
		return nil, false, true
	}
	if _, err := topLevel(branchRaw); err != nil {
		return nil, false, true
	}
	realRaw, err := readReal(c.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		realRaw = []byte("{}")
	case err != nil:
		return nil, false, true
	}
	return cf.diff(nil, realRaw, branchRaw), true, true
}

// benignNote starts configNotes' note on benign keys.
const benignNote = "benign key(s): "

// configNotes describes a config file change by class, each naming its
// keys: "persist" and "persist key(s): …" for keys that run code or change
// trust, "unknown key(s): …" for keys the table does not list (shown
// plainly, not as persistence), and "benign key(s): …" for keys the CLI
// rewrites on its own. ok is false when c is not a config file.
func configNotes(c Change) (notes []string, ok bool) {
	changes, readable, ok := configChanges(c)
	if !ok {
		return nil, false
	}
	if !readable {
		// Nothing can be told about its keys, so it counts as the worst.
		return []string{"persist", "not a readable regular JSON file"}, true
	}
	byClass := map[keyClass][]string{}
	for _, ch := range changes {
		byClass[ch.class] = append(byClass[ch.class], ch.String())
	}
	if k := byClass[classPersist]; len(k) > 0 {
		notes = append(notes, "persist", "persist key(s): "+strings.Join(k, ", "))
	}
	if k := byClass[classUnknown]; len(k) > 0 {
		notes = append(notes, "unknown key(s): "+strings.Join(k, ", "))
	}
	if m := widened(c); m != "" {
		notes = append(notes, m)
	}
	if k := byClass[classBenign]; len(k) > 0 {
		notes = append(notes, benignNote+strings.Join(k, ", "))
	}
	return notes, true
}

// widened names a mode change that lets other users write the config,
// who could then add an MCP server to it; "" when there is none. Without
// a real file the CLI's own 0600 is the base.
func widened(c Change) string {
	if c.Kind == Deleted || c.Type != 0 {
		return ""
	}
	old := fs.FileMode(0o600)
	if fi, err := os.Stat(c.Path); err == nil {
		old = fi.Mode().Perm()
	}
	if c.Mode.Perm()&^old&0o002 == 0 {
		return ""
	}
	return fmt.Sprintf("mode %04o -> %04o, writable by other users", old, c.Mode.Perm())
}

// configFlags are review's flags for a config file change: configNotes
// without the benign keys, since a change confined to them needs no
// decision (the diff still names them). nil when c is not a config file
// or no other key changed.
func configFlags(c Change) []string {
	notes, _ := configNotes(c)
	return slices.DeleteFunc(notes, func(n string) bool { return strings.HasPrefix(n, benignNote) })
}

// topLevel parses a config file, which must be a JSON object: null or
// any other value is malformed, so it is flagged as unreadable. So is
// text Go's decoder would change while reading: invalid UTF-8, and
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
func readRegular(path string) ([]byte, error) { return readFile(path, syscall.O_NOFOLLOW) }

// readReal reads the real config, which the host may keep as a symlink
// (into a dotfiles directory, say). The real $HOME is the host's, not
// the agent's, so the link is followed, to a regular file only.
func readReal(path string) ([]byte, error) { return readFile(path, 0) }

func readFile(path string, flags int) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|flags, 0)
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

// canon returns a value's canonical form (object keys sorted), so two
// configs compare by meaning, not by formatting. A nil or unparsable
// value canonicalizes to "", so a missing key differs from any present
// one.
func canon(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	// Numbers stay as written (json.Number): through float64, two
	// integers above 2^53 would compare equal.
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return string(b)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return string(b) // trailing data
	}
	out, err := json.Marshal(v)
	if err != nil {
		return string(b)
	}
	return string(out)
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
	// The project directories it holds, read as names: a home path may
	// hold the characters a glob pattern would take as special.
	projects := []string{realPath}
	switch len(parts) {
	case 1:
		projects = subdirs(filepath.Join(realPath, "projects"))
	case 2:
		projects = subdirs(realPath)
	}
	for _, p := range projects {
		if _, err := os.Lstat(filepath.Join(p, "memory")); err == nil {
			return true
		}
	}
	return false
}

func subdirs(dir string) []string {
	ents, _ := os.ReadDir(dir)
	var out []string
	for _, e := range ents {
		if e.IsDir() {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

// agentMemory reports whether a home path is inside a Claude Code project
// memory directory (~/.claude/projects/<slug>/memory/…), which later
// sessions load as instructions.
func agentMemory(rel string) bool {
	parts := strings.Split(strings.TrimSuffix(filepath.ToSlash(rel), "/"), "/")
	return len(parts) >= 4 && parts[0] == ".claude" && parts[1] == "projects" && parts[3] == "memory"
}
