package apply

import (
	"fmt"
	"os"
	"strings"

	"github.com/getjump/airbag/internal/review"
)

// Unit is what the human accepts or rejects as one piece. Most units
// are single files; git internals, caches and replaced directories go
// together, because applying half of them would leave a broken state.
type Unit struct {
	Title   string
	Changes []review.Change
	Flags   []string
}

func Units(cs []review.Change) []Unit {
	var out []*Unit
	byKey := map[string]*Unit{}
	var replaced []string // layer:rel/ prefixes of replaced directories
	withChildren := map[string]bool{}
	for _, c := range cs {
		dir := c.Layer + ":" + c.Rel
		for p := dir; ; {
			i := strings.LastIndex(p, "/")
			if i < 0 {
				break
			}
			p = p[:i]
			withChildren[p] = true
		}
	}
	for _, c := range cs {
		id := c.Layer + ":" + c.Rel
		if c.IsDir() && c.Kind == review.Added && withChildren[id] {
			continue // created along with its files
		}
		key, title := id, mark(c)+" "+display(c)
		for _, r := range replaced {
			if strings.HasPrefix(id, r) {
				key = strings.TrimSuffix(r, "/")
			}
		}
		flagged := len(withoutOutside(c.Flags)) > 0
		switch {
		case key != id:
		case c.Kind == review.Replaced:
			replaced = append(replaced, id+"/")
			title = "! " + display(c) + "/ (directory replaced)"
		case c.Layer == "ws" && strings.HasPrefix(c.Rel, ".git/") && !flagged:
			key, title = "ws:.git", "git internals"
		case c.Layer == "home" && !flagged && noise(c.Rel) != "":
			d, kind := review.Noise(c.Rel)
			key, title = "home:"+d, "~/"+d+"… ("+kind+")"
		case c.Layer == "home" && !flagged && review.GitDir(c.Rel) != "":
			d := review.GitDir(c.Rel)
			key, title = "home:"+d, "~/"+d+"… (git internals)"
		}
		u := byKey[key]
		if u == nil {
			u = &Unit{Title: title}
			byKey[key] = u
			out = append(out, u)
		}
		u.Changes = append(u.Changes, c)
		u.Flags = appendNew(u.Flags, c.Flags...)
	}
	units := make([]Unit, 0, len(out))
	for _, u := range out {
		if len(u.Changes) > 1 && !strings.HasPrefix(u.Title, "!") {
			u.Title = fmt.Sprintf("%s (%d files)", u.Title, len(u.Changes))
		}
		units = append(units, *u)
	}
	return units
}

func mark(c review.Change) string {
	return map[string]string{review.Added: "+", review.Modified: "~", review.Deleted: "-", review.Replaced: "!"}[c.Kind]
}

func display(c review.Change) string {
	if c.Layer == "home" {
		return "~/" + c.Rel
	}
	return c.Rel
}

func withoutOutside(fl []string) []string {
	var out []string
	for _, f := range fl {
		if f != "outside workspace" {
			out = append(out, f)
		}
	}
	return out
}

func appendNew(list []string, items ...string) []string {
	for _, it := range items {
		found := false
		for _, x := range list {
			found = found || x == it
		}
		if !found {
			list = append(list, it)
		}
	}
	return list
}

// matches reports whether a unit touches one of the given paths.
func (u Unit) matches(paths []string) bool {
	for _, c := range u.Changes {
		for _, p := range paths {
			p = strings.TrimSuffix(p, "/")
			rel := strings.TrimPrefix(p, "~/")
			if c.Path == p || strings.HasPrefix(c.Path, p+"/") || c.Rel == rel || strings.HasPrefix(c.Rel, rel+"/") {
				return true
			}
		}
	}
	return false
}

// inside returns the path of paths that names something inside the
// directory u replaces, when none names the directory itself or one
// above it: a replacement applies whole or not at all.
func (u Unit) inside(paths []string) string {
	r := u.Changes[0]
	if r.Kind != review.Replaced || (Unit{Changes: u.Changes[:1]}).matches(paths) {
		return ""
	}
	for _, p := range paths {
		if (Unit{Changes: u.Changes[1:]}).matches([]string{p}) {
			return p
		}
	}
	return ""
}

// forget removes applied changes from the branch so they no longer show
// up in review. Children go before their directories. A replaced
// directory was applied whole, so all of it goes, whiteouts left in it
// included.
func forget(cs []review.Change) {
	for i := len(cs) - 1; i >= 0; i-- {
		c := cs[i]
		if c.IsDir() && c.Kind != review.Deleted && c.Kind != review.Replaced {
			_ = os.Remove(c.Upper) // only if empty
			continue
		}
		_ = os.RemoveAll(c.Upper)
	}
}

func noise(rel string) string {
	group, _ := review.Noise(rel)
	return group
}
