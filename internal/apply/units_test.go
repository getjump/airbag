package apply

import (
	"io/fs"
	"testing"

	"github.com/getjump/airbag/internal/review"
)

func TestUnits(t *testing.T) {
	cs := []review.Change{
		{Layer: "ws", Rel: ".git/index", Kind: review.Modified},
		{Layer: "ws", Rel: ".git/objects/ab/cd", Kind: review.Added},
		{Layer: "ws", Rel: ".git/hooks/pre-commit", Kind: review.Added, Flags: []string{"persist"}},
		{Layer: "ws", Rel: "src", Kind: review.Added, Type: fs.ModeDir},
		{Layer: "ws", Rel: "src/a.go", Kind: review.Added},
		{Layer: "ws", Rel: "vendor", Kind: review.Replaced, Type: fs.ModeDir},
		{Layer: "ws", Rel: "vendor/x.go", Kind: review.Added},
		{Layer: "home", Rel: ".cache/go/1", Kind: review.Added, Flags: []string{"outside workspace"}},
		{Layer: "home", Rel: ".cache/go/2", Kind: review.Added, Flags: []string{"outside workspace"}},
		{Layer: "home", Rel: ".bashrc", Kind: review.Modified, Flags: []string{"outside workspace", "persist"}},
	}
	want := []struct {
		title string
		n     int
	}{
		{"git internals (2 files)", 2},
		{"+ .git/hooks/pre-commit", 1},
		{"+ src/a.go", 1},
		{"! vendor/ (directory replaced)", 2},
		{"~/.cache/… (cache) (2 files)", 2},
		{"~ ~/.bashrc", 1},
	}
	got := Units(cs)
	if len(got) != len(want) {
		t.Fatalf("got %d units: %+v", len(got), got)
	}
	for i, w := range want {
		if got[i].Title != w.title || len(got[i].Changes) != w.n {
			t.Errorf("unit %d: got %q (%d), want %q (%d)", i, got[i].Title, len(got[i].Changes), w.title, w.n)
		}
	}
	if !got[3].matches([]string{"vendor"}) || got[3].matches([]string{"src"}) {
		t.Error("matches")
	}
}
