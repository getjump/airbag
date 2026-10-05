package outbox

import (
	"fmt"
	"io"
	"strings"

	"github.com/getjump/airbag/internal/operation"
)

// WritePreview interprets a frozen request without touching credentials or the
// network. Callers writing a terminal must supply a term.Safe writer.
func WritePreview(w io.Writer, id, status string, p operation.Preview) {
	r := p.Request.PullRequest
	fmt.Fprintf(w, "%s %s [%s]\n", id, p.Request.Kind, status)
	fmt.Fprintf(w, "  destination: %s/%s\n  base: %s\n  head: %s\n  commit: %s\n", p.Authority.Service, r.Repository, r.Base, r.Head, r.HeadCommit)
	fmt.Fprintf(w, "  title: %s\n  draft: %t\n  authority required: %s on %s\n", r.Title, r.Draft, p.Authority.Permission, p.Authority.Resource)
	fmt.Fprintf(w, "  request: %s\n  body: %s, %d bytes, %d lines, each shown after \"| \"\n", p.RequestDigest, p.BodyDigest, len(r.Body), len(bodyLines(r.Body)))
	// Every body line is marked, so a line in the body cannot pass for
	// the end of it.
	for _, l := range bodyLines(r.Body) {
		fmt.Fprintf(w, "  | %s\n", l)
	}
}

func bodyLines(body string) []string {
	if body == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(body, "\n"), "\n")
}
