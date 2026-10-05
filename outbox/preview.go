package outbox

import (
	"fmt"
	"io"

	"github.com/getjump/airbag/operation"
)

// WritePreview interprets a frozen request without touching credentials or the
// network. Callers writing a terminal must supply a term.Safe writer.
func WritePreview(w io.Writer, id, status string, p operation.Preview) {
	r := p.Request.PullRequest
	fmt.Fprintf(w, "%s %s [%s]\n", id, p.Request.Kind, status)
	fmt.Fprintf(w, "  destination: %s/%s\n  base: %s\n  head: %s\n  commit: %s\n", p.Authority.Service, r.Repository, r.Base, r.Head, r.HeadCommit)
	fmt.Fprintf(w, "  title: %s\n  draft: %t\n  authority required: %s on %s\n", r.Title, r.Draft, p.Authority.Permission, p.Authority.Resource)
	fmt.Fprintf(w, "  request: %s\n  body: %s\n--- frozen body ---\n%s\n--- end body ---\n", p.RequestDigest, p.BodyDigest, r.Body)
}
