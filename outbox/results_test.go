package outbox

import (
	"encoding/json"
	"testing"

	"github.com/getjump/airbag/operation"
)

func TestResultCannotConfuseQueuedRequestWithRemoteSuccess(t *testing.T) {
	in := typedIntent()
	in.ID, in.Status = "i-1", Pending
	digest, err := in.Request.Digest()
	if err != nil {
		t.Fatal(err)
	}
	in.RequestDigest = digest
	if r := in.TypedResult(); r == nil || r.Outcome != operation.Queued || r.Value != "" {
		t.Fatalf("queued result: %+v", r)
	}
	result := operation.Result{Ticket: in.ID, RequestDigest: digest, Outcome: operation.Succeeded, Value: "https://github.com/getjump/airbag/pull/7"}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	in.Status, in.Output = Done, string(data)
	if r := in.TypedResult(); r == nil || *r != result {
		t.Fatalf("lost recorded outcome: %+v", r)
	}
	in.RequestDigest = "different"
	if in.TypedResult() != nil {
		t.Fatal("attested a result for a different request")
	}
	in.Status, in.Output, in.RequestDigest = Unknown, "interrupted before outcome was recorded", digest
	if r := in.TypedResult(); r == nil || r.Outcome != operation.Uncertain {
		t.Fatalf("crash result: %+v", r)
	}
	legacy := Intent{Kind: KindCmd, Status: Done, Output: string(data)}
	if legacy.TypedResult() != nil {
		t.Fatal("invented typed evidence for a legacy action")
	}
}
