package api_test

import (
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/httperr"
)

// TestProblemDetailIsHTTPErrAlias fails to compile — not merely fails — if
// api.ProblemDetail is ever redefined as a distinct type, which would break
// every caller that passes one across the boundary.
func TestProblemDetailIsHTTPErrAlias(t *testing.T) {
	var p api.ProblemDetail
	var q *httperr.ProblemDetail = &p
	q.Title = "Teapot"
	if p.Title != "Teapot" {
		t.Fatalf("api.ProblemDetail is not an alias of httperr.ProblemDetail")
	}
}

// errSentinel keeps WriteInternal's two calls comparable: the error is logged,
// never rendered, so any non-nil value works as long as both sides get the same.
var errSentinel = &httperr.ProblemDetail{Title: "internal", Detail: "secret database password"}
