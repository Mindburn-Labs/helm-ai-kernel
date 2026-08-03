package tracing_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/correlation"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/tracing"
)

// TestDeprecatedAliasesStillResolve is the no-breaking-change claim of
// HELM-460, asserted rather than assumed. svc-helm-control-plane and any
// external embedder import these names today; the move to pkg/correlation is
// only safe if a consumer pinned to this path keeps compiling and behaving.
//
// This file is itself the compile-time half of the proof: it uses every
// symbol the old package exported.
func TestDeprecatedAliasesStillResolve(t *testing.T) {
	const canonical = "3f2504e0-4f89-41d3-9a0c-0305e82c3301"

	if !tracing.IsValidCorrelationID(canonical) {
		t.Error("IsValidCorrelationID rejected a canonical UUID")
	}
	if tracing.IsValidCorrelationID("3F2504E0-4F89-41D3-9A0C-0305E82C3301") {
		t.Error("IsValidCorrelationID accepted an uppercase alias; one request could appear under two identities")
	}

	headers := http.Header{}
	headers.Set("X-Helm-Correlation-ID", canonical)
	id, adopted := tracing.AdoptOrMintFromHeaders(headers)
	if !adopted || string(id) != canonical {
		t.Errorf("AdoptOrMintFromHeaders(%q) = (%q, %v), want it adopted", canonical, id, adopted)
	}

	ctx := tracing.WithCorrelationID(context.Background(), id)
	got, ok := tracing.GetCorrelationID(ctx)
	if !ok || got != id {
		t.Errorf("GetCorrelationID round-trip = (%q, %v), want (%q, true)", got, ok, id)
	}

	outbound := http.Header{}
	tracing.InjectHTTPHeaders(ctx, outbound)
	extracted, ok := tracing.ExtractHTTPHeaders(outbound)
	if !ok || extracted != id {
		t.Errorf("Inject→Extract round-trip = (%q, %v), want (%q, true)", extracted, ok, id)
	}

	if minted := tracing.NewCorrelationID(); !tracing.IsValidCorrelationID(string(minted)) {
		t.Errorf("NewCorrelationID produced %q, which is not canonical", minted)
	}
}

// TestAliasIsTheSameType guards the alias rather than a redefinition. A
// `type CorrelationID correlation.ID` would compile here but break every
// caller that passes a value across the two packages, which is exactly the
// breakage this refactor promises not to cause.
func TestAliasIsTheSameType(t *testing.T) {
	var fromNew correlation.ID = correlation.New()

	// Assigning both directions without conversion only compiles if the two
	// names denote one type.
	var fromOld tracing.CorrelationID = fromNew
	fromNew = fromOld

	// The context key lives in pkg/correlation, so a value stored through the
	// deprecated setter must be readable through the new getter and back.
	ctx := tracing.WithCorrelationID(context.Background(), fromOld)
	if got, ok := correlation.From(ctx); !ok || got != fromNew {
		t.Errorf("value stored via tracing.WithCorrelationID not readable via correlation.From: got (%q, %v)", got, ok)
	}

	ctx = correlation.With(context.Background(), fromNew)
	if got, ok := tracing.GetCorrelationID(ctx); !ok || got != fromOld {
		t.Errorf("value stored via correlation.With not readable via tracing.GetCorrelationID: got (%q, %v)", got, ok)
	}
}
