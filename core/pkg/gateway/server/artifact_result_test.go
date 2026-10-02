package server

import (
	"bytes"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
)

func TestArtifactObservationPreservesItsCanonicalWireContent(t *testing.T) {
	a, err := adapters.NewJSONResult("helm.work.delegate.result.v1", []byte(`{"child_id":"child-7"}`))
	if err != nil {
		t.Fatal(err)
	}
	o := observationProto(&admission.Observation{Source: "workeffects.readback", TrustClass: "gateway_bound_cp",
		ObservedAt: time.Now().UTC(), ResultRef: a.Digest, Artifact: a})
	r := o.GetArtifact()
	if r == nil || r.SchemaId != a.SchemaID || r.ContentType != "application/json" || r.Digest != a.Digest ||
		!bytes.Equal(r.CanonicalBytes, a.CanonicalBytes) || o.ResultRef != r.Digest {
		t.Fatalf("wire result changed the recorded content: %+v", o)
	}
}
