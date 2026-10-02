package mcpserver

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/admission"
)

func TestArtifactResultReachesTheWorkerAsItsDeclaredPayload(t *testing.T) {
	artifact, err := adapters.NewJSONResult("helm.work.delegate.result.v1", []byte(`{"child_id":"child-7"}`))
	if err != nil {
		t.Fatal(err)
	}
	observed := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	attempt := admission.Attempt{ID: "attempt-7", EffectType: "helm.work.delegate", State: "OBSERVED", Outcome: "SUCCEEDED",
		LatestObservation: &admission.Observation{Source: "workeffects.readback", TrustClass: "gateway_bound_cp", ObservedAt: observed,
			ResultRef: artifact.Digest, Artifact: artifact}}
	r := resultFor(attempt)
	if r.IsError || r.StructuredContent["status"] != "succeeded" || r.StructuredContent["result_kind"] != "artifact" ||
		r.StructuredContent["result_schema_id"] != artifact.SchemaID || r.StructuredContent["result_digest"] != artifact.Digest {
		t.Fatalf("worker result: %+v", r)
	}
	raw, err := json.Marshal(r.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Result struct {
			ChildID string `json:"child_id"`
		} `json:"result"`
		Observation struct {
			Source     string    `json:"source"`
			ResultRef  string    `json:"result_ref"`
			ObservedAt time.Time `json:"observed_at"`
		} `json:"observation"`
	}
	if json.Unmarshal(raw, &decoded) != nil || decoded.Result.ChildID != "child-7" ||
		decoded.Observation.Source != "workeffects.readback" || decoded.Observation.ResultRef != artifact.Digest || !decoded.Observation.ObservedAt.Equal(observed) {
		t.Fatalf("declared result/readback metadata did not reach the worker: %s", raw)
	}
}
