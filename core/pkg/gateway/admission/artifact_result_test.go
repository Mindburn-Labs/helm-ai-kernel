package admission

import (
	"encoding/json"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/adapters"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

const artifactSchemaID = "helm.work.delegate.result.v1"

func artifactDeclaration(effectType string) adapters.Declaration {
	return adapters.Declaration{EffectType: effectType, ResultSchemaID: artifactSchemaID,
		ResultSchema: []byte(`{"$id":"helm.work.delegate.result.v1","type":"object","additionalProperties":false,"required":["child_id"],"properties":{"child_id":{"type":"string","minLength":1}}}`)}
}

func artifactObservation(t *testing.T, raw string) *adapters.Observation {
	t.Helper()
	artifact, err := adapters.NewJSONResult(artifactSchemaID, []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return &adapters.Observation{Source: "workeffects.readback", TrustClass: "gateway_bound_cp", Artifact: artifact}
}

func TestArtifactResultRequiresTheDeclaredSchema(t *testing.T) {
	schema, err := adapters.CompileResultSchema(artifactDeclaration(noteType))
	if err != nil {
		t.Fatal(err)
	}
	o := artifactObservation(t, `{"child_id":"child-7"}`)
	kind, body, err := typedResult(noteType, schema, o)
	if err != nil || kind != "artifact" || len(body) == 0 {
		t.Fatalf("declared result = %q %s %v", kind, body, err)
	}
	for name, test := range map[string]struct {
		effectType  string
		schema      *adapters.ResultSchema
		observation *adapters.Observation
	}{
		"undeclared output":      {noteType, nil, o},
		"missing output":         {noteType, schema, &adapters.Observation{Source: "s", TrustClass: "t"}},
		"fixed type replacement": {effectargs.GitHubRepositoryGet, schema, o},
		"unrecognized property":  {noteType, schema, artifactObservation(t, `{"child_id":"child-7","new_grants":["all"]}`)},
	} {
		if _, _, err := typedResult(test.effectType, test.schema, test.observation); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	o.GitHubBranch = &adapters.GitHubBranchResult{}
	if _, _, err := typedResult(noteType, schema, o); err == nil {
		t.Fatal("multiple typed members were accepted")
	}
}

func TestStoredArtifactRetainsItsOriginalSchemaAndContentAddress(t *testing.T) {
	o := artifactObservation(t, `{"child_id":"child-7"}`)
	body, err := json.Marshal(o.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	stored := Observation{ResultRef: o.Artifact.Digest}
	if err := stored.decodeResult("artifact", body); err != nil {
		t.Fatal(err)
	}
	if stored.Artifact.SchemaID != artifactSchemaID || string(stored.Artifact.CanonicalBytes) != `{"child_id":"child-7"}` {
		t.Fatalf("historical read changed the original result: %+v", stored)
	}
	stored.ResultRef = "sha256:wrong"
	if err := stored.decodeResult("artifact", body); err == nil {
		t.Fatal("an observation with a different content address was accepted")
	}
	o.Artifact.CanonicalBytes[13] = 'X'
	body, err = json.Marshal(o.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	stored.ResultRef = o.Artifact.Digest
	if err := stored.decodeResult("artifact", body); err == nil {
		t.Fatal("altered stored content was accepted under the old digest")
	}
}
