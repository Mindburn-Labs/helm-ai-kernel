package effectargs

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// publishedSchemas is where each embedded copy is published, relative to the
// repository root.
var publishedSchemas = map[string]string{
	GitHubBranchCreateFromChanges: "protocols/json-schemas/effects/github/branch_create_from_changes.v1.json",
	GitHubPullRequestCreateDraft:  "protocols/json-schemas/effects/github/pull_request_create_draft.v1.json",
	GitHubPullRequestCreate:       "protocols/json-schemas/effects/github/pull_request_create.v1.json",
	GitHubPullRequestMerge:        "protocols/json-schemas/effects/github/pull_request_merge.v1.json",
	GitHubRepositoryGet:           "protocols/json-schemas/effects/github/repository_get.v1.json",
	AuthorityProvision:            "protocols/json-schemas/effects/authority/provision.v1.json",
	AuthorityNarrow:               "protocols/json-schemas/effects/authority/narrow.v1.json",
}

// The catalog serves the embedded copies as the contract: a copy that drifts
// from the published file would tell a client something the docs do not.
func TestEmbeddedSchemasAreThePublishedOnes(t *testing.T) {
	if len(publishedSchemas) != len(schemaFileOf) {
		t.Fatalf("%d published schemas listed, %d embedded", len(publishedSchemas), len(schemaFileOf))
	}
	root := filepath.Join("..", "..", "..", "..")
	for effectType, path := range publishedSchemas {
		want, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		got, ok := ArgumentSchema(effectType)
		if !ok {
			t.Fatalf("%s has no embedded schema", effectType)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("the embedded schema of %s differs from %s: copy it again", effectType, path)
		}
		var doc struct {
			XHelm struct {
				EffectType string `json:"effect_type"`
			} `json:"x-helm"`
		}
		if err := json.Unmarshal(got, &doc); err != nil || doc.XHelm.EffectType != effectType {
			t.Errorf("the schema of %s names effect type %q (%v)", effectType, doc.XHelm.EffectType, err)
		}
	}
}

func TestArgumentSchemaOfAnotherEffectTypeIsAbsent(t *testing.T) {
	for _, effectType := range []string{"", AuthorityLift, "ops.note", "model.inference"} {
		if body, ok := ArgumentSchema(effectType); ok || body != nil {
			t.Errorf("ArgumentSchema(%q) = %d bytes, %v", effectType, len(body), ok)
		}
	}
}
