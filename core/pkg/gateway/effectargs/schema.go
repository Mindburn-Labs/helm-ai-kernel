package effectargs

import (
	"embed"
)

// The JSON Schemas of the effect arguments this package checks. The published
// contract is protocols/json-schemas/effects; a Go module cannot embed files
// from outside its own tree, so the gateway embeds these copies to serve them
// in the effect-type catalog (AuthorityAdminService.ListEffectTypes).
// TestEmbeddedSchemasAreThePublishedOnes keeps each copy byte-identical to the
// published file.
//
//go:embed schemas/*.json
var schemaFiles embed.FS

// schemaFileOf names the embedded schema of each effect type this package
// owns.
var schemaFileOf = map[string]string{
	GitHubBranchCreateFromChanges: "branch_create_from_changes.v1.json",
	GitHubPullRequestCreateDraft:  "pull_request_create_draft.v1.json",
	GitHubRepositoryGet:           "repository_get.v1.json",
	AuthorityProvision:            "provision.v1.json",
	AuthorityNarrow:               "narrow.v1.json",
}

// ArgumentSchema returns the JSON Schema (draft 2020-12) of effectType's
// arguments, exactly as published in protocols/json-schemas/effects, or false
// for an effect type whose schema this package does not own.
func ArgumentSchema(effectType string) ([]byte, bool) {
	name, ok := schemaFileOf[effectType]
	if !ok {
		return nil, false
	}
	body, err := schemaFiles.ReadFile("schemas/" + name)
	if err != nil {
		return nil, false
	}
	return body, true
}
