package deniallegibility

import (
	"encoding/json"
	"os"
	"sort"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// The finality vocabulary is declared in three load-bearing places: the Go
// contracts constants the workstation producer writes, the workstation receipt
// schema every consumer validates against, and the reason-code registry schema
// the per-code classifications validate against. This pins them to each other,
// so the vocabulary cannot drift one file at a time. (The proto enum in
// policy-schema/v1/verdict.proto is additive-only under proto-breaking and is
// not re-checked here.)
func TestFinalityVocabularyParity(t *testing.T) {
	want := make([]string, 0, len(requiredFinalities))
	for _, f := range requiredFinalities {
		want = append(want, string(f))
	}
	sort.Strings(want)

	schemas := map[string][]string{
		"workstation receipt schema": enumAt(t,
			"../../../protocols/json-schemas/workstation/agent_run_receipt.v1.schema.json",
			"$defs", "denied_effect", "properties", "finality", "enum"),
		"reason-code registry schema": enumAt(t,
			"../../../protocols/json-schemas/reason-codes/reason-codes-v1.schema.json",
			"$defs", "ReasonCodeEntry", "properties", "finality", "enum"),
	}
	for name, got := range schemas {
		sort.Strings(got)
		if len(got) != len(want) {
			t.Errorf("%s finality enum = %v, contracts declare %v", name, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%s finality enum = %v, contracts declare %v", name, got, want)
				break
			}
		}
	}
}

// requiredFinalities is doubly load-bearing: the pack coverage check and the
// parity check above both key on it. It must itself cover every declared
// constant, or a sixth value could ship with no conformance coverage and no
// parity pin.
func TestRequiredFinalitiesCoverEveryDeclaredConstant(t *testing.T) {
	declared := []contracts.DenialFinality{
		contracts.DenialClassForbidden,
		contracts.DenialUngranted,
		contracts.DenialInstanceParameter,
		contracts.DenialInstanceContext,
		contracts.DenialInstanceMembership,
	}
	if len(declared) != len(requiredFinalities) {
		t.Fatalf("requiredFinalities has %d values, contracts declare %d", len(requiredFinalities), len(declared))
	}
	seen := map[contracts.DenialFinality]bool{}
	for _, f := range requiredFinalities {
		seen[f] = true
	}
	for _, f := range declared {
		if !seen[f] {
			t.Errorf("requiredFinalities is missing %q", f)
		}
	}
}

// enumAt reads a JSON document and returns the string array at the given key
// path. Failing loudly on a missing step keeps a schema refactor from turning
// the parity check into a vacuous pass.
func enumAt(t *testing.T, path string, keys ...string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	for _, key := range keys {
		obj, ok := doc.(map[string]any)
		if !ok {
			t.Fatalf("%s: %q is not an object", path, key)
		}
		doc, ok = obj[key]
		if !ok {
			t.Fatalf("%s: no %q — did the schema move?", path, key)
		}
	}
	items, ok := doc.([]any)
	if !ok {
		t.Fatalf("%s: enum at %v is not an array", path, keys)
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			t.Fatalf("%s: enum member %v is not a string", path, item)
		}
		out = append(out, s)
	}
	return out
}
