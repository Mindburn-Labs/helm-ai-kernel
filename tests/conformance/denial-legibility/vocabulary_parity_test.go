package deniallegibility

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
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

// MISSING_REQUIREMENT does not identify which input, grant, or context would
// resolve the denial. Classifying it as retryable would make consumers learn a
// false parameter lesson, so the generic registry entry must stay unclassified.
func TestGenericMissingRequirementIsUnclassified(t *testing.T) {
	raw, err := os.ReadFile("../../../protocols/json-schemas/reason-codes/reason-codes-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var registry struct {
		Codes []struct {
			Code     string `json:"code"`
			Finality string `json:"finality"`
		} `json:"codes"`
	}
	if err := json.Unmarshal(raw, &registry); err != nil {
		t.Fatal(err)
	}
	for _, entry := range registry.Codes {
		if entry.Code != "MISSING_REQUIREMENT" {
			continue
		}
		if entry.Finality != "" {
			t.Fatalf("MISSING_REQUIREMENT finality = %q, want no classification", entry.Finality)
		}
		return
	}
	t.Fatal("MISSING_REQUIREMENT is missing from the reason-code registry")
}

func TestProtoCounterfactualCannotExpressAmbiguousShapes(t *testing.T) {
	raw, err := os.ReadFile("../../../protocols/policy-schema/v1/verdict.proto")
	if err != nil {
		t.Fatal(err)
	}
	block := protoMessageBlock(t, string(raw), "DenialCounterfactual")
	for _, want := range []string{
		"oneof envelope",
		"DenialScalarBound scalar_bound = 1;",
		"DenialRequiredCapability required_capability = 2;",
		"denial_counterfactual.envelope_required",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("DenialCounterfactual is missing %q", want)
		}
	}
	scalar := protoMessageBlock(t, string(raw), "DenialScalarBound")
	if !strings.Contains(scalar, "denial_scalar_bound.complete") {
		t.Error("DenialScalarBound is missing non-empty semantic validation")
	}
	if !strings.Contains(scalar, "this.requested > this.max") {
		t.Error("DenialScalarBound does not require requested to exceed max")
	}
	for _, forbidden := range []string{
		"string field =",
		"int64 requested =",
		"int64 max =",
		"string capability =",
	} {
		if strings.Contains(block, forbidden) {
			t.Errorf("DenialCounterfactual still exposes ambiguous flat field %q", forbidden)
		}
	}
}

func TestProtoCounterfactualUsesFixedCapabilityVocabulary(t *testing.T) {
	raw, err := os.ReadFile("../../../protocols/policy-schema/v1/verdict.proto")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	block := protoMessageBlock(t, source, "DenialRequiredCapability")
	if !strings.Contains(block, "WorkstationPermission capability = 2") {
		t.Fatal("DenialRequiredCapability does not use the fixed workstation permission enum")
	}
	for _, rule := range []string{"defined_only: true", "not_in: [0]"} {
		if !strings.Contains(block, rule) {
			t.Errorf("DenialRequiredCapability is missing validation rule %q", rule)
		}
	}
	for _, value := range []string{
		"NETWORK_EGRESS",
		"MCP_MUTATE",
		"MEMORY_WRITE",
		"LOOP_REGISTER",
		"SHELL_OPERATE",
		"DEPLOY_PUBLISH",
		"SECRET_READ",
		"PAYMENT_INITIATE",
	} {
		if !strings.Contains(source, "WORKSTATION_PERMISSION_"+value) {
			t.Errorf("WorkstationPermission is missing %s", value)
		}
	}
}

func protoMessageBlock(t *testing.T, source, name string) string {
	t.Helper()
	start := strings.Index(source, "message "+name+" {")
	if start < 0 {
		t.Fatalf("proto message %s not found", name)
	}
	depth := 0
	for i := start; i < len(source); i++ {
		switch source[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return source[start : i+1]
			}
		}
	}
	t.Fatalf("proto message %s is not closed", name)
	return ""
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
