package admission

// quantum_posture: validates the SHA-256-bound outcome binding document
// against its JSON schema; no signature is made and no post-quantum claim.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

func outcomeBindingSchema(t *testing.T) (*jsonschema.Schema, map[string]any) {
	t.Helper()
	path, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "protocols", "json-schemas", "gateway", "outcome-binding.v1.schema.json"))
	must(t, err)
	raw, err := os.ReadFile(path) // #nosec G304 -- repository schema path
	must(t, err)
	var document map[string]any
	must(t, json.Unmarshal(raw, &document))
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	compiler.AssertFormat = true
	url := "file:///" + strings.ReplaceAll(path, string(filepath.Separator), "/")
	must(t, compiler.AddResource(url, bytes.NewReader(raw)))
	schema, err := compiler.Compile(url)
	must(t, err)
	return schema, document
}

// jsonMembers lists the JSON member names a struct type encodes.
func jsonMembers(typ reflect.Type) []string {
	var out []string
	for i := 0; i < typ.NumField(); i++ {
		out = append(out, strings.Split(typ.Field(i).Tag.Get("json"), ",")[0])
	}
	sort.Strings(out)
	return out
}

func schemaMembers(t *testing.T, object map[string]any) []string {
	t.Helper()
	var out []string
	for _, name := range object["required"].([]any) {
		out = append(out, name.(string))
	}
	sort.Strings(out)
	properties := object["properties"].(map[string]any)
	if len(properties) != len(out) {
		t.Fatalf("schema lists %d properties and requires %d", len(properties), len(out))
	}
	return out
}

// TestOutcomeBindingMatchesItsSchema: the verifier's one definition of
// helm.gateway.outcome-binding.v1 has exactly the members its schema
// requires, at every level, and the frozen chain's outcome binding (and the
// same binding with a model call's money row) is valid under the schema.
func TestOutcomeBindingMatchesItsSchema(t *testing.T) {
	schema, document := outcomeBindingSchema(t)
	properties := document["properties"].(map[string]any)
	for name, pair := range map[string]struct {
		typ    reflect.Type
		object map[string]any
	}{
		"binding":     {reflect.TypeOf(receiptverify.GatewayOutcomeBinding{}), document},
		"observation": {reflect.TypeOf(receiptverify.GatewayOutcomeObservation{}), properties["observation"].(map[string]any)},
		"exposure":    {reflect.TypeOf(receiptverify.GatewayOutcomeExposure{}), properties["exposures"].(map[string]any)["items"].(map[string]any)},
		"model call":  {reflect.TypeOf(receiptverify.GatewayOutcomeModelCall{}), properties["model_call"].(map[string]any)["oneOf"].([]any)[1].(map[string]any)},
	} {
		if got, want := jsonMembers(pair.typ), schemaMembers(t, pair.object); !reflect.DeepEqual(got, want) {
			t.Errorf("%s members %v, schema %v", name, got, want)
		}
	}

	decisions := frozenGatewayDecisions()
	_, binding := frozenGatewayOutcome(t, decisions[2], "0190a5b4-0000-7000-8000-0000000000f4", 4, sampleHead)
	parsed, err := receiptverify.ParseGatewayOutcomeBinding(binding)
	must(t, err)
	var instance any
	must(t, json.Unmarshal(binding, &instance))
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("the frozen outcome binding does not match its schema: %v", err)
	}
	model := parsed
	model.SettledBy = "model_call"
	model.ModelCall = &receiptverify.GatewayOutcomeModelCall{State: "CONFIRMED", CurrencyCode: "USD", HeldMicros: "900", ConfirmedMicros: "640",
		BillableMicros: "640", UsageDigest: strings.Repeat("ab", 32)}
	raw, err := json.Marshal(model)
	must(t, err)
	must(t, json.Unmarshal(raw, &instance))
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("an outcome binding with a model call does not match its schema: %v", err)
	}
	// Known bad: the schema refuses what the verifier refuses.
	instance.(map[string]any)["model_call"].(map[string]any)["currency_code"] = "usd"
	if err := schema.Validate(instance); err == nil {
		t.Fatal("the outcome schema accepted a lower-case currency code")
	}
	instance.(map[string]any)["model_call"].(map[string]any)["currency_code"] = "USD"
	instance.(map[string]any)["verdict"] = "ALLOW"
	if err := schema.Validate(instance); err == nil {
		t.Fatal("the outcome schema accepted a verdict member")
	}
}
