package extauthz

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestContractFieldsStayInParityAcrossSchemaProtoAndGo(t *testing.T) {
	root := repoRoot(t)
	schema := loadSchema(t, filepath.Join(root, "protocols", "json-schemas", "boundary", "extauthz.v1.schema.json"))
	proto := readText(t, filepath.Join(root, "protocols", "proto", "boundary", "extauthz", "v1", "extauthz.proto"))

	requestSchema := schemaDefFields(t, schema, "request")
	responseSchema := schemaDefFields(t, schema, "response")

	assertSetEqual(t, "Go request vs schema request", jsonStructFields(reflect.TypeOf(AuthorizationRequest{})), requestSchema)
	assertSetEqual(t, "Go response vs schema response", jsonStructFields(reflect.TypeOf(AuthorizationResponse{})), responseSchema)
	assertSetEqual(t, "proto request vs schema request", protoMessageFields(t, proto, "AuthorizationRequest"), requestSchema)
	assertSetEqual(t, "proto response vs schema response", protoMessageFields(t, proto, "AuthorizationResponse"), responseSchema)

	for _, field := range []string{"effect_receipt_ref", "evidence_pack_ref", "proof_graph_edge_ref", "final_evidence_ref", "receipt_ref"} {
		assertAbsent(t, field, requestSchema, responseSchema, protoMessageFields(t, proto, "AuthorizationRequest"), protoMessageFields(t, proto, "AuthorizationResponse"))
	}
}

func TestContractConstantsStayInParity(t *testing.T) {
	root := repoRoot(t)
	schema := loadSchema(t, filepath.Join(root, "protocols", "json-schemas", "boundary", "extauthz.v1.schema.json"))
	if got := stringConst(t, schema, "schema_version"); got != SchemaVersionV1 {
		t.Fatalf("schema_version mismatch: schema=%s go=%s", got, SchemaVersionV1)
	}
	if got := stringConst(t, schema, "contract_version"); got != ContractVersionV1 {
		t.Fatalf("contract_version mismatch: schema=%s go=%s", got, ContractVersionV1)
	}
	proto := readText(t, filepath.Join(root, "protocols", "proto", "boundary", "extauthz", "v1", "extauthz.proto"))
	for _, verdict := range []string{"ALLOW", "DENY", "ESCALATE"} {
		if !strings.Contains(proto, "VERDICT_"+verdict) {
			t.Fatalf("proto missing verdict %s", verdict)
		}
	}
	for _, protocol := range []string{"MCP", "A2A", "HTTP", "GRPC", "OPENAI"} {
		if !strings.Contains(proto, "PROTOCOL_"+protocol) {
			t.Fatalf("proto missing protocol %s", protocol)
		}
	}
}

func TestContractEncodingSemanticsStayInParity(t *testing.T) {
	root := repoRoot(t)
	schema := loadSchema(t, filepath.Join(root, "protocols", "json-schemas", "boundary", "extauthz.v1.schema.json"))
	proto := readText(t, filepath.Join(root, "protocols", "proto", "boundary", "extauthz", "v1", "extauthz.proto"))

	responseProtoTypes := protoMessageFieldTypes(t, proto, "AuthorizationResponse")
	requestProtoTypes := protoMessageFieldTypes(t, proto, "AuthorizationRequest")
	requestProperties := schemaDefProperties(t, schema, "request")
	responseProperties := schemaDefProperties(t, schema, "response")

	assertGoFieldType(t, AuthorizationResponse{}, "kernel_verdict_signature", "string")
	assertSchemaPattern(t, responseProperties, "kernel_verdict_signature", "^[a-f0-9]{128}$")
	if responseProtoTypes["kernel_verdict_signature"] != "bytes" {
		t.Fatalf("kernel_verdict_signature proto type must be bytes, got %s", responseProtoTypes["kernel_verdict_signature"])
	}

	assertGoFieldType(t, AuthorizationResponse{}, "kernel_verdict_hash", "string")
	assertSchemaPattern(t, responseProperties, "kernel_verdict_hash", "^[a-f0-9]{64}$")
	if responseProtoTypes["kernel_verdict_hash"] != "string" {
		t.Fatalf("kernel_verdict_hash proto type must be string, got %s", responseProtoTypes["kernel_verdict_hash"])
	}

	for _, field := range []string{"kernel_verdict_issued_at", "kernel_verdict_expires_at", "permit_expiry"} {
		assertGoFieldType(t, AuthorizationResponse{}, field, "string")
		assertSchemaFormat(t, responseProperties, field, "date-time")
		if responseProtoTypes[field] != "google.protobuf.Timestamp" {
			t.Fatalf("%s proto type must be google.protobuf.Timestamp, got %s", field, responseProtoTypes[field])
		}
	}

	hashFields := []string{"connector_contract_hash", "args_c14n_hash", "request_body_hash", "plan_hash", "policy_hash", "p0_hash", "risk_context_hash"}
	for _, field := range hashFields {
		assertGoFieldType(t, AuthorizationRequest{}, field, "string")
		assertGoFieldType(t, AuthorizationResponse{}, field, "string")
		assertSchemaRef(t, requestProperties, field, "#/$defs/hash")
		assertSchemaRef(t, responseProperties, field, "#/$defs/hash")
		if requestProtoTypes[field] != "string" {
			t.Fatalf("request %s proto type must be string, got %s", field, requestProtoTypes[field])
		}
		if responseProtoTypes[field] != "string" {
			t.Fatalf("response %s proto type must be string, got %s", field, responseProtoTypes[field])
		}
	}

	hashDef := schema["$defs"].(map[string]any)["hash"].(map[string]any)
	if got := hashDef["pattern"].(string); got != "^sha256:[a-f0-9]{64}$" {
		t.Fatalf("hash schema pattern mismatch: %s", got)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Clean(filepath.Join(dir, "..", "..", "..", ".."))
}

func loadSchema(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	return schema
}

func readText(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func stringConst(t *testing.T, schema map[string]any, field string) string {
	t.Helper()
	properties := schema["properties"].(map[string]any)
	spec := properties[field].(map[string]any)
	return spec["const"].(string)
}

func schemaDefFields(t *testing.T, schema map[string]any, def string) []string {
	t.Helper()
	properties := schemaDefProperties(t, schema, def)
	fields := make([]string, 0, len(properties))
	for field := range properties {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	return fields
}

func schemaDefProperties(t *testing.T, schema map[string]any, def string) map[string]any {
	t.Helper()
	defs := schema["$defs"].(map[string]any)
	entry := defs[def].(map[string]any)
	return entry["properties"].(map[string]any)
}

func jsonStructFields(typ reflect.Type) []string {
	fields := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name != "" && name != "-" {
			fields = append(fields, name)
		}
	}
	sort.Strings(fields)
	return fields
}

func protoMessageFields(t *testing.T, source, message string) []string {
	t.Helper()
	fieldTypes := protoMessageFieldTypes(t, source, message)
	fields := make([]string, 0, len(fieldTypes))
	for field := range fieldTypes {
		fields = append(fields, field)
	}
	sort.Strings(fields)
	return fields
}

func protoMessageFieldTypes(t *testing.T, source, message string) map[string]string {
	t.Helper()
	messagePattern := regexp.MustCompile(`(?s)message\s+` + regexp.QuoteMeta(message) + `\s*\{(.*?)\n\}`)
	match := messagePattern.FindStringSubmatch(source)
	if len(match) != 2 {
		t.Fatalf("proto missing message %s", message)
	}
	fieldPattern := regexp.MustCompile(`(?m)^\s*(?:string|uint64|bytes|Verdict|Protocol|google\.protobuf\.(?:Timestamp|Struct))\s+([a-z0-9_]+)\s*=\s*\d+;`)
	typedFieldPattern := regexp.MustCompile(`(?m)^\s*((?:string|uint64|bytes|Verdict|Protocol|google\.protobuf\.(?:Timestamp|Struct)))\s+([a-z0-9_]+)\s*=\s*\d+;`)
	if matches := fieldPattern.FindAllStringSubmatch(match[1], -1); len(matches) == 0 {
		t.Fatalf("proto message %s has no typed fields", message)
	}
	types := make(map[string]string)
	for _, fieldMatch := range typedFieldPattern.FindAllStringSubmatch(match[1], -1) {
		types[fieldMatch[2]] = fieldMatch[1]
	}
	return types
}

func assertSetEqual(t *testing.T, name string, got, want []string) {
	t.Helper()
	sort.Strings(got)
	sort.Strings(want)
	gotText := strings.Join(got, "\n")
	wantText := strings.Join(want, "\n")
	if gotText != wantText {
		t.Fatalf("%s mismatch:\ngot:\n%s\nwant:\n%s", name, gotText, wantText)
	}
}

func assertAbsent(t *testing.T, field string, fieldSets ...[]string) {
	t.Helper()
	for _, fields := range fieldSets {
		if sort.SearchStrings(fields, field) < len(fields) && fields[sort.SearchStrings(fields, field)] == field {
			t.Fatalf("forbidden pre-dispatch field present: %s", field)
		}
	}
}

func assertGoFieldType(t *testing.T, value any, jsonField, want string) {
	t.Helper()
	typ := reflect.TypeOf(value)
	for i := 0; i < typ.NumField(); i++ {
		tag := typ.Field(i).Tag.Get("json")
		if strings.Split(tag, ",")[0] == jsonField {
			if got := typ.Field(i).Type.String(); got != want {
				t.Fatalf("%s Go field type mismatch: got %s want %s", jsonField, got, want)
			}
			return
		}
	}
	t.Fatalf("Go field not found for json tag %s", jsonField)
}

func assertSchemaPattern(t *testing.T, properties map[string]any, field, want string) {
	t.Helper()
	entry := properties[field].(map[string]any)
	if got := entry["pattern"].(string); got != want {
		t.Fatalf("%s schema pattern mismatch: got %s want %s", field, got, want)
	}
}

func assertSchemaFormat(t *testing.T, properties map[string]any, field, want string) {
	t.Helper()
	entry := properties[field].(map[string]any)
	if got := entry["format"].(string); got != want {
		t.Fatalf("%s schema format mismatch: got %s want %s", field, got, want)
	}
}

func assertSchemaRef(t *testing.T, properties map[string]any, field, want string) {
	t.Helper()
	entry := properties[field].(map[string]any)
	if got := entry["$ref"].(string); got != want {
		t.Fatalf("%s schema ref mismatch: got %s want %s", field, got, want)
	}
}
