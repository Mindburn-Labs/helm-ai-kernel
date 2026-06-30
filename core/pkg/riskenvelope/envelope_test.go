package riskenvelope

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

func TestPseudonymIsDeterministicAndSalted(t *testing.T) {
	saltA := []byte("0123456789abcdef")
	saltB := []byte("abcdef0123456789")

	first, err := Pseudonym(saltA, "repo:customer/private-game")
	if err != nil {
		t.Fatalf("pseudonym: %v", err)
	}
	second, err := Pseudonym(saltA, "repo:customer/private-game")
	if err != nil {
		t.Fatalf("pseudonym second: %v", err)
	}
	otherSalt, err := Pseudonym(saltB, "repo:customer/private-game")
	if err != nil {
		t.Fatalf("pseudonym other salt: %v", err)
	}

	if first != second {
		t.Fatalf("same salt and raw id must be deterministic: %q != %q", first, second)
	}
	if first == otherSalt {
		t.Fatalf("different salts must not correlate: %q", first)
	}
	if !hmacRefPattern.MatchString(first) {
		t.Fatalf("pseudonym must be an hmac ref, got %q", first)
	}
}

func TestRiskEnvelopeValidateRejectsRawIdentifiersAndCollection(t *testing.T) {
	valid := validEnvelope(t)
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}

	rawResource := valid
	rawResource.Findings[0].ResourceID = "github.com/customer/private-game"
	if err := rawResource.Validate(); err == nil {
		t.Fatal("raw resource identifier should be rejected")
	}

	collectedSource := valid
	collectedSource.Privacy.SourceCodeCollected = true
	if err := collectedSource.Validate(); err == nil {
		t.Fatal("source_code_collected=true should be rejected")
	}

	rawPermission := valid
	rawPermission.Posture.PermissionMode = PermissionMode("accept all writes please")
	if err := rawPermission.Validate(); err == nil {
		t.Fatal("free-text permission mode should be rejected")
	}

	nilFindings := valid
	nilFindings.Findings = nil
	if err := nilFindings.Validate(); err == nil {
		t.Fatal("nil findings should be rejected; wire form must be [] not null")
	}

	nilBuckets := valid
	nilBuckets.Posture.OAuthScopeBuckets = nil
	if err := nilBuckets.Validate(); err == nil {
		t.Fatal("nil bucket slices should be rejected; wire form must be [] not null")
	}
}

func TestRiskEnvelopeSchemaAlignment(t *testing.T) {
	schema := compileRiskEnvelopeSchema(t)
	raw := marshalEnvelopeForSchema(t, validEnvelope(t))
	if err := schema.Validate(raw); err != nil {
		t.Fatalf("valid envelope rejected by schema: %v", err)
	}
}

func TestRiskEnvelopeSchemaRejectsFreeTextProjectionFields(t *testing.T) {
	schema := compileRiskEnvelopeSchema(t)

	withPath := marshalEnvelopeForSchema(t, validEnvelope(t))
	withPath["path"] = "/Users/customer/private-game/.mcp.json"
	if err := schema.Validate(withPath); err == nil {
		t.Fatal("top-level path field should be rejected")
	}

	withRawEvidence := marshalEnvelopeForSchema(t, validEnvelope(t))
	findings := withRawEvidence["findings"].([]any)
	finding := findings[0].(map[string]any)
	evidence := finding["evidence"].(map[string]any)
	evidence["raw_evidence"] = "sk-live-customer-secret"
	if err := schema.Validate(withRawEvidence); err == nil {
		t.Fatal("raw evidence field should be rejected")
	}

	withPrivacyLeak := marshalEnvelopeForSchema(t, validEnvelope(t))
	privacy := withPrivacyLeak["privacy"].(map[string]any)
	privacy["command_bodies_exported"] = true
	if err := schema.Validate(withPrivacyLeak); err == nil {
		t.Fatal("privacy collection flag set to true should be rejected")
	}
}

func TestRiskEnvelopeTypeHasNoPlainFreeTextSinks(t *testing.T) {
	allowedPlainStrings := map[string]bool{
		"RiskEnvelope.SchemaVersion":  true,
		"RiskEnvelope.EnvelopeID":     true,
		"RiskEnvelope.SourcePackHash": true,
		"EnvelopeFinding.ResourceID":  true,
	}
	walkEnvelopeType(t, reflect.TypeOf(RiskEnvelope{}), allowedPlainStrings, map[reflect.Type]bool{})
}

func validEnvelope(t *testing.T) RiskEnvelope {
	t.Helper()
	salt := []byte("0123456789abcdef")
	sourcePackHash := SHA256Ref([]byte("local scan pack"))
	envelopeID, err := EnvelopeID(salt, sourcePackHash)
	if err != nil {
		t.Fatalf("envelope id: %v", err)
	}
	resourceID, err := Pseudonym(salt, "repo:customer/private-game")
	if err != nil {
		t.Fatalf("resource id: %v", err)
	}
	branchProtection := false
	reviewers := 0
	mcpWriteScopes := true
	managedSettings := false
	auditLogging := false

	return RiskEnvelope{
		SchemaVersion:  SchemaVersion,
		EnvelopeID:     envelopeID,
		CohortBucket:   CohortRepos11To50,
		SourcePackHash: sourcePackHash,
		Findings: []EnvelopeFinding{
			{
				ResourceID:   resourceID,
				ResourceType: ResourceRepo,
				RiskCode:     RiskAgentWriteWithoutEnvApproval,
				Severity:     SeverityHigh,
				Evidence: EnvelopeEvidence{
					AgentTool:        ToolClassGitPush,
					PermissionMode:   PermissionModeAcceptEdits,
					BranchProtection: &branchProtection,
					ProdEnvReviewers: &reviewers,
					MCPWriteScopes:   &mcpWriteScopes,
					ManagedSettings:  &managedSettings,
					AuditLogging:     &auditLogging,
				},
			},
		},
		Posture: PostureProbe{
			AgentSurface:           AgentSurfaceClaudeCode,
			PermissionMode:         PermissionModeAcceptEdits,
			ManagedSettingsPresent: false,
			MCPServerCount:         3,
			OAuthScopeBuckets: []OAuthScopeBucketCount{
				{Bucket: OAuthScopeRead, Count: 4},
				{Bucket: OAuthScopeWrite, Count: 2},
			},
			IAMGrantBuckets: []IAMGrantBucketCount{
				{Bucket: IAMGrantRead, Count: 2},
			},
			StaticConfigFilesRead: 4,
			MetadataAPICalls:      7,
		},
		Privacy:     PrivacyNonCollection{},
		GeneratedAt: time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC),
	}
}

func compileRiskEnvelopeSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
	schemaPath := filepath.Join(root, "protocols", "json-schemas", "risk-envelope", "v1.json")
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	url := "file:///" + strings.ReplaceAll(schemaPath, string(filepath.Separator), "/")
	if err := compiler.AddResource(url, strings.NewReader(string(data))); err != nil {
		t.Fatalf("add schema resource: %v", err)
	}
	schema, err := compiler.Compile(url)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return schema
}

func marshalEnvelopeForSchema(t *testing.T, envelope RiskEnvelope) map[string]any {
	t.Helper()
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	return raw
}

func walkEnvelopeType(t *testing.T, typ reflect.Type, allowedPlainStrings map[string]bool, seen map[reflect.Type]bool) {
	t.Helper()
	for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
		typ = typ.Elem()
	}
	if typ == reflect.TypeOf(time.Time{}) {
		return
	}
	if seen[typ] {
		return
	}
	seen[typ] = true

	switch typ.Kind() {
	case reflect.Map, reflect.Interface:
		t.Fatalf("risk envelope must not expose map/interface sinks: %s", typ)
	case reflect.Struct:
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			fieldPath := typ.Name() + "." + field.Name
			fieldType := field.Type
			for fieldType.Kind() == reflect.Pointer || fieldType.Kind() == reflect.Slice || fieldType.Kind() == reflect.Array {
				fieldType = fieldType.Elem()
			}
			if fieldType.Kind() == reflect.String && fieldType.Name() == "string" && !allowedPlainStrings[fieldPath] {
				t.Fatalf("plain string field %s would allow free-text upload", fieldPath)
			}
			walkEnvelopeType(t, field.Type, allowedPlainStrings, seen)
		}
	}
}
