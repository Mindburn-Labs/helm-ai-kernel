package riskenvelope

import (
	"bytes"
	"encoding/hex"
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
	saltA := bytes.Repeat([]byte{0x01}, SaltBytes)
	saltB := bytes.Repeat([]byte{0x02}, SaltBytes)

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

func TestSaltFileIsGeneratedLocalOnlyAndStrict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan_salt.hex")
	salt, err := LoadOrCreateSaltFile(path)
	if err != nil {
		t.Fatalf("load/create salt: %v", err)
	}
	if len(salt) != SaltBytes {
		t.Fatalf("salt length = %d, want %d", len(salt), SaltBytes)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat salt: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("salt mode = %o, want 0600", got)
	}
	again, err := LoadOrCreateSaltFile(path)
	if err != nil {
		t.Fatalf("reload salt: %v", err)
	}
	if !bytes.Equal(salt, again) {
		t.Fatal("salt file reload returned different bytes")
	}

	weak := filepath.Join(t.TempDir(), "weak.hex")
	if err := os.WriteFile(weak, []byte(hex.EncodeToString(bytes.Repeat([]byte{0x03}, 16))), 0o600); err != nil {
		t.Fatalf("write weak salt: %v", err)
	}
	if _, err := LoadOrCreateSaltFile(weak); err == nil {
		t.Fatal("weak salt file should be rejected")
	}

	loose := filepath.Join(t.TempDir(), "loose.hex")
	if err := os.WriteFile(loose, []byte(hex.EncodeToString(bytes.Repeat([]byte{0x04}, SaltBytes))), 0o644); err != nil {
		t.Fatalf("write loose salt: %v", err)
	}
	if _, err := LoadOrCreateSaltFile(loose); err == nil {
		t.Fatal("group/world-readable salt file should be rejected")
	}
}

func TestRiskEnvelopeValidateRejectsRawIdentifiersAndCollection(t *testing.T) {
	valid := validEnvelope(t)
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}

	rawResource := validEnvelope(t)
	rawResource.Findings[0].ResourceID = "github.com/customer/private-game"
	if err := rawResource.Validate(); err == nil {
		t.Fatal("raw resource identifier should be rejected")
	}

	collectedSource := validEnvelope(t)
	collectedSource.Privacy.SourceCodeCollected = true
	if err := collectedSource.Validate(); err == nil {
		t.Fatal("source_code_collected=true should be rejected")
	}

	rawPermission := validEnvelope(t)
	rawPermission.Posture.PermissionMode = PermissionMode("accept all writes please")
	if err := rawPermission.Validate(); err == nil {
		t.Fatal("free-text permission mode should be rejected")
	}

	nilFindings := validEnvelope(t)
	nilFindings.Findings = nil
	if err := nilFindings.Validate(); err == nil {
		t.Fatal("nil findings should be rejected; wire form must be [] not null")
	}

	nilBuckets := validEnvelope(t)
	nilBuckets.Posture.OAuthScopeBuckets = nil
	if err := nilBuckets.Validate(); err == nil {
		t.Fatal("nil bucket slices should be rejected; wire form must be [] not null")
	}

	negativeSuppression := validEnvelope(t)
	negativeSuppression.Posture.SuppressedFindingCount = -1
	if err := negativeSuppression.Validate(); err == nil {
		t.Fatal("negative suppression count should be rejected")
	}
}

func TestRiskEnvelopeContentHashBindsFindings(t *testing.T) {
	valid := validEnvelope(t)
	hash := valid.EnvelopeContentHash

	modified := valid
	modified.Findings = append([]EnvelopeFinding(nil), valid.Findings...)
	modified.Findings[0].RiskCode = RiskNoAuditExport
	newHash, err := modified.ContentHash()
	if err != nil {
		t.Fatalf("content hash: %v", err)
	}
	if newHash == hash {
		t.Fatal("content hash should change when findings change")
	}
	modified.EnvelopeContentHash = hash
	if err := modified.Validate(); err == nil {
		t.Fatal("modified envelope with old content hash should be rejected")
	}
}

func TestRiskEnvelopeSchemaAlignment(t *testing.T) {
	schema := compileRiskEnvelopeSchema(t)
	raw := marshalEnvelopeForSchema(t, validEnvelope(t))
	if err := schema.Validate(raw); err != nil {
		t.Fatalf("valid envelope rejected by schema: %v", err)
	}
}

func TestRiskEnvelopeSchemaEnumParity(t *testing.T) {
	raw := loadRiskEnvelopeSchema(t)
	assertSchemaEnum(t, raw, []string{"$defs", "finding", "properties", "resource_type", "enum"}, stringValues(ResourceRepo, ResourceMCPServer, ResourceWorkflow, ResourceSecretClass, ResourcePermissionProfile, ResourceEnvironment, ResourceOAuthClient, ResourceIAMPrincipal))
	assertSchemaEnum(t, raw, []string{"$defs", "finding", "properties", "risk_code", "enum"}, stringValues(RiskAgentWriteWithoutEnvApproval, RiskBroadShellAllow, RiskBypassPermissionsEnabled, RiskMCPWriteScopeWithoutApproval, RiskProdEnvWithoutReviewers, RiskSecretClassAgentReadable, RiskDirectDispatchSeen, RiskNoManagedSettings, RiskNoAuditExport, RiskNoBranchProtection, RiskSchemaPinMissing, RiskIAMAdminGrantVisible, RiskOAuthHighRiskScope, RiskCIWorkflowWriteToken))
	assertSchemaEnum(t, raw, []string{"$defs", "finding", "properties", "severity", "enum"}, stringValues(SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical))
	assertSchemaEnum(t, raw, []string{"$defs", "evidence", "properties", "agent_tool", "enum"}, stringValues(ToolClassUnknown, ToolClassGitPush, ToolClassGitWrite, ToolClassDBWrite, ToolClassMCPWrite, ToolClassMCPRead, ToolClassDeployPublish, ToolClassSecretRead, ToolClassPaymentInitiate, ToolClassShellOperate, ToolClassNetworkEgress, ToolClassWorkflowDispatch))
	assertSchemaEnum(t, raw, []string{"$defs", "posture", "properties", "agent_surface", "enum"}, stringValues(AgentSurfaceUnknown, AgentSurfaceClaudeCode, AgentSurfaceCodex, AgentSurfaceGitHubActions, AgentSurfaceMCP))
	assertSchemaEnum(t, raw, []string{"$defs", "posture", "properties", "permission_mode", "enum"}, stringValues(PermissionModeUnknown, PermissionModePlan, PermissionModeAsk, PermissionModeAcceptEdits, PermissionModeBypassPermissions))
	assertSchemaEnum(t, raw, []string{"$defs", "oauth_scope_bucket_count", "properties", "bucket", "enum"}, stringValues(OAuthScopeNone, OAuthScopeRead, OAuthScopeWrite, OAuthScopeAdmin, OAuthScopeRepo, OAuthScopeWorkflow, OAuthScopeCloud, OAuthScopeDB, OAuthScopeUnknown))
	assertSchemaEnum(t, raw, []string{"$defs", "iam_grant_bucket_count", "properties", "bucket", "enum"}, stringValues(IAMGrantNone, IAMGrantRead, IAMGrantWrite, IAMGrantAdmin, IAMGrantCloud, IAMGrantDeploy, IAMGrantBilling, IAMGrantUnknown))
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
		"RiskEnvelope.SchemaVersion":       true,
		"RiskEnvelope.EnvelopeID":          true,
		"RiskEnvelope.EnvelopeContentHash": true,
		"RiskEnvelope.SourcePackHash":      true,
		"EnvelopeFinding.ResourceID":       true,
	}
	walkEnvelopeType(t, reflect.TypeOf(RiskEnvelope{}), allowedPlainStrings, map[reflect.Type]bool{})
}

func validEnvelope(t *testing.T) RiskEnvelope {
	t.Helper()
	salt := bytes.Repeat([]byte{0x01}, SaltBytes)
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

	envelope := RiskEnvelope{
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
			StaticConfigFilesRead:  4,
			MetadataAPICalls:       7,
			SuppressedFindingCount: 0,
			KAnonymityFloor:        0,
		},
		Privacy:     PrivacyNonCollection{},
		GeneratedAt: time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC),
	}
	sealed, err := Seal(envelope)
	if err != nil {
		t.Fatalf("seal envelope: %v", err)
	}
	return sealed
}

func compileRiskEnvelopeSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	data, schemaPath := readRiskEnvelopeSchema(t)
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

func loadRiskEnvelopeSchema(t *testing.T) map[string]any {
	t.Helper()
	data, _ := readRiskEnvelopeSchema(t)
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	return raw
}

func readRiskEnvelopeSchema(t *testing.T) ([]byte, string) {
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
	return data, schemaPath
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

func assertSchemaEnum(t *testing.T, root map[string]any, path []string, want []string) {
	t.Helper()
	var node any = root
	for _, part := range path {
		obj, ok := node.(map[string]any)
		if !ok {
			t.Fatalf("schema path %v does not point to object at %q", path, part)
		}
		node = obj[part]
	}
	raw, ok := node.([]any)
	if !ok {
		t.Fatalf("schema path %v is not enum array", path)
	}
	got := make([]string, 0, len(raw))
	for _, item := range raw {
		value, ok := item.(string)
		if !ok {
			t.Fatalf("schema enum %v has non-string item %T", path, item)
		}
		got = append(got, value)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("schema enum %v mismatch\ngot:  %#v\nwant: %#v", path, got, want)
	}
}

func stringValues[T ~string](values ...T) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}
