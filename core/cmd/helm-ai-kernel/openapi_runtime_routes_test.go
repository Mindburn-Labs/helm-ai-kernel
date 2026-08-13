package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"gopkg.in/yaml.v3"
)

func TestOpenAPIPathsAreRegisteredByHelmServeRuntime(t *testing.T) {
	chdirTempDir(t)

	mux := http.NewServeMux()
	svc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	RegisterSubsystemRoutes(mux, svc)
	RegisterConsoleRoutes(mux, svc, serverOptions{Mode: "serve", PolicyPath: "policy.toml"})
	RegisterLocalFirstRunRoutes(mux, svc, serverOptions{Mode: "quickstart", BindAddr: "127.0.0.1", Port: 7714, Quickstart: quickstartRouteRuntime()})

	for _, spec := range PublicRuntimeRouteSpecs() {
		path := representativeRuntimePath(spec.Path)
		req, err := http.NewRequest(spec.Method, "http://helm.test"+path, nil)
		if err != nil {
			t.Fatalf("build request for %s %s: %v", spec.Method, spec.Path, err)
		}
		_, pattern := mux.Handler(req)
		if pattern == "" {
			t.Fatalf("registered route %s %s is not mounted by helm-ai-kernel serve runtime", spec.Method, spec.Path)
		}
	}
}

func TestRuntimeRouteRegistryMatchesOpenAPI(t *testing.T) {
	operations := readOpenAPIOperations(t)
	registry := map[string]RuntimeRouteSpec{}
	for _, spec := range PublicRuntimeRouteSpecs() {
		key := spec.Method + " " + spec.Path
		if existing, ok := registry[key]; ok {
			t.Fatalf("duplicate public route registry entry %s: %s and %s", key, existing.OperationID, spec.OperationID)
		}
		registry[key] = spec
	}

	for key, operationID := range operations {
		registered, ok := registry[key]
		if !ok {
			t.Fatalf("OpenAPI operation %s is missing from runtime route registry", key)
		}
		if registered.OperationID != operationID {
			t.Fatalf("operationId drift for %s: registry=%s openapi=%s", key, registered.OperationID, operationID)
		}
	}
	for key, registered := range registry {
		operationID, ok := operations[key]
		if !ok {
			t.Fatalf("public runtime route %s (%s) is missing from OpenAPI", key, registered.OperationID)
		}
		if operationID != registered.OperationID {
			t.Fatalf("operationId drift for %s: registry=%s openapi=%s", key, registered.OperationID, operationID)
		}
	}
}

func TestPublicDocsOpenAPIContract(t *testing.T) {
	root := openAPIRepositoryRoot(t)
	manifestData, err := os.ReadFile(filepath.Join(root, "docs", "public-docs.manifest.json"))
	if err != nil {
		t.Fatalf("read public docs manifest: %v", err)
	}
	var manifest publicDocsManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatalf("parse public docs manifest: %v", err)
	}
	contract := manifest.APIContract
	if contract.SchemaVersion != 1 {
		t.Fatalf("public docs API contract schema_version=%d, want 1", contract.SchemaVersion)
	}
	if contract.SourcePath != "api/openapi/helm.openapi.yaml" {
		t.Fatalf("public docs API contract source_path=%q", contract.SourcePath)
	}
	if len(contract.PublicOperations) == 0 {
		t.Fatal("public docs API contract has no public operations")
	}

	openAPIData, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(contract.SourcePath)))
	if err != nil {
		t.Fatalf("read public OpenAPI source: %v", err)
	}
	digest := sha256.Sum256(openAPIData)
	if got, want := contract.ContentSHA256, "sha256:"+hex.EncodeToString(digest[:]); got != want {
		t.Fatalf("public docs API contract content_sha256=%q, want %q", got, want)
	}

	openAPIOperations := readOpenAPIOperations(t)
	runtimeRoutes := make(map[string]RuntimeRouteSpec, len(PublicRuntimeRouteSpecs()))
	for _, spec := range PublicRuntimeRouteSpecs() {
		key := spec.Method + " " + spec.Path
		if existing, exists := runtimeRoutes[key]; exists {
			t.Fatalf("duplicate public runtime route %s: %s and %s", key, existing.OperationID, spec.OperationID)
		}
		runtimeRoutes[key] = spec
	}

	seenRoutes := map[string]struct{}{}
	seenOperationIDs := map[string]struct{}{}
	for _, expected := range contract.PublicOperations {
		if expected.Method != strings.ToUpper(expected.Method) || expected.Path == "" || expected.OperationID == "" {
			t.Fatalf("invalid public docs API contract operation: %+v", expected)
		}
		key := expected.Method + " " + expected.Path
		if _, exists := seenRoutes[key]; exists {
			t.Fatalf("duplicate public docs API contract route %s", key)
		}
		seenRoutes[key] = struct{}{}
		if _, exists := seenOperationIDs[expected.OperationID]; exists {
			t.Fatalf("duplicate public docs API contract operationId %q", expected.OperationID)
		}
		seenOperationIDs[expected.OperationID] = struct{}{}

		if got, exists := openAPIOperations[key]; !exists {
			t.Fatalf("public docs API contract route %s is missing from OpenAPI", key)
		} else if got != expected.OperationID {
			t.Fatalf("public docs API contract operationId drift for %s: manifest=%s openapi=%s", key, expected.OperationID, got)
		}
		runtimeRoute, exists := runtimeRoutes[key]
		if !exists {
			t.Fatalf("public docs API contract route %s is not a public runtime route", key)
		}
		if runtimeRoute.OperationID != expected.OperationID {
			t.Fatalf("public docs API contract operationId drift for %s: manifest=%s runtime=%s", key, expected.OperationID, runtimeRoute.OperationID)
		}
	}
}

type publicDocsManifest struct {
	APIContract struct {
		SchemaVersion    int                           `json:"schema_version"`
		SourcePath       string                        `json:"source_path"`
		ContentSHA256    string                        `json:"content_sha256"`
		PublicOperations []publicDocsManifestOperation `json:"public_operations"`
	} `json:"api_contract"`
}

type publicDocsManifestOperation struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	OperationID string `json:"operation_id"`
}

func openAPIRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate OpenAPI contract test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func TestBoundaryStatusOpenAPIMatchesRuntimeContract(t *testing.T) {
	schema := readOpenAPIBoundaryStatusSchema(t)
	properties, required := boundaryStatusJSONContract(t)

	actualProperties := make([]string, 0, len(schema.Properties))
	for name := range schema.Properties {
		actualProperties = append(actualProperties, name)
	}
	sort.Strings(actualProperties)
	if !reflect.DeepEqual(actualProperties, properties) {
		t.Fatalf("BoundaryStatus OpenAPI properties drifted from Go JSON contract:\nopenapi=%v\ngo=%v", actualProperties, properties)
	}
	sort.Strings(schema.Required)
	if !reflect.DeepEqual(schema.Required, required) {
		t.Fatalf("BoundaryStatus OpenAPI required fields drifted from Go JSON contract:\nopenapi=%v\ngo=%v", schema.Required, required)
	}

	for name, property := range schema.Properties {
		wantType := boundaryStatusOpenAPIType(t, name)
		if property.Type != wantType {
			t.Errorf("BoundaryStatus.%s type=%q, want %q", name, property.Type, wantType)
		}
	}
	if got := schema.Properties["updated_at"].Format; got != "date-time" {
		t.Errorf("BoundaryStatus.updated_at format=%q, want date-time", got)
	}
	for _, name := range []string{"open_approval_count", "quarantined_mcp_count"} {
		minimum := schema.Properties[name].Minimum
		if minimum == nil || *minimum != 0 {
			t.Errorf("BoundaryStatus.%s minimum=%v, want 0", name, minimum)
		}
	}
	if got := openAPIAdditionalPropertiesType(t, schema.Properties["components"].AdditionalProperties); got != "string" {
		t.Errorf("BoundaryStatus.components additionalProperties type=%q, want string values", got)
	}

	registry := boundarypkg.NewSurfaceRegistry(func() time.Time {
		return time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	})
	ready := registry.Status("v-test", true, true, 0)
	degraded := registry.Status("v-test", false, false, 0)
	expectedEnums := map[string][]string{
		"status":            {ready.Status, degraded.Status},
		"mode":              {ready.Mode},
		"receipt_signer":    {ready.ReceiptSigner, degraded.ReceiptSigner},
		"receipt_store":     {ready.ReceiptStore, degraded.ReceiptStore},
		"pdp":               {ready.PDP},
		"mcp_firewall":      {ready.MCPFirewall},
		"sandbox":           {ready.Sandbox},
		"authz":             {ready.Authz},
		"evidence_verifier": {ready.EvidenceVerifier},
		"checkpoint_log":    {ready.CheckpointLog},
	}
	for name, want := range expectedEnums {
		got := append([]string(nil), schema.Properties[name].Enum...)
		got = uniqueSorted(got)
		want = uniqueSorted(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("BoundaryStatus.%s enum=%v, want runtime values %v", name, got, want)
		}
	}
}

func TestRequestBodyContractMatchesRuntime(t *testing.T) {
	schemas := readOpenAPIRequestBodySchemas(t)
	contracts := requestBodyRuntimeContracts()
	allowlisted := 0

	for key, schema := range schemas {
		contract, ok := contracts[key]
		if !ok {
			t.Errorf("OpenAPI requestBody %s is missing a runtime classification", key)
			continue
		}
		if contract.Source == "" {
			t.Errorf("requestBody classification %s is missing source ownership", key)
			continue
		}
		if contract.Type == nil {
			if strings.TrimSpace(contract.Reason) == "" {
				t.Errorf("allowlisted requestBody %s (%s) is missing a concrete reason", key, contract.Source)
			}
			allowlisted++
			continue
		}

		properties, required := jsonObjectContractFromType(t, contract.Type)
		unexpectedProperties := make([]string, 0, len(schema.Properties))
		for name := range schema.Properties {
			if !containsString(properties, name) {
				unexpectedProperties = append(unexpectedProperties, name)
			}
		}
		sort.Strings(unexpectedProperties)
		if len(unexpectedProperties) > 0 {
			t.Errorf("%s OpenAPI requestBody exposes properties absent from runtime contract at %s: %v", key, contract.Source, unexpectedProperties)
		}

		missingRequired := make([]string, 0, len(schema.Required))
		for _, name := range uniqueSorted(schema.Required) {
			if !containsString(required, name) {
				missingRequired = append(missingRequired, name)
			}
		}
		if len(missingRequired) > 0 {
			t.Errorf("%s OpenAPI requestBody marks fields required that runtime does not require at %s: %v", key, contract.Source, missingRequired)
		}
	}

	for key, contract := range contracts {
		if _, ok := schemas[key]; ok {
			continue
		}
		t.Errorf("requestBody classification %s (%s) has no matching OpenAPI requestBody operation", key, contract.Source)
	}

	t.Logf("HELM-481 allowlisted requestBody operations pending follow-up: %d", allowlisted)
}

type openAPISchemaProperty struct {
	Type                 string    `yaml:"type"`
	Format               string    `yaml:"format"`
	Enum                 []string  `yaml:"enum"`
	Minimum              *int      `yaml:"minimum"`
	AdditionalProperties yaml.Node `yaml:"additionalProperties"`
}

type openAPIObjectSchema struct {
	Type       string                           `yaml:"type"`
	Required   []string                         `yaml:"required"`
	Properties map[string]openAPISchemaProperty `yaml:"properties"`
}

type openAPISpec struct {
	Paths      map[string]map[string]openAPIOperation `yaml:"paths"`
	Components struct {
		Schemas map[string]yaml.Node `yaml:"schemas"`
	} `yaml:"components"`
}

type openAPIOperation struct {
	RequestBody openAPIRequestBody `yaml:"requestBody"`
}

type openAPIRequestBody struct {
	Content map[string]openAPIMediaType `yaml:"content"`
}

type openAPIMediaType struct {
	Schema yaml.Node `yaml:"schema"`
}

type requestBodyRuntimeContract struct {
	Type   reflect.Type
	Source string
	Reason string
}

func readOpenAPIBoundaryStatusSchema(t *testing.T) openAPIObjectSchema {
	t.Helper()
	data, err := readOpenAPIFromRepository()
	if err != nil {
		t.Fatalf("read OpenAPI: %v", err)
	}
	var spec struct {
		Components struct {
			Schemas map[string]yaml.Node `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI: %v", err)
	}
	node, ok := spec.Components.Schemas["BoundaryStatus"]
	if !ok {
		t.Fatal("OpenAPI is missing components.schemas.BoundaryStatus")
	}
	var schema openAPIObjectSchema
	if err := node.Decode(&schema); err != nil {
		t.Fatalf("decode OpenAPI BoundaryStatus schema: %v", err)
	}
	if schema.Type != "object" {
		t.Fatalf("BoundaryStatus type=%q, want object", schema.Type)
	}
	return schema
}

func readOpenAPIRequestBodySchemas(t *testing.T) map[string]openAPIObjectSchema {
	t.Helper()
	data, err := readOpenAPIFromRepository()
	if err != nil {
		t.Fatalf("read OpenAPI: %v", err)
	}
	var spec openAPISpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI: %v", err)
	}

	schemas := map[string]openAPIObjectSchema{}
	for path, operations := range spec.Paths {
		for method, operation := range operations {
			switch method {
			case "delete", "patch", "post", "put":
			default:
				continue
			}
			mediaType, ok := operation.RequestBody.Content["application/json"]
			if !ok {
				mediaType, ok = operation.RequestBody.Content["multipart/form-data"]
			}
			if !ok || mediaType.Schema.Kind == 0 {
				continue
			}
			schema := decodeOpenAPIObjectSchema(t, spec, mediaType.Schema)
			key := strings.ToUpper(method) + " " + path
			schemas[key] = schema
		}
	}
	return schemas
}

func decodeOpenAPIObjectSchema(t *testing.T, spec openAPISpec, node yaml.Node) openAPIObjectSchema {
	t.Helper()
	var ref struct {
		Ref string `yaml:"$ref"`
	}
	if err := node.Decode(&ref); err != nil {
		t.Fatalf("decode OpenAPI schema ref: %v", err)
	}
	if ref.Ref != "" {
		schemaName := strings.TrimPrefix(ref.Ref, "#/components/schemas/")
		refNode, ok := spec.Components.Schemas[schemaName]
		if !ok {
			t.Fatalf("OpenAPI is missing components.schemas.%s", schemaName)
		}
		return decodeOpenAPIObjectSchema(t, spec, refNode)
	}

	var schema openAPIObjectSchema
	if err := node.Decode(&schema); err != nil {
		t.Fatalf("decode OpenAPI object schema: %v", err)
	}
	return schema
}

func boundaryStatusJSONContract(t *testing.T) ([]string, []string) {
	t.Helper()
	typeOfStatus := reflect.TypeOf(contracts.BoundaryStatus{})
	properties := make([]string, 0, typeOfStatus.NumField())
	required := make([]string, 0, typeOfStatus.NumField())
	for i := 0; i < typeOfStatus.NumField(); i++ {
		field := typeOfStatus.Field(i)
		parts := strings.Split(field.Tag.Get("json"), ",")
		if len(parts) == 0 || parts[0] == "" || parts[0] == "-" {
			t.Fatalf("BoundaryStatus.%s has no public JSON property", field.Name)
		}
		properties = append(properties, parts[0])
		optional := false
		for _, option := range parts[1:] {
			if option == "omitempty" {
				optional = true
				break
			}
		}
		if !optional {
			required = append(required, parts[0])
		}
	}
	sort.Strings(properties)
	sort.Strings(required)
	return properties, required
}

func jsonObjectContractFromType(t *testing.T, typ reflect.Type) ([]string, []string) {
	t.Helper()
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		t.Fatalf("runtime request contract type %s is not a struct", typ)
	}

	properties := make([]string, 0, typ.NumField())
	required := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		parts := strings.Split(field.Tag.Get("json"), ",")
		if len(parts) == 0 || parts[0] == "" || parts[0] == "-" {
			t.Fatalf("%s.%s has no public JSON property", typ.Name(), field.Name)
		}
		properties = append(properties, parts[0])
		optional := false
		for _, option := range parts[1:] {
			if option == "omitempty" {
				optional = true
				break
			}
		}
		if !optional {
			required = append(required, parts[0])
		}
	}
	sort.Strings(properties)
	sort.Strings(required)
	return properties, required
}

func boundaryStatusOpenAPIType(t *testing.T, propertyName string) string {
	t.Helper()
	typeOfStatus := reflect.TypeOf(contracts.BoundaryStatus{})
	for i := 0; i < typeOfStatus.NumField(); i++ {
		field := typeOfStatus.Field(i)
		if strings.Split(field.Tag.Get("json"), ",")[0] != propertyName {
			continue
		}
		if field.Type == reflect.TypeOf(time.Time{}) {
			return "string"
		}
		switch field.Type.Kind() {
		case reflect.String:
			return "string"
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return "integer"
		case reflect.Map:
			return "object"
		default:
			t.Fatalf("BoundaryStatus.%s has unsupported Go type %s", field.Name, field.Type)
		}
	}
	t.Fatalf("BoundaryStatus has no JSON property %q", propertyName)
	return ""
}

func openAPIAdditionalPropertiesType(t *testing.T, node yaml.Node) string {
	t.Helper()
	if node.Kind == 0 {
		return ""
	}
	var boolean bool
	if err := node.Decode(&boolean); err == nil {
		if boolean {
			return "any"
		}
		return ""
	}
	var property openAPISchemaProperty
	if err := node.Decode(&property); err != nil {
		t.Fatalf("decode additionalProperties: %v", err)
	}
	return property.Type
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	sort.Strings(unique)
	return unique
}

func requestBodyRuntimeContracts() map[string]requestBodyRuntimeContract {
	return map[string]requestBodyRuntimeContract{
		"POST /api/v1/kernel/approve": {
			Type:   reflect.TypeOf(contracts.ApprovalReceipt{}),
			Source: "core/pkg/api/approve_handler.go:83",
		},
		"POST /api/v1/approvals": {
			Type: reflect.TypeOf(struct {
				ApprovalID  string   `json:"approval_id"`
				Subject     string   `json:"subject"`
				Action      string   `json:"action"`
				RequestedBy string   `json:"requested_by"`
				Approvers   []string `json:"approvers"`
				Quorum      int      `json:"quorum"`
				TimelockMs  int64    `json:"timelock_ms"`
				ExpiresInMs int64    `json:"expires_in_ms"`
				Reason      string   `json:"reason"`
				ReceiptID   string   `json:"receipt_id"`
				BreakGlass  bool     `json:"break_glass"`
			}{}),
			Source: "core/cmd/helm-ai-kernel/contract_routes.go:1217",
		},
		"POST /api/v1/approvals/{approval_id}/webauthn/challenge": {
			Type: reflect.TypeOf(struct {
				Method string `json:"method"`
				TTLMS  int64  `json:"ttl_ms"`
			}{}),
			Source: "core/cmd/helm-ai-kernel/contract_routes.go:1281",
		},
		"POST /api/v1/approvals/{approval_id}/webauthn/assert": {
			Type:   reflect.TypeOf(contracts.ApprovalWebAuthnAssertion{}),
			Source: "core/cmd/helm-ai-kernel/contract_routes.go:1295",
		},
		"POST /api/v1/approvals/{approval_id}/{action}": {
			Type: reflect.TypeOf(struct {
				ReceiptID            string `json:"receipt_id"`
				Reason               string `json:"reason"`
				ExpectedCeremonyHash string `json:"expected_ceremony_hash"`
			}{}),
			Source: "core/cmd/helm-ai-kernel/contract_routes.go:1312",
		},
		"POST /api/v1/harness/change-contracts/{change_id}/approve": {
			Type: reflect.TypeOf(struct {
				ReceiptRef string `json:"receipt_ref"`
			}{}),
			Source: "core/cmd/helm-ai-kernel/contract_routes.go:555",
		},
		"PUT /api/v1/budgets/{budget_id}": {
			Type:   reflect.TypeOf(contracts.BudgetCeiling{}),
			Source: "core/cmd/helm-ai-kernel/contract_routes.go:1372",
		},
		"POST /api/v1/telemetry/export": {
			Type:   reflect.TypeOf(contracts.TelemetryExportRequest{}),
			Source: "core/cmd/helm-ai-kernel/contract_routes.go:1421",
		},
		"POST /api/v1/mcp/scan": {
			Type:   reflect.TypeOf(contracts.MCPScanRequest{}),
			Source: "core/cmd/helm-ai-kernel/contract_routes.go:897",
		},
		"PUT /api/v1/mcp/auth-profiles/{profile_id}": {
			Type:   reflect.TypeOf(contracts.MCPAuthorizationProfile{}),
			Source: "core/cmd/helm-ai-kernel/contract_routes.go:955",
		},
		"POST /api/v1/mcp/authorize-call": {
			Type:   reflect.TypeOf(contracts.MCPAuthorizeCallRequest{}),
			Source: "core/cmd/helm-ai-kernel/contract_routes.go:971",
		},
		"POST /api/v1/sandbox/preflight": {
			Type:   reflect.TypeOf(contracts.SandboxPreflightRequest{}),
			Source: "core/cmd/helm-ai-kernel/contract_routes.go:1108",
		},

		"POST /api/demo/run": {
			Source: "core/cmd/helm-ai-kernel/demo_routes.go:103",
			Reason: "inline runtime request shape not yet classified in HELM-481 phase 1",
		},
		"POST /api/demo/verify": {
			Source: "core/cmd/helm-ai-kernel/demo_routes.go:176",
			Reason: "inline runtime request shape not yet classified in HELM-481 phase 1",
		},
		"POST /api/demo/tamper": {
			Source: "core/cmd/helm-ai-kernel/demo_routes.go:194",
			Reason: "inline runtime request shape not yet classified in HELM-481 phase 1",
		},
		"POST /v1/chat/completions": {
			Source: "core/pkg/api/openai_proxy.go:83",
			Reason: "proxy request contract spans compatibility surface and is deferred to a follow-up slice",
		},
		"POST /api/v1/evaluate": {
			Source: "core/cmd/helm-ai-kernel/receipt_routes.go:40",
			Reason: "shared evaluation compatibility envelope is deferred to a follow-up slice",
		},
		"POST /api/v1/local-session/exchange": {
			Source: "core/cmd/helm-ai-kernel/local_first_run_routes.go",
			Reason: "local-first bootstrap request contract not yet classified in HELM-481 phase 1",
		},
		"POST /api/v1/onboarding/run-step": {
			Source: "core/cmd/helm-ai-kernel/local_first_run_routes.go",
			Reason: "local-first onboarding request contract not yet classified in HELM-481 phase 1",
		},
		"POST /api/v1/agent-ui/run": {
			Source: "core/cmd/helm-ai-kernel/console_agui_routes.go:64",
			Reason: "agent UI runtime request contract not yet classified in HELM-481 phase 1",
		},
		"POST /api/v1/launchpad/plan": {
			Source: "core/cmd/helm-ai-kernel/launchpad_routes.go",
			Reason: "launchpad planning request contract not yet classified in HELM-481 phase 1",
		},
		"POST /api/v1/launchpad/launch": {
			Source: "core/cmd/helm-ai-kernel/launchpad_routes.go",
			Reason: "launchpad launch request contract not yet classified in HELM-481 phase 1",
		},
		"POST /api/v1/launchpad/imports": {
			Source: "core/cmd/helm-ai-kernel/launchpad_routes.go",
			Reason: "launchpad import request contract not yet classified in HELM-481 phase 1",
		},
		"POST /api/v1/launchpad/runs": {
			Source: "core/cmd/helm-ai-kernel/launchpad_routes.go",
			Reason: "launchpad run creation request contract not yet classified in HELM-481 phase 1",
		},
		"POST /api/v1/launchpad/runs/{run_id}/teardown": {
			Source: "core/cmd/helm-ai-kernel/launchpad_routes.go",
			Reason: "launchpad teardown request contract not yet classified in HELM-481 phase 1",
		},
		"POST /api/v1/launchpad/policy/simulate": {
			Source: "core/cmd/helm-ai-kernel/launchpad_routes.go",
			Reason: "launchpad policy simulation request contract not yet classified in HELM-481 phase 1",
		},
		"POST /api/v1/launchpad/mcp/approvals": {
			Source: "core/cmd/helm-ai-kernel/launchpad_routes.go",
			Reason: "launchpad MCP approval request contract not yet classified in HELM-481 phase 1",
		},
		"POST /api/v1/launchpad/secrets": {
			Source: "core/cmd/helm-ai-kernel/launchpad_routes.go",
			Reason: "launchpad secret binding request contract not yet classified in HELM-481 phase 1",
		},
		"POST /api/v1/launchpad/launches/{launch_id}/delete": {
			Source: "core/cmd/helm-ai-kernel/launchpad_routes.go",
			Reason: "launchpad delete request contract not yet classified in HELM-481 phase 1",
		},
		"POST /api/ag-ui/run": {
			Source: "core/cmd/helm-ai-kernel/console_agui_routes.go:64",
			Reason: "compat AGUI request contract not yet classified in HELM-481 phase 1",
		},
		"POST /api/v1/trust/keys/add": {
			Source: "core/pkg/api/trust_keys_handler.go:39",
			Reason: "trust-key request package is deferred to a follow-up slice",
		},
		"POST /api/v1/trust/keys/revoke": {
			Source: "core/pkg/api/trust_keys_handler.go:83",
			Reason: "trust-key request package is deferred to a follow-up slice",
		},
		"POST /mcp": {
			Source: "core/pkg/mcp/gateway.go:171",
			Reason: "JSON-RPC request contract is deferred to a follow-up slice",
		},
		"POST /api/v1/evidence/export": {
			Source: "core/cmd/helm-ai-kernel/contract_routes.go",
			Reason: "evidence export request contract not yet classified in HELM-481 phase 1",
		},
		"POST /api/v1/evidence/verify": {
			Source: "core/cmd/helm-ai-kernel/contract_routes.go",
			Reason: "evidence verify request contract not yet classified in HELM-481 phase 1",
		},
		"POST /api/v1/evidence/verification-scopes": {
			Source: "core/cmd/helm-ai-kernel/contract_routes.go",
			Reason: "verification-scope request contract not yet classified in HELM-481 phase 1",
		},
		"POST /api/v1/telemetry/harness-traces": {
			Source: "core/cmd/helm-ai-kernel/contract_routes.go",
			Reason: "harness trace request contract not yet classified in HELM-481 phase 1",
		},
		"POST /api/v1/plans/transactions": {
			Source: "core/cmd/helm-ai-kernel/contract_routes.go",
			Reason: "plan-transaction request contract not yet classified in HELM-481 phase 1",
		},
		"POST /api/v1/harness/change-contracts": {
			Source: "core/cmd/helm-ai-kernel/contract_routes.go",
			Reason: "harness contract creation request not yet classified in HELM-481 phase 1",
		},
		"POST /api/v1/gui/receipts/verify": {
			Source: "core/cmd/helm-ai-kernel/contract_routes.go",
			Reason: "GUI receipt verification request not yet classified in HELM-481 phase 1",
		},
		"POST /api/v1/evidence/envelopes": {
			Source: "core/cmd/helm-ai-kernel/contract_routes.go",
			Reason: "evidence envelope request contract not yet classified in HELM-481 phase 1",
		},
		"POST /api/v1/replay/verify": {
			Source: "core/cmd/helm-ai-kernel/contract_routes.go",
			Reason: "replay verification request contract not yet classified in HELM-481 phase 1",
		},
		"POST /api/v1/conformance/run": {
			Source: "core/cmd/helm-ai-kernel/contract_routes.go",
			Reason: "conformance run request contract not yet classified in HELM-481 phase 1",
		},
		"POST /api/v1/mcp/registry": {
			Source: "core/cmd/helm-ai-kernel/contract_routes.go:808",
			Reason: "MCP registry discovery request contract not yet classified in HELM-481 phase 1",
		},
		"POST /api/v1/mcp/registry/approve": {
			Source: "core/cmd/helm-ai-kernel/contract_routes.go:847",
			Reason: "approval-verification-unavailable endpoint intentionally ignores body fields and is deferred",
		},
		"POST /api/v1/mcp/registry/{server_id}/approve": {
			Source: "core/cmd/helm-ai-kernel/contract_routes.go:873",
			Reason: "approval-verification-unavailable endpoint intentionally ignores body fields and is deferred",
		},
		"POST /api/v1/mcp/registry/{server_id}/revoke": {
			Source: "core/cmd/helm-ai-kernel/contract_routes.go:878",
			Reason: "MCP revoke request contract not yet classified in HELM-481 phase 1",
		},
		"POST /mcp/v1/execute": {
			Source: "core/pkg/mcp/gateway.go:297",
			Reason: "MCP execute request contract is deferred to a follow-up slice",
		},
		"POST /api/v1/sandbox/grants": {
			Source: "core/cmd/helm-ai-kernel/contract_routes.go",
			Reason: "sandbox grant creation request not yet classified in HELM-481 phase 1",
		},
		"POST /api/v1/authz/check": {
			Source: "core/cmd/helm-ai-kernel/subsystems.go:116",
			Reason: "authz check request contract not yet classified in HELM-481 phase 1",
		},
	}
}

func TestRuntimeRouteRegistryHasExplicitSecurityMetadata(t *testing.T) {
	for _, spec := range RuntimeRouteSpecs() {
		if spec.Method == "" || spec.Path == "" || spec.MuxPattern == "" || spec.OperationID == "" || spec.Owner == "" {
			t.Fatalf("route registry entry has incomplete identity metadata: %+v", spec)
		}
		if spec.Auth == "" {
			t.Fatalf("route %s %s missing auth metadata", spec.Method, spec.Path)
		}
		if spec.RateLimit == "" {
			t.Fatalf("route %s %s missing rate-limit metadata", spec.Method, spec.Path)
		}
		if spec.ContractStatus == "" {
			t.Fatalf("route %s %s missing contract status", spec.Method, spec.Path)
		}
	}
}

func TestApprovalConsumptionRoutesHaveExactRegistryMetadata(t *testing.T) {
	expected := []RuntimeRouteSpec{
		{Method: http.MethodPost, Path: approvalGrantConsumePath, MuxPattern: approvalGrantConsumePath, Auth: RouteAuthWorkload, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "consumeApprovalGrant", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: approvalGrantConsumptionRecoverPath, MuxPattern: approvalGrantConsumptionRecoverPath, Auth: RouteAuthWorkload, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "recoverApprovalGrantConsumption", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: approvalDispatchAdmissionPath, MuxPattern: approvalDispatchAdmissionPath, Auth: RouteAuthWorkload, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "admitApprovalDispatch", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: approvalDispatchAdmissionRecoverPath, MuxPattern: approvalDispatchAdmissionRecoverPath, Auth: RouteAuthWorkload, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "recoverApprovalDispatchAdmission", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: effectDispositionPath, MuxPattern: effectDispositionPath, Auth: RouteAuthWorkload, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "recordEffectDisposition", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: effectDispositionRecoverPath, MuxPattern: effectDispositionRecoverPath, Auth: RouteAuthWorkload, RateLimit: RouteRateEvidence, ContractStatus: RouteContractInternal, OperationID: "recoverEffectDisposition", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: effectReconciliationCandidatesPath, MuxPattern: effectReconciliationCandidatesPath, Auth: RouteAuthWorkload, RateLimit: RouteRateEvidence, ContractStatus: RouteContractInternal, OperationID: "listEffectReconciliationCandidates", Owner: "core/cmd/helm-ai-kernel"},
	}
	registered := make(map[string]RuntimeRouteSpec, len(RuntimeRouteSpecs()))
	for _, spec := range RuntimeRouteSpecs() {
		registered[spec.Method+" "+spec.Path] = spec
	}
	for _, want := range expected {
		key := want.Method + " " + want.Path
		got, ok := registered[key]
		if !ok {
			t.Fatalf("approval workload route %s is missing from the runtime registry", key)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("approval workload route %s metadata = %+v, want %+v", key, got, want)
		}
	}
}

func TestLocalConsolePeerProofRoutesHaveExactInternalRegistryMetadata(t *testing.T) {
	expected := []RuntimeRouteSpec{
		{Method: http.MethodGet, Path: localConsolePeerProofPath, MuxPattern: localConsolePeerProofPath, Auth: RouteAuthLoopback, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "getLocalConsolePeerProof", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodHead, Path: localConsolePeerProofPath, MuxPattern: localConsolePeerProofPath, Auth: RouteAuthLoopback, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "checkLocalConsolePeerProof", Owner: "core/cmd/helm-ai-kernel"},
	}
	registered := make(map[string]RuntimeRouteSpec, len(RuntimeRouteSpecs()))
	for _, spec := range RuntimeRouteSpecs() {
		registered[spec.Method+" "+spec.Path] = spec
	}
	for _, want := range expected {
		key := want.Method + " " + want.Path
		got, ok := registered[key]
		if !ok {
			t.Fatalf("local Console peer-proof route %s is missing from the runtime registry", key)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("local Console peer-proof route %s metadata = %+v, want %+v", key, got, want)
		}
	}
	for _, spec := range PublicRuntimeRouteSpecs() {
		if spec.Path == localConsolePeerProofPath {
			t.Fatalf("local Console peer-proof route %s must remain internal, not public", spec.Method+" "+spec.Path)
		}
	}
}

func TestDesktopTransportProofRouteHasExactInternalRegistryMetadata(t *testing.T) {
	want := RuntimeRouteSpec{Method: http.MethodGet, Path: desktopTransportV1ProofPath, MuxPattern: desktopTransportV1ProofPath, Auth: RouteAuthLoopback, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "proveDesktopTransport", Owner: "core/cmd/helm-ai-kernel"}
	for _, got := range RuntimeRouteSpecs() {
		if got.Method == want.Method && got.Path == want.Path {
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("desktop transport proof route metadata = %+v, want %+v", got, want)
			}
			for _, public := range PublicRuntimeRouteSpecs() {
				if public.Path == desktopTransportV1ProofPath {
					t.Fatalf("desktop transport proof route must remain internal, not public: %+v", public)
				}
			}
			return
		}
	}
	t.Fatalf("desktop transport proof route %s is missing from the runtime registry", want.Path)
}

func TestProtectedRuntimeHandlersAreDeclaredInRouteRegistry(t *testing.T) {
	registered := map[string]RuntimeRouteSpec{}
	for _, spec := range RuntimeRouteSpecs() {
		registered[spec.MuxPattern] = spec
	}

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate route registry test source")
	}
	sourceDir := filepath.Dir(file)
	routeFiles := []string{
		"subsystems.go",
		"receipt_routes.go",
		"console_routes.go",
		"local_first_run_routes.go",
		"console_agui_routes.go",
		"launchpad_routes.go",
		"contract_routes.go",
		"policy_reconcile_routes.go",
		"emergency_stop_routes.go",
	}
	protectedRoute := regexp.MustCompile(`mux\.HandleFunc\("([^"]+)",\s*protectRuntimeHandler`)
	for _, routeFile := range routeFiles {
		data, err := os.ReadFile(filepath.Join(sourceDir, routeFile))
		if err != nil {
			t.Fatalf("read %s: %v", routeFile, err)
		}
		for _, match := range protectedRoute.FindAllStringSubmatch(string(data), -1) {
			muxPattern := match[1]
			if _, ok := registered[muxPattern]; !ok {
				t.Fatalf("protected runtime route %s in %s is missing from route registry", muxPattern, routeFile)
			}
		}
	}
}

func TestProtectedPublicRoutesDeclareOpenAPISecurity(t *testing.T) {
	operations := readOpenAPIOperationSecurity(t)
	for _, spec := range PublicRuntimeRouteSpecs() {
		if spec.Auth != RouteAuthAdmin && spec.Auth != RouteAuthAuthenticated && spec.Auth != RouteAuthTenant && spec.Auth != RouteAuthService && spec.Auth != RouteAuthWorkload {
			continue
		}
		key := spec.Method + " " + spec.Path
		operation, ok := operations[key]
		if !ok {
			t.Fatalf("protected public route %s is missing from OpenAPI", key)
		}
		if len(operation.Security) == 0 {
			t.Fatalf("protected public route %s is missing OpenAPI security", key)
		}
		assertOpenAPISecurityScheme(t, key, operation, expectedOpenAPISecurityScheme(spec.Auth))
		if _, ok := operation.Responses["401"]; !ok {
			t.Fatalf("protected public route %s is missing OpenAPI 401 response", key)
		}
		if spec.Auth == RouteAuthTenant {
			if _, ok := operation.Responses["403"]; !ok {
				t.Fatalf("tenant-scoped public route %s is missing OpenAPI 403 response", key)
			}
			assertOpenAPIRequiredHeader(t, key, operation, "X-Helm-Tenant-ID", "#/components/parameters/HelmTenantIDHeader")
			assertOpenAPIRequiredHeader(t, key, operation, "X-Helm-Principal-ID", "#/components/parameters/HelmPrincipalIDHeader")
			if spec.Path == "/api/v1/evaluate" {
				assertOpenAPIHeader(t, key, operation, "X-Helm-Workspace-ID", "#/components/parameters/HelmWorkspaceIDHeader")
			}
		}
	}
}

type openAPIOperationSecurity struct {
	Security   []map[string][]string `yaml:"security"`
	Parameters []openAPIParameter    `yaml:"parameters"`
	Responses  map[string]any        `yaml:"responses"`
}

type openAPIParameter struct {
	Ref      string `yaml:"$ref"`
	Name     string `yaml:"name"`
	In       string `yaml:"in"`
	Required bool   `yaml:"required"`
}

func expectedOpenAPISecurityScheme(auth RouteAuth) string {
	if auth == RouteAuthService {
		return "ServiceBearerAuth"
	}
	return "AdminBearerAuth"
}

func assertOpenAPISecurityScheme(t *testing.T, route string, operation openAPIOperationSecurity, scheme string) {
	t.Helper()
	for _, requirement := range operation.Security {
		if _, ok := requirement[scheme]; ok {
			return
		}
	}
	t.Fatalf("protected public route %s is missing OpenAPI %s security requirement", route, scheme)
}

func assertOpenAPIRequiredHeader(t *testing.T, route string, operation openAPIOperationSecurity, headerName string, ref string) {
	t.Helper()
	for _, parameter := range operation.Parameters {
		if parameter.Ref == ref {
			return
		}
		if strings.EqualFold(parameter.Name, headerName) && parameter.In == "header" && parameter.Required {
			return
		}
	}
	t.Fatalf("tenant-scoped public route %s is missing required OpenAPI header %s", route, headerName)
}

func assertOpenAPIHeader(t *testing.T, route string, operation openAPIOperationSecurity, headerName string, ref string) {
	t.Helper()
	for _, parameter := range operation.Parameters {
		if parameter.Ref == ref {
			return
		}
		if strings.EqualFold(parameter.Name, headerName) && parameter.In == "header" {
			return
		}
	}
	t.Fatalf("public route %s is missing OpenAPI header %s", route, headerName)
}

func readOpenAPIOperationSecurity(t *testing.T) map[string]openAPIOperationSecurity {
	t.Helper()
	data, err := readOpenAPIFromRepository()
	if err != nil {
		t.Fatalf("read OpenAPI: %v", err)
	}
	var spec struct {
		Paths map[string]map[string]openAPIOperationSecurity `yaml:"paths"`
	}
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI: %v", err)
	}
	methods := map[string]string{
		"get":    http.MethodGet,
		"post":   http.MethodPost,
		"put":    http.MethodPut,
		"patch":  http.MethodPatch,
		"delete": http.MethodDelete,
	}
	operations := map[string]openAPIOperationSecurity{}
	for path, pathItem := range spec.Paths {
		for method, operation := range pathItem {
			httpMethod, ok := methods[method]
			if !ok {
				continue
			}
			operations[httpMethod+" "+path] = operation
		}
	}
	return operations
}

func readOpenAPIFromRepository() ([]byte, error) {
	_, file, _, ok := runtime.Caller(0)
	if ok {
		path := filepath.Join(filepath.Dir(file), "..", "..", "..", "api", "openapi", "helm.openapi.yaml")
		if data, err := os.ReadFile(path); err == nil {
			return data, nil
		}
	}
	return os.ReadFile("api/openapi/helm.openapi.yaml")
}

func readOpenAPIOperations(t *testing.T) map[string]string {
	t.Helper()
	data, err := readOpenAPIFromRepository()
	if err != nil {
		t.Fatalf("read OpenAPI: %v", err)
	}
	var spec struct {
		Paths map[string]map[string]struct {
			OperationID string `yaml:"operationId"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parse OpenAPI: %v", err)
	}
	if len(spec.Paths) == 0 {
		t.Fatal("OpenAPI paths section is empty")
	}
	methods := map[string]string{
		"get":    http.MethodGet,
		"post":   http.MethodPost,
		"put":    http.MethodPut,
		"patch":  http.MethodPatch,
		"delete": http.MethodDelete,
	}
	operations := map[string]string{}
	for path, pathItem := range spec.Paths {
		for method, operation := range pathItem {
			httpMethod, ok := methods[method]
			if !ok {
				continue
			}
			if operation.OperationID == "" {
				t.Fatalf("OpenAPI operation %s %s missing operationId", httpMethod, path)
			}
			operations[httpMethod+" "+path] = operation.OperationID
		}
	}
	return operations
}

func representativeRuntimePath(openAPIPath string) string {
	replacements := map[string]string{
		"{receipt_id}":   "rcpt-test",
		"{receipt_hash}": "rcpt-test",
		"{session_id}":   "agent.test",
		"{surface_id}":   "overview",
		"{report_id}":    "conf_test",
		"{launch_id}":    "launch-test",
	}
	path := openAPIPath
	for token, value := range replacements {
		path = strings.ReplaceAll(path, token, value)
	}
	return path
}
