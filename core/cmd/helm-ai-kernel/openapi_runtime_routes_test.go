package main

import (
	"fmt"
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
		if !property.Type.is(wantType) {
			t.Errorf("BoundaryStatus.%s type=%q, want %q", name, property.Type.String(), wantType)
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
	if additional := schema.Properties["components"].AdditionalProperties; additional == nil || !additional.Type.is("string") {
		t.Errorf("BoundaryStatus.components additionalProperties=%+v, want string values", additional)
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

func TestEvaluateOpenAPIContractsMatchServedRuntimeTypes(t *testing.T) {
	tests := []struct {
		name   string
		schema string
		value  any
	}{
		{name: "request", schema: "DecisionRequest", value: evaluateRequest{}},
		{name: "response", schema: "DecisionRecord", value: contracts.DecisionRecord{}},
		{name: "intervention", schema: "InterventionMetadata", value: contracts.InterventionMetadata{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			schema := readOpenAPIObjectSchema(t, tt.schema)
			if schema.AdditionalProperties == nil || *schema.AdditionalProperties {
				t.Fatalf("%s OpenAPI schema must reject undeclared top-level properties", tt.schema)
			}
			properties, required := jsonObjectContract(t, tt.value)
			actualProperties := make([]string, 0, len(schema.Properties))
			for name := range schema.Properties {
				actualProperties = append(actualProperties, name)
			}
			sort.Strings(actualProperties)
			if !reflect.DeepEqual(actualProperties, properties) {
				t.Fatalf("%s OpenAPI properties drifted from Go JSON contract:\nopenapi=%v\ngo=%v", tt.schema, actualProperties, properties)
			}
			sort.Strings(schema.Required)
			if !reflect.DeepEqual(schema.Required, required) {
				t.Fatalf("%s OpenAPI required properties drifted from Go JSON contract:\nopenapi=%v\ngo=%v", tt.schema, schema.Required, required)
			}
		})
	}
}

func TestEvaluateOpenAPIValidationMatchesRuntime(t *testing.T) {
	operations := readOpenAPIOperationSecurity(t)
	operation, ok := operations[http.MethodPost+" /api/v1/evaluate"]
	if !ok {
		t.Fatal("OpenAPI is missing POST /api/v1/evaluate")
	}
	if response, ok := operation.Responses["405"]; !ok || response.Ref != "#/components/responses/HelmError" {
		t.Fatalf("evaluate OpenAPI 405 response = %+v, want HelmError", response)
	}

	schema := readOpenAPIObjectSchema(t, "DecisionRequest")
	for _, field := range []string{"action", "resource"} {
		property, ok := schema.Properties[field]
		if !ok {
			t.Fatalf("DecisionRequest is missing %s", field)
		}
		if property.MinLength == nil || *property.MinLength != 1 {
			t.Errorf("DecisionRequest.%s minLength=%v, want 1", field, property.MinLength)
		}
	}
	context := schema.Properties["context"]
	if !context.Type.includes("object") || !context.Type.includes("null") {
		t.Errorf("DecisionRequest.context type=%q, want object and null", context.Type.String())
	}
	for _, key := range []string{
		"principal_id", "tenant_id", "tenantId", "tenant", "workspace_id", "workspaceId", "workspace",
		"security_context_trusted", "credential_hash", "session_id", "source_channel", "trust_level", "destination",
		"zeroid_token", "spiffe_uri",
	} {
		if !strings.Contains(context.Description, "`"+key+"`") {
			t.Errorf("DecisionRequest.context description does not reserve %q", key)
		}
	}
}

type openAPIType []string

func (t *openAPIType) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		*t = []string{value.Value}
		return nil
	case yaml.SequenceNode:
		var values []string
		if err := value.Decode(&values); err != nil {
			return err
		}
		*t = values
		return nil
	default:
		return fmt.Errorf("openapi type has unexpected YAML node kind %d", value.Kind)
	}
}

func (t openAPIType) includes(value string) bool {
	for _, candidate := range t {
		if candidate == value {
			return true
		}
	}
	return false
}

func (t openAPIType) is(value string) bool {
	return len(t) == 1 && t[0] == value
}

func (t openAPIType) String() string {
	return strings.Join(t, "|")
}

type openAPISchemaProperty struct {
	Type                 openAPIType            `yaml:"type"`
	Format               string                 `yaml:"format"`
	Enum                 []string               `yaml:"enum"`
	Minimum              *int                   `yaml:"minimum"`
	MinLength            *int                   `yaml:"minLength"`
	Description          string                 `yaml:"description"`
	AdditionalProperties *openAPISchemaProperty `yaml:"additionalProperties"`
}

type openAPIObjectSchema struct {
	Type                 string                           `yaml:"type"`
	Required             []string                         `yaml:"required"`
	Properties           map[string]openAPISchemaProperty `yaml:"properties"`
	AdditionalProperties *bool                            `yaml:"additionalProperties"`
}

func readOpenAPIBoundaryStatusSchema(t *testing.T) openAPIObjectSchema {
	return readOpenAPIObjectSchema(t, "BoundaryStatus")
}

func readOpenAPIObjectSchema(t *testing.T, name string) openAPIObjectSchema {
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
	node, ok := spec.Components.Schemas[name]
	if !ok {
		t.Fatalf("OpenAPI is missing components.schemas.%s", name)
	}
	var schema openAPIObjectSchema
	if err := node.Decode(&schema); err != nil {
		t.Fatalf("decode OpenAPI %s schema: %v", name, err)
	}
	if schema.Type != "object" {
		t.Fatalf("%s type=%q, want object", name, schema.Type)
	}
	return schema
}

func jsonObjectContract(t *testing.T, value any) ([]string, []string) {
	t.Helper()
	typeOfValue := reflect.TypeOf(value)
	properties := make([]string, 0, typeOfValue.NumField())
	required := make([]string, 0, typeOfValue.NumField())
	for i := 0; i < typeOfValue.NumField(); i++ {
		field := typeOfValue.Field(i)
		parts := strings.Split(field.Tag.Get("json"), ",")
		if len(parts) == 0 || parts[0] == "" || parts[0] == "-" {
			t.Fatalf("%s.%s has no public JSON property", typeOfValue.Name(), field.Name)
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
		if spec.Auth != RouteAuthAdmin && spec.Auth != RouteAuthAuthenticated && spec.Auth != RouteAuthTenant && spec.Auth != RouteAuthService {
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
	Security   []map[string][]string      `yaml:"security"`
	Parameters []openAPIParameter         `yaml:"parameters"`
	Responses  map[string]openAPIResponse `yaml:"responses"`
}

type openAPIResponse struct {
	Ref string `yaml:"$ref"`
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
