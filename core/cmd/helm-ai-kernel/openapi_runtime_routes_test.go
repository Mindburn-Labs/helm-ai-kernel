package main

import (
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
	if additional := schema.Properties["components"].AdditionalProperties; additional == nil || additional.Type != "string" {
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

type openAPISchemaProperty struct {
	Type                 string                 `yaml:"type"`
	Format               string                 `yaml:"format"`
	Enum                 []string               `yaml:"enum"`
	Minimum              *int                   `yaml:"minimum"`
	AdditionalProperties *openAPISchemaProperty `yaml:"additionalProperties"`
}

type openAPIObjectSchema struct {
	Type       string                           `yaml:"type"`
	Required   []string                         `yaml:"required"`
	Properties map[string]openAPISchemaProperty `yaml:"properties"`
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

func TestApprovalConsumptionRoutesHaveExactRegistryMetadata(t *testing.T) {
	expected := []RuntimeRouteSpec{
		{Method: http.MethodPost, Path: approvalGrantConsumePath, MuxPattern: approvalGrantConsumePath, Auth: RouteAuthWorkload, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "consumeApprovalGrant", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: approvalGrantConsumptionRecoverPath, MuxPattern: approvalGrantConsumptionRecoverPath, Auth: RouteAuthWorkload, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "recoverApprovalGrantConsumption", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: approvalDispatchAdmissionPath, MuxPattern: approvalDispatchAdmissionPath, Auth: RouteAuthWorkload, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "admitApprovalDispatch", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: approvalDispatchAdmissionRecoverPath, MuxPattern: approvalDispatchAdmissionRecoverPath, Auth: RouteAuthWorkload, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "recoverApprovalDispatchAdmission", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: effectDispositionPath, MuxPattern: effectDispositionPath, Auth: RouteAuthWorkload, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "recordEffectDisposition", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: effectDispositionRecoverPath, MuxPattern: effectDispositionRecoverPath, Auth: RouteAuthWorkload, RateLimit: RouteRateEvidence, ContractStatus: RouteContractInternal, OperationID: "recoverEffectDisposition", Owner: "core/cmd/helm-ai-kernel"},
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
