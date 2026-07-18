package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
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
	manifestPath := filepath.Join(root, "docs", "public-docs.manifest.json")
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read public docs manifest: %v", err)
	}
	var manifest publicDocsManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatalf("parse public docs manifest: %v", err)
	}
	if manifest.APIContract.SchemaVersion != 1 {
		t.Fatalf("public docs API contract schema_version=%d, want 1", manifest.APIContract.SchemaVersion)
	}
	if manifest.APIContract.SourcePath != "api/openapi/helm.openapi.yaml" {
		t.Fatalf("public docs API contract source_path=%q", manifest.APIContract.SourcePath)
	}
	if len(manifest.APIContract.PublicOperations) == 0 {
		t.Fatal("public docs API contract has no public operations")
	}

	openAPIPath := filepath.Join(root, filepath.FromSlash(manifest.APIContract.SourcePath))
	openAPIData, err := os.ReadFile(openAPIPath)
	if err != nil {
		t.Fatalf("read public OpenAPI source: %v", err)
	}
	digest := sha256.Sum256(openAPIData)
	if got, want := manifest.APIContract.ContentSHA256, "sha256:"+hex.EncodeToString(digest[:]); got != want {
		t.Fatalf("public docs API contract content_sha256=%q, want %q", got, want)
	}

	var spec publicDocsOpenAPISpec
	if err := yaml.Unmarshal(openAPIData, &spec); err != nil {
		t.Fatalf("parse public OpenAPI source: %v", err)
	}
	operationsByID := make(map[string]publicDocsOpenAPIOperation)
	for _, pathItem := range spec.Paths {
		for _, operation := range pathItem {
			if operation.OperationID != "" {
				operationsByID[operation.OperationID] = operation
			}
		}
	}
	for _, expected := range manifest.APIContract.PublicOperations {
		operation, ok := spec.Paths[expected.Path][strings.ToLower(expected.Method)]
		if !ok {
			t.Fatalf("public docs API contract route %s %s is missing from OpenAPI", expected.Method, expected.Path)
		}
		if operation.OperationID != expected.OperationID {
			t.Fatalf("public docs API contract operationId drift for %s %s: manifest=%s openapi=%s", expected.Method, expected.Path, expected.OperationID, operation.OperationID)
		}
		assertPublicDocsOperationSemantics(t, root, expected.OperationID, operation)
	}

	verifyEvidence, ok := operationsByID["verifyEvidence"]
	if !ok {
		t.Fatal("OpenAPI is missing verifyEvidence")
	}
	for _, contentType := range []string{"application/octet-stream", "multipart/form-data"} {
		if _, ok := verifyEvidence.RequestBody.Content[contentType]; !ok {
			t.Fatalf("verifyEvidence does not declare %s request content", contentType)
		}
	}

	for _, requirement := range []publicDocsExampleRequirement{
		{
			OperationID: "runPublicDemo",
			ContentType: "application/json",
			LiteralKeys: []string{"action_id", "policy_id"},
		},
		{
			OperationID: "verifyPublicDemoReceipt",
			ContentType: "application/json",
			Bindings: map[string]string{
				"receipt":               "$.receipt",
				"expected_receipt_hash": "$.proof_refs.receipt_hash",
			},
		},
		{
			OperationID: "tamperPublicDemoReceipt",
			ContentType: "application/json",
			LiteralKeys: []string{"mutation"},
			Bindings: map[string]string{
				"receipt":               "$.receipt",
				"expected_receipt_hash": "$.proof_refs.receipt_hash",
			},
		},
		{
			OperationID: "evaluateDecision",
			ContentType: "application/json",
			LiteralKeys: []string{"action", "resource"},
		},
		{
			OperationID: "verifyEvidence",
			ContentType: "application/octet-stream",
			RequireFile: true,
		},
		{
			OperationID: "authorizeMcpCall",
			ContentType: "application/json",
			LiteralKeys: []string{"server_id", "tool_name", "args_hash"},
		},
	} {
		operation, ok := operationsByID[requirement.OperationID]
		if !ok {
			t.Fatalf("OpenAPI is missing %s", requirement.OperationID)
		}
		assertPublicDocsExample(t, root, requirement, operation.DocsExample)
	}
	assertPublicDocsExamplesMatchSourceFixturesAndExerciseRuntime(t, spec)
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

type publicDocsOpenAPISpec struct {
	Paths map[string]map[string]publicDocsOpenAPIOperation `yaml:"paths"`
}

type publicDocsOpenAPIOperation struct {
	OperationID string                    `yaml:"operationId"`
	Description string                    `yaml:"description"`
	RequestBody publicDocsRequestBody     `yaml:"requestBody"`
	DocsExample *publicDocsOpenAPIExample `yaml:"x-helm-docs-example"`
}

type publicDocsRequestBody struct {
	Content map[string]any `yaml:"content"`
}

type publicDocsOpenAPIExample struct {
	SourceTest string                           `yaml:"source_test"`
	Request    *publicDocsOpenAPIExampleRequest `yaml:"request"`
}

type publicDocsOpenAPIExampleRequest struct {
	ContentType string                            `yaml:"content_type"`
	Literal     map[string]any                    `yaml:"literal"`
	Bindings    map[string]publicDocsResponseBind `yaml:"bindings"`
	File        string                            `yaml:"file"`
}

type publicDocsResponseBind struct {
	FromResponse struct {
		Method   string `yaml:"method"`
		Path     string `yaml:"path"`
		JSONPath string `yaml:"json_path"`
	} `yaml:"from_response"`
}

type publicDocsExampleRequirement struct {
	OperationID string
	ContentType string
	LiteralKeys []string
	Bindings    map[string]string
	RequireFile bool
}

func assertPublicDocsExample(t *testing.T, root string, requirement publicDocsExampleRequirement, example *publicDocsOpenAPIExample) {
	t.Helper()
	if example == nil {
		t.Fatalf("%s is missing x-helm-docs-example", requirement.OperationID)
	}
	if example.Request == nil {
		t.Fatalf("%s docs example is missing request metadata", requirement.OperationID)
	}
	if example.Request.ContentType != requirement.ContentType {
		t.Fatalf("%s docs example content_type=%q, want %q", requirement.OperationID, example.Request.ContentType, requirement.ContentType)
	}
	sourceFile, sourceTestName, ok := strings.Cut(example.SourceTest, "#")
	if !ok || sourceFile == "" || sourceTestName == "" {
		t.Fatalf("%s docs example source_test=%q, want path#TestName", requirement.OperationID, example.SourceTest)
	}
	if filepath.IsAbs(sourceFile) {
		t.Fatalf("%s docs example source_test must be repository-relative: %q", requirement.OperationID, example.SourceTest)
	}
	sourceTestPath := filepath.Join(root, filepath.FromSlash(sourceFile))
	if _, err := os.Stat(sourceTestPath); err != nil {
		t.Fatalf("%s docs example source_test does not resolve: %v", requirement.OperationID, err)
	}
	sourceTestData, err := os.ReadFile(sourceTestPath)
	if err != nil {
		t.Fatalf("%s read docs example source_test: %v", requirement.OperationID, err)
	}
	if !regexp.MustCompile(`(?m)^func\s+` + regexp.QuoteMeta(sourceTestName) + `\s*\(`).Match(sourceTestData) {
		t.Fatalf("%s docs example source_test symbol %q is not declared in %s", requirement.OperationID, sourceTestName, sourceFile)
	}
	for _, key := range requirement.LiteralKeys {
		if _, ok := example.Request.Literal[key]; !ok {
			t.Fatalf("%s docs example is missing literal %q", requirement.OperationID, key)
		}
	}
	for key, jsonPath := range requirement.Bindings {
		binding, ok := example.Request.Bindings[key]
		if !ok {
			t.Fatalf("%s docs example is missing response binding %q", requirement.OperationID, key)
		}
		if binding.FromResponse.Method != http.MethodPost || binding.FromResponse.Path != "/api/demo/run" || binding.FromResponse.JSONPath != jsonPath {
			t.Fatalf("%s docs example binding %q=%+v, want POST /api/demo/run %s", requirement.OperationID, key, binding.FromResponse, jsonPath)
		}
	}
	if requirement.RequireFile && example.Request.File == "" {
		t.Fatalf("%s docs example must name its source-owned input file", requirement.OperationID)
	}
}

func assertPublicDocsOperationSemantics(t *testing.T, root, operationID string, operation publicDocsOpenAPIOperation) {
	t.Helper()
	if strings.TrimSpace(operation.Description) == "" {
		t.Fatalf("%s is missing a source-owned operation description", operationID)
	}
	example := operation.DocsExample
	if example == nil {
		t.Fatalf("%s is missing x-helm-docs-example", operationID)
	}
	if example.Request == nil {
		t.Fatalf("%s docs example is missing request metadata", operationID)
	}
	if len(operation.RequestBody.Content) > 0 && example.Request.ContentType == "" {
		t.Fatalf("%s has a request body but its docs example has no content_type", operationID)
	}
	if example.Request.ContentType != "" {
		if _, ok := operation.RequestBody.Content[example.Request.ContentType]; !ok {
			t.Fatalf("%s docs example content_type=%q is not declared by the operation", operationID, example.Request.ContentType)
		}
	} else if len(example.Request.Literal) > 0 || len(example.Request.Bindings) > 0 || example.Request.File != "" {
		t.Fatalf("%s docs example declares a body or binding without content_type", operationID)
	}
	assertPublicDocsExampleSource(t, root, operationID, example.SourceTest)
}

func assertPublicDocsExampleSource(t *testing.T, root, operationID, sourceTest string) {
	t.Helper()
	sourceFile, sourceTestName, ok := strings.Cut(sourceTest, "#")
	if !ok || sourceFile == "" || sourceTestName == "" {
		t.Fatalf("%s docs example source_test=%q, want path#TestName", operationID, sourceTest)
	}
	if filepath.IsAbs(sourceFile) {
		t.Fatalf("%s docs example source_test must be repository-relative: %q", operationID, sourceTest)
	}
	sourceTestPath := filepath.Join(root, filepath.FromSlash(sourceFile))
	if _, err := os.Stat(sourceTestPath); err != nil {
		t.Fatalf("%s docs example source_test does not resolve: %v", operationID, err)
	}
	sourceTestData, err := os.ReadFile(sourceTestPath)
	if err != nil {
		t.Fatalf("%s read docs example source_test: %v", operationID, err)
	}
	if !regexp.MustCompile(`(?m)^func\s+` + regexp.QuoteMeta(sourceTestName) + `\s*\(`).Match(sourceTestData) {
		t.Fatalf("%s docs example source_test symbol %q is not declared in %s", operationID, sourceTestName, sourceFile)
	}
}

type publicDocsExampleFixture struct {
	SourceTest              string
	RequestContentType      string
	Literal                 map[string]any
	Bindings                map[string]publicDocsResponseBind
	File                    string
	WantStatus              int
	WantResponseContentType string
	PathValues              map[string]string
	Cancel                  bool
}

type publicDocsExampleRoute struct {
	Method    string
	Path      string
	Operation publicDocsOpenAPIOperation
}

type publicDocsExampleResponse struct {
	Body []byte
}

var publicDocsExampleFixtures = map[string]*publicDocsExampleFixture{
	"getPublicDemoHealth":            publicDocsContractExampleFixtures["getPublicDemoHealth"],
	"runPublicDemo":                  publicDocsDemoRunFixture,
	"verifyPublicDemoReceipt":        publicDocsDemoVerifyFixture,
	"tamperPublicDemoReceipt":        publicDocsDemoTamperFixture,
	"chatCompletions":                publicDocsOpenAIChatFixture,
	"evaluateDecision":               publicDocsEvaluateFixture,
	"listReceipts":                   publicDocsContractExampleFixtures["listReceipts"],
	"tailReceipts":                   publicDocsContractExampleFixtures["tailReceipts"],
	"getConsoleReceipt":              publicDocsContractExampleFixtures["getConsoleReceipt"],
	"getBoundaryStatus":              publicDocsContractExampleFixtures["getBoundaryStatus"],
	"exportEvidence":                 publicDocsContractExampleFixtures["exportEvidence"],
	"verifyEvidence":                 publicDocsContractExampleFixtures["verifyEvidence"],
	"listNegativeConformanceVectors": publicDocsContractExampleFixtures["listNegativeConformanceVectors"],
	"listMcpRegistry":                publicDocsContractExampleFixtures["listMcpRegistry"],
	"scanMcpServer":                  publicDocsContractExampleFixtures["scanMcpServer"],
	"authorizeMcpCall":               publicDocsContractExampleFixtures["authorizeMcpCall"],
}

func publicDocsResponseBinding(method, path, jsonPath string) publicDocsResponseBind {
	var binding publicDocsResponseBind
	binding.FromResponse.Method = method
	binding.FromResponse.Path = path
	binding.FromResponse.JSONPath = jsonPath
	return binding
}

func assertPublicDocsExamplesMatchSourceFixturesAndExerciseRuntime(t *testing.T, spec publicDocsOpenAPISpec) {
	t.Helper()
	routes := make(map[string]publicDocsExampleRoute)
	for path, pathItem := range spec.Paths {
		for method, operation := range pathItem {
			if operation.DocsExample == nil {
				continue
			}
			if operation.OperationID == "" {
				t.Fatalf("OpenAPI docs example at %s %s has no operationId", strings.ToUpper(method), path)
			}
			if _, duplicate := routes[operation.OperationID]; duplicate {
				t.Fatalf("duplicate OpenAPI docs example operationId %q", operation.OperationID)
			}
			routes[operation.OperationID] = publicDocsExampleRoute{Method: strings.ToUpper(method), Path: path, Operation: operation}
		}
	}
	if got, want := len(routes), len(publicDocsExampleFixtures); got != want {
		t.Fatalf("OpenAPI docs example count=%d, want %d source-test fixtures", got, want)
	}
	for operationID, fixture := range publicDocsExampleFixtures {
		if fixture == nil {
			t.Fatalf("source-test fixture %q is nil", operationID)
		}
		route, ok := routes[operationID]
		if !ok {
			t.Fatalf("source-test fixture %q has no OpenAPI docs example", operationID)
		}
		example := route.Operation.DocsExample
		if example == nil || example.Request == nil {
			t.Fatalf("%s is missing request metadata", operationID)
		}
		if got := example.SourceTest; got != fixture.SourceTest {
			t.Fatalf("%s source_test=%q, want %q", operationID, got, fixture.SourceTest)
		}
		if got := example.Request.ContentType; got != fixture.RequestContentType {
			t.Fatalf("%s content_type=%q, want source-test fixture %q", operationID, got, fixture.RequestContentType)
		}
		if !reflect.DeepEqual(example.Request.Literal, fixture.Literal) {
			t.Fatalf("%s literal=%#v, want source-test fixture %#v", operationID, example.Request.Literal, fixture.Literal)
		}
		if !reflect.DeepEqual(example.Request.Bindings, fixture.Bindings) {
			t.Fatalf("%s bindings=%#v, want source-test fixture %#v", operationID, example.Request.Bindings, fixture.Bindings)
		}
		if got := example.Request.File; got != fixture.File {
			t.Fatalf("%s file=%q, want source-test fixture %q", operationID, got, fixture.File)
		}
	}
	for operationID := range routes {
		if _, ok := publicDocsExampleFixtures[operationID]; !ok {
			t.Fatalf("OpenAPI docs example %q has no source-test fixture", operationID)
		}
	}

	exercisePublicDocsOpenAPIExamples(t, routes)
}

func exercisePublicDocsOpenAPIExamples(t *testing.T, routes map[string]publicDocsExampleRoute) {
	t.Helper()
	responses := make(map[string]publicDocsExampleResponse)

	signer, err := helmcrypto.NewEd25519Signer("public-docs-openapi-example")
	if err != nil {
		t.Fatal(err)
	}
	demoMux := http.NewServeMux()
	registerDemoRoutes(demoMux, &Services{ReceiptSigner: signer})
	servePublicDocsOpenAPIExample(t, demoMux, publicDocsExampleRouteFor(t, routes, "getPublicDemoHealth"), responses, nil)
	servePublicDocsOpenAPIExample(t, demoMux, publicDocsExampleRouteFor(t, routes, "runPublicDemo"), responses, nil)
	servePublicDocsOpenAPIExample(t, demoMux, publicDocsExampleRouteFor(t, routes, "verifyPublicDemoReceipt"), responses, nil)
	servePublicDocsOpenAPIExample(t, demoMux, publicDocsExampleRouteFor(t, routes, "tamperPublicDemoReceipt"), responses, nil)

	openAIHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleGovernedOpenAIProxy(w, r, &Services{EmergencyStops: &kernel.ScopedStopStore{}})
	})
	servePublicDocsOpenAPIExample(t, openAIHandler, publicDocsExampleRouteFor(t, routes, "chatCompletions"), responses, nil)

	if !t.Run("evaluate metadata", func(t *testing.T) {
		t.Setenv("HELM_ADMIN_API_KEY", testAdminAPIKey)
		t.Setenv(runtimeTenantIDEnv, "tenant-trusted")
		t.Setenv(runtimePrincipalIDEnv, "principal-trusted")
		evaluateSvc, evaluateReceipts := newEvaluateRouteTestServices(t)
		evaluateMux := http.NewServeMux()
		registerReceiptRoutes(evaluateMux, evaluateSvc)
		servePublicDocsOpenAPIExample(t, evaluateMux, publicDocsExampleRouteFor(t, routes, "evaluateDecision"), responses, func(req *http.Request) {
			req.Header.Set(tenantHeader, "tenant-trusted")
			req.Header.Set(principalHeader, "principal-trusted")
		})
		if evaluateReceipts.stored == nil || evaluateReceipts.stored.ExecutorID != "principal-trusted" {
			t.Fatalf("metadata-derived evaluate example did not bind the authenticated principal: %+v", evaluateReceipts.stored)
		}
	}) {
		return
	}

	contractSvc, cleanup := newContractRouteTestServices(t)
	defer cleanup()
	contractMux := http.NewServeMux()
	registerReceiptRoutes(contractMux, contractSvc)
	registerContractRoutes(contractMux, contractSvc)
	for _, operationID := range []string{
		"listReceipts",
		"tailReceipts",
		"getConsoleReceipt",
		"getBoundaryStatus",
		"exportEvidence",
		"verifyEvidence",
		"listNegativeConformanceVectors",
		"listMcpRegistry",
		"scanMcpServer",
	} {
		servePublicDocsOpenAPIExample(t, contractMux, publicDocsExampleRouteFor(t, routes, operationID), responses, nil)
	}
	authorizeRoute := publicDocsExampleRouteFor(t, routes, "authorizeMcpCall")
	preparePublicDocsMCPAuthorizeFixture(t, contractMux, authorizeRoute)
	servePublicDocsOpenAPIExample(t, contractMux, authorizeRoute, responses, nil)
}

func publicDocsExampleRouteFor(t *testing.T, routes map[string]publicDocsExampleRoute, operationID string) publicDocsExampleRoute {
	t.Helper()
	route, ok := routes[operationID]
	if !ok {
		t.Fatalf("OpenAPI docs example %q is missing", operationID)
	}
	return route
}

func servePublicDocsOpenAPIExample(t *testing.T, handler http.Handler, route publicDocsExampleRoute, responses map[string]publicDocsExampleResponse, configure func(*http.Request)) {
	t.Helper()
	fixture := publicDocsExampleFixtureFor(t, route.Operation.OperationID)
	body := publicDocsOpenAPIExampleRequestBody(t, route.Operation.DocsExample, responses)
	req := httptest.NewRequest(route.Method, publicDocsExamplePath(t, route.Path, fixture), body)
	authorizeTestRequest(req)
	if contentType := route.Operation.DocsExample.Request.ContentType; contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if configure != nil {
		configure(req)
	}
	if fixture.Cancel {
		ctx, cancel := context.WithCancel(req.Context())
		cancel()
		req = req.WithContext(ctx)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != fixture.WantStatus {
		t.Fatalf("%s metadata-derived request status=%d, want=%d body=%s", route.Operation.OperationID, rec.Code, fixture.WantStatus, rec.Body.String())
	}
	if fixture.WantResponseContentType != "" && !strings.HasPrefix(rec.Header().Get("Content-Type"), fixture.WantResponseContentType) {
		t.Fatalf("%s metadata-derived response content_type=%q, want prefix %q", route.Operation.OperationID, rec.Header().Get("Content-Type"), fixture.WantResponseContentType)
	}
	responses[route.Method+" "+route.Path] = publicDocsExampleResponse{Body: append([]byte(nil), rec.Body.Bytes()...)}
}

func publicDocsOpenAPIExampleRequestBody(t *testing.T, example *publicDocsOpenAPIExample, responses map[string]publicDocsExampleResponse) io.Reader {
	t.Helper()
	if example == nil || example.Request == nil {
		t.Fatal("OpenAPI docs example is missing request metadata")
	}
	if example.Request.File != "" {
		response, ok := responses[http.MethodPost+" /api/v1/evidence/export"]
		if !ok || len(response.Body) == 0 {
			t.Fatalf("docs example file %q has no in-memory EvidencePack source", example.Request.File)
		}
		return bytes.NewReader(response.Body)
	}
	body := clonePublicDocsLiteral(example.Request.Literal)
	for name, binding := range example.Request.Bindings {
		response, ok := responses[binding.FromResponse.Method+" "+binding.FromResponse.Path]
		if !ok {
			t.Fatalf("docs example binding %q has no response for %s %s", name, binding.FromResponse.Method, binding.FromResponse.Path)
		}
		body[name] = publicDocsResponseJSONPath(t, response.Body, binding.FromResponse.JSONPath)
	}
	if len(body) == 0 {
		return nil
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode metadata-derived docs request: %v", err)
	}
	return bytes.NewReader(encoded)
}

func publicDocsResponseJSONPath(t *testing.T, body []byte, jsonPath string) any {
	t.Helper()
	if !strings.HasPrefix(jsonPath, "$.") {
		t.Fatalf("unsupported docs response JSON path %q", jsonPath)
	}
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatalf("decode docs response for JSON path %q: %v", jsonPath, err)
	}
	for _, segment := range strings.Split(strings.TrimPrefix(jsonPath, "$."), ".") {
		object, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("docs response JSON path %q traverses non-object %T", jsonPath, value)
		}
		var found bool
		value, found = object[segment]
		if !found {
			t.Fatalf("docs response JSON path %q is missing segment %q", jsonPath, segment)
		}
	}
	return value
}

func publicDocsExamplePath(t *testing.T, path string, fixture *publicDocsExampleFixture) string {
	t.Helper()
	for name, value := range fixture.PathValues {
		path = strings.ReplaceAll(path, "{"+name+"}", value)
	}
	if strings.Contains(path, "{") {
		t.Fatalf("docs example path %q has an unbound parameter", path)
	}
	return path
}

func preparePublicDocsMCPAuthorizeFixture(t *testing.T, mux *http.ServeMux, route publicDocsExampleRoute) {
	t.Helper()
	literal := clonePublicDocsLiteral(route.Operation.DocsExample.Request.Literal)
	serverID, ok := literal["server_id"].(string)
	if !ok || serverID == "" {
		t.Fatalf("authorizeMcpCall docs example has no server_id literal")
	}
	discoverBody, err := json.Marshal(map[string]any{"server_id": serverID, "tool_names": []string{"local.echo"}, "risk": "high"})
	if err != nil {
		t.Fatal(err)
	}
	discoverReq := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/registry", bytes.NewReader(discoverBody))
	authorizeTestRequest(discoverReq)
	discoverReq.Header.Set("Content-Type", "application/json")
	discoverRec := httptest.NewRecorder()
	mux.ServeHTTP(discoverRec, discoverReq)
	if discoverRec.Code != http.StatusAccepted {
		t.Fatalf("metadata-derived MCP prerequisite discovery status=%d body=%s", discoverRec.Code, discoverRec.Body.String())
	}
	approveBody := []byte(`{"approver_id":"user:docs","approval_receipt_id":"docs-approval","reason":"fixture prerequisite","tool_names":["local.echo"]}`)
	approveReq := httptest.NewRequest(http.MethodPost, "/api/v1/mcp/registry/"+serverID+"/approve", bytes.NewReader(approveBody))
	authorizeTestRequest(approveReq)
	approveReq.Header.Set("Content-Type", "application/json")
	approveRec := httptest.NewRecorder()
	mux.ServeHTTP(approveRec, approveReq)
	if approveRec.Code != http.StatusOK {
		t.Fatalf("metadata-derived MCP prerequisite approval status=%d body=%s", approveRec.Code, approveRec.Body.String())
	}
}

func publicDocsExampleFixtureFor(t *testing.T, operationID string) *publicDocsExampleFixture {
	t.Helper()
	fixture, ok := publicDocsExampleFixtures[operationID]
	if !ok || fixture == nil {
		t.Fatalf("source-test fixture %q is missing", operationID)
	}
	return fixture
}

func publicDocsExampleFixtureLiteral(fixture *publicDocsExampleFixture) map[string]any {
	if fixture == nil {
		return nil
	}
	return clonePublicDocsLiteral(fixture.Literal)
}

func publicDocsExampleFixtureJSON(t *testing.T, fixture *publicDocsExampleFixture, bindings map[string]any) []byte {
	t.Helper()
	if fixture == nil {
		t.Fatal("source-test fixture is nil")
	}
	body := publicDocsExampleFixtureLiteral(fixture)
	for name, value := range bindings {
		body[name] = value
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("encode source-test fixture %q: %v", fixture.SourceTest, err)
	}
	return encoded
}

func publicDocsExampleFixtureFile(t *testing.T, fixture *publicDocsExampleFixture) string {
	t.Helper()
	if fixture == nil {
		t.Fatal("source-test fixture is nil")
	}
	file := fixture.File
	if file == "" {
		t.Fatalf("source-test fixture %q has no file", fixture.SourceTest)
	}
	return file
}

func clonePublicDocsLiteral(literal map[string]any) map[string]any {
	if len(literal) == 0 {
		return make(map[string]any)
	}
	clone := make(map[string]any, len(literal))
	for name, value := range literal {
		clone[name] = value
	}
	return clone
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
