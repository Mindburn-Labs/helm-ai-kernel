package main

import "net/http"

type RouteAuth string
type RouteRateLimit string
type RouteContractStatus string

const (
	RouteAuthPublic        RouteAuth = "public"
	RouteAuthAuthenticated RouteAuth = "authenticated"
	RouteAuthAdmin         RouteAuth = "admin"
	RouteAuthService       RouteAuth = "service_internal"
	RouteAuthTenant        RouteAuth = "tenant_scoped"

	RouteRatePublic   RouteRateLimit = "public"
	RouteRateKernel   RouteRateLimit = "kernel"
	RouteRateEvidence RouteRateLimit = "evidence"
	RouteRateAdmin    RouteRateLimit = "admin"
	RouteRateStream   RouteRateLimit = "stream"

	RouteContractPublic         RouteContractStatus = "public"
	RouteContractInternal       RouteContractStatus = "internal"
	RouteContractCompatibility  RouteContractStatus = "compatibility"
	RouteContractImplementation RouteContractStatus = "implementation"
)

type RuntimeRouteSpec struct {
	Method         string
	Path           string
	MuxPattern     string
	Auth           RouteAuth
	RateLimit      RouteRateLimit
	ContractStatus RouteContractStatus
	OperationID    string
	Owner          string
}

func RuntimeRouteSpecs() []RuntimeRouteSpec {
	return []RuntimeRouteSpec{
		{Method: http.MethodPost, Path: "/v1/chat/completions", MuxPattern: "/v1/chat/completions", Auth: RouteAuthPublic, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "chatCompletions", Owner: "core/cmd/helm"},
		{Method: http.MethodPost, Path: "/api/v1/kernel/approve", MuxPattern: "/api/v1/kernel/approve", Auth: RouteAuthService, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "approveIntent", Owner: "core/pkg/api"},
		{Method: http.MethodPost, Path: "/api/v1/evaluate", MuxPattern: "/api/v1/evaluate", Auth: RouteAuthPublic, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "evaluateDecision", Owner: "core/cmd/helm"},
		{Method: http.MethodGet, Path: "/api/v1/receipts", MuxPattern: "/api/v1/receipts", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "listReceipts", Owner: "core/cmd/helm"},
		{Method: http.MethodGet, Path: "/api/v1/receipts/tail", MuxPattern: "/api/v1/receipts/tail", Auth: RouteAuthTenant, RateLimit: RouteRateStream, ContractStatus: RouteContractPublic, OperationID: "tailReceipts", Owner: "core/cmd/helm"},
		{Method: http.MethodGet, Path: "/api/v1/receipts/{receipt_id}", MuxPattern: "/api/v1/receipts/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "getConsoleReceipt", Owner: "core/cmd/helm"},
		{Method: http.MethodGet, Path: "/api/v1/console/bootstrap", MuxPattern: "/api/v1/console/bootstrap", Auth: RouteAuthTenant, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "getConsoleBootstrap", Owner: "core/cmd/helm"},
		{Method: http.MethodGet, Path: "/api/v1/console/surfaces", MuxPattern: "/api/v1/console/surfaces", Auth: RouteAuthTenant, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "listConsoleSurfaces", Owner: "core/cmd/helm"},
		{Method: http.MethodGet, Path: "/api/v1/console/surfaces/{surface_id}", MuxPattern: "/api/v1/console/surfaces/", Auth: RouteAuthTenant, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "getConsoleSurface", Owner: "core/cmd/helm"},
		{Method: http.MethodPost, Path: "/api/v1/trust/keys/add", MuxPattern: "/api/v1/trust/keys/add", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "addTrustKey", Owner: "core/pkg/api"},
		{Method: http.MethodPost, Path: "/api/v1/trust/keys/revoke", MuxPattern: "/api/v1/trust/keys/revoke", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "revokeTrustKey", Owner: "core/pkg/api"},
		{Method: http.MethodGet, Path: "/mcp", MuxPattern: "/mcp", Auth: RouteAuthPublic, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "getMCPTransport", Owner: "core/pkg/mcp"},
		{Method: http.MethodPost, Path: "/mcp", MuxPattern: "/mcp", Auth: RouteAuthPublic, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "postMCPJSONRPC", Owner: "core/pkg/mcp"},
		{Method: http.MethodGet, Path: "/.well-known/oauth-protected-resource/mcp", MuxPattern: "/.well-known/oauth-protected-resource/mcp", Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "getMCPProtectedResourceMetadata", Owner: "core/pkg/mcp"},
		{Method: http.MethodGet, Path: "/api/v1/proofgraph/sessions", MuxPattern: "/api/v1/proofgraph/sessions", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "listSessions", Owner: "core/cmd/helm"},
		{Method: http.MethodGet, Path: "/api/v1/proofgraph/sessions/{session_id}/receipts", MuxPattern: "/api/v1/proofgraph/sessions/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "getSessionReceipts", Owner: "core/cmd/helm"},
		{Method: http.MethodGet, Path: "/api/v1/proofgraph/receipts/{receipt_hash}", MuxPattern: "/api/v1/proofgraph/receipts/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "getReceipt", Owner: "core/cmd/helm"},
		{Method: http.MethodPost, Path: "/api/v1/evidence/export", MuxPattern: "/api/v1/evidence/export", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "exportEvidence", Owner: "core/cmd/helm"},
		{Method: http.MethodPost, Path: "/api/v1/evidence/verify", MuxPattern: "/api/v1/evidence/verify", Auth: RouteAuthPublic, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "verifyEvidence", Owner: "core/cmd/helm"},
		{Method: http.MethodPost, Path: "/api/v1/replay/verify", MuxPattern: "/api/v1/replay/verify", Auth: RouteAuthPublic, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "replayVerify", Owner: "core/cmd/helm"},
		{Method: http.MethodPost, Path: "/api/v1/conformance/run", MuxPattern: "/api/v1/conformance/run", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "runConformance", Owner: "core/cmd/helm"},
		{Method: http.MethodGet, Path: "/api/v1/conformance/reports/{report_id}", MuxPattern: "/api/v1/conformance/reports/", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "getConformanceReport", Owner: "core/cmd/helm"},
		{Method: http.MethodGet, Path: "/mcp/v1/capabilities", MuxPattern: "/mcp/v1/capabilities", Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "listMCPCapabilities", Owner: "core/pkg/mcp"},
		{Method: http.MethodPost, Path: "/mcp/v1/execute", MuxPattern: "/mcp/v1/execute", Auth: RouteAuthPublic, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "executeMCPTool", Owner: "core/pkg/mcp"},
		{Method: http.MethodGet, Path: "/healthz", MuxPattern: "/healthz", Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "healthCheck", Owner: "core/cmd/helm"},
		{Method: http.MethodGet, Path: "/version", MuxPattern: "/version", Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "getVersion", Owner: "core/cmd/helm"},

		{Method: http.MethodPost, Path: "/api/v1/evidence/envelopes", MuxPattern: "/api/v1/evidence/envelopes", Auth: RouteAuthAdmin, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "createEvidenceEnvelopeManifest", Owner: "core/cmd/helm"},
		{Method: http.MethodGet, Path: "/api/v1/conformance/negative", MuxPattern: "/api/v1/conformance/negative", Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "listNegativeConformanceVectors", Owner: "core/cmd/helm"},
		{Method: http.MethodGet, Path: "/api/v1/mcp/registry", MuxPattern: "/api/v1/mcp/registry", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "listMcpRegistry", Owner: "core/cmd/helm"},
		{Method: http.MethodPost, Path: "/api/v1/mcp/registry", MuxPattern: "/api/v1/mcp/registry", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "discoverMcpServer", Owner: "core/cmd/helm"},
		{Method: http.MethodPost, Path: "/api/v1/mcp/registry/approve", MuxPattern: "/api/v1/mcp/registry/approve", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "approveMcpServer", Owner: "core/cmd/helm"},
		{Method: http.MethodGet, Path: "/api/v1/sandbox/grants/inspect", MuxPattern: "/api/v1/sandbox/grants/inspect", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "inspectSandboxGrants", Owner: "core/cmd/helm"},
		{Method: http.MethodGet, Path: "/api/v1/evidence/soc2", MuxPattern: "/api/v1/evidence/soc2", Auth: RouteAuthAdmin, RateLimit: RouteRateEvidence, ContractStatus: RouteContractImplementation, OperationID: "exportSOC2Evidence", Owner: "core/cmd/helm"},
		{Method: http.MethodGet, Path: "/api/v1/merkle/root", MuxPattern: "/api/v1/merkle/root", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractImplementation, OperationID: "getMerkleRoot", Owner: "core/cmd/helm"},
		{Method: http.MethodGet, Path: "/api/v1/budget/status", MuxPattern: "/api/v1/budget/status", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractImplementation, OperationID: "getBudgetStatus", Owner: "core/cmd/helm"},
		{Method: http.MethodGet, Path: "/api/v1/authz/check", MuxPattern: "/api/v1/authz/check", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractImplementation, OperationID: "getAuthzStatus", Owner: "core/cmd/helm"},
	}
}

func PublicRuntimeRouteSpecs() []RuntimeRouteSpec {
	specs := RuntimeRouteSpecs()
	public := make([]RuntimeRouteSpec, 0, len(specs))
	for _, spec := range specs {
		if spec.ContractStatus == RouteContractPublic {
			public = append(public, spec)
		}
	}
	return public
}
