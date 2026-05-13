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
		{Method: http.MethodPost, Path: "/v1/chat/completions", MuxPattern: "/v1/chat/completions", Auth: RouteAuthPublic, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "chatCompletions", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/internal/policy/reconcile", MuxPattern: "/internal/policy/reconcile", Auth: RouteAuthService, RateLimit: RouteRateAdmin, ContractStatus: RouteContractInternal, OperationID: "wakePolicyReconciler", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/kernel/approve", MuxPattern: "/api/v1/kernel/approve", Auth: RouteAuthService, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "approveIntent", Owner: "core/pkg/api"},
		{Method: http.MethodGet, Path: "/api/health", MuxPattern: "/api/health", Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "getPublicDemoHealth", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/demo/run", MuxPattern: "/api/demo/run", Auth: RouteAuthPublic, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "runPublicDemo", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/demo/verify", MuxPattern: "/api/demo/verify", Auth: RouteAuthPublic, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "verifyPublicDemoReceipt", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/demo/tamper", MuxPattern: "/api/demo/tamper", Auth: RouteAuthPublic, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "tamperPublicDemoReceipt", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/evaluate", MuxPattern: "/api/v1/evaluate", Auth: RouteAuthPublic, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "evaluateDecision", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/receipts", MuxPattern: "/api/v1/receipts", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "listReceipts", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/receipts/tail", MuxPattern: "/api/v1/receipts/tail", Auth: RouteAuthTenant, RateLimit: RouteRateStream, ContractStatus: RouteContractPublic, OperationID: "tailReceipts", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/receipts/{receipt_id}", MuxPattern: "/api/v1/receipts/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "getConsoleReceipt", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/console/bootstrap", MuxPattern: "/api/v1/console/bootstrap", Auth: RouteAuthTenant, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "getConsoleBootstrap", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/console/surfaces", MuxPattern: "/api/v1/console/surfaces", Auth: RouteAuthTenant, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "listConsoleSurfaces", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/console/surfaces/{surface_id}", MuxPattern: "/api/v1/console/surfaces/", Auth: RouteAuthTenant, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "getConsoleSurface", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/agent-ui/info", MuxPattern: "/api/v1/agent-ui/info", Auth: RouteAuthTenant, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "getAgentUIRuntimeInfo", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/agent-ui/run", MuxPattern: "/api/v1/agent-ui/run", Auth: RouteAuthTenant, RateLimit: RouteRateStream, ContractStatus: RouteContractPublic, OperationID: "runAgentUIRuntime", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/ag-ui/info", MuxPattern: "/api/ag-ui/info", Auth: RouteAuthTenant, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "getAGUIRuntimeInfoCompat", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/ag-ui/run", MuxPattern: "/api/ag-ui/run", Auth: RouteAuthTenant, RateLimit: RouteRateStream, ContractStatus: RouteContractPublic, OperationID: "runAGUIRuntimeCompat", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/trust/keys/add", MuxPattern: "/api/v1/trust/keys/add", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "addTrustKey", Owner: "core/pkg/api"},
		{Method: http.MethodPost, Path: "/api/v1/trust/keys/revoke", MuxPattern: "/api/v1/trust/keys/revoke", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "revokeTrustKey", Owner: "core/pkg/api"},
		{Method: http.MethodGet, Path: "/mcp", MuxPattern: "/mcp", Auth: RouteAuthPublic, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "getMCPTransport", Owner: "core/pkg/mcp"},
		{Method: http.MethodPost, Path: "/mcp", MuxPattern: "/mcp", Auth: RouteAuthPublic, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "postMCPJSONRPC", Owner: "core/pkg/mcp"},
		{Method: http.MethodGet, Path: "/.well-known/oauth-protected-resource/mcp", MuxPattern: "/.well-known/oauth-protected-resource/mcp", Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "getMCPProtectedResourceMetadata", Owner: "core/pkg/mcp"},
		{Method: http.MethodGet, Path: "/.well-known/agent-card.json", MuxPattern: "/.well-known/agent-card.json", Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "getA2AAgentCard", Owner: "core/pkg/a2a"},
		{Method: http.MethodGet, Path: "/api/v1/proofgraph/sessions", MuxPattern: "/api/v1/proofgraph/sessions", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "listSessions", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/proofgraph/sessions/{session_id}/receipts", MuxPattern: "/api/v1/proofgraph/sessions/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "getSessionReceipts", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/proofgraph/receipts/{receipt_hash}", MuxPattern: "/api/v1/proofgraph/receipts/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "getReceipt", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/evidence/export", MuxPattern: "/api/v1/evidence/export", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "exportEvidence", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/evidence/verify", MuxPattern: "/api/v1/evidence/verify", Auth: RouteAuthPublic, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "verifyEvidence", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/replay/verify", MuxPattern: "/api/v1/replay/verify", Auth: RouteAuthPublic, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "replayVerify", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/conformance/run", MuxPattern: "/api/v1/conformance/run", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "runConformance", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/conformance/reports/{report_id}", MuxPattern: "/api/v1/conformance/reports/", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "getConformanceReport", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/mcp/v1/capabilities", MuxPattern: "/mcp/v1/capabilities", Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "listMCPCapabilities", Owner: "core/pkg/mcp"},
		{Method: http.MethodPost, Path: "/mcp/v1/execute", MuxPattern: "/mcp/v1/execute", Auth: RouteAuthPublic, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "executeMCPTool", Owner: "core/pkg/mcp"},
		{Method: http.MethodGet, Path: "/healthz", MuxPattern: "/healthz", Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "healthCheck", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/version", MuxPattern: "/version", Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "getVersion", Owner: "core/cmd/helm-ai-kernel"},

		{Method: http.MethodGet, Path: "/api/v1/boundary/status", MuxPattern: "/api/v1/boundary/status", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "getBoundaryStatus", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/boundary/capabilities", MuxPattern: "/api/v1/boundary/capabilities", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "listBoundaryCapabilities", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/boundary/records", MuxPattern: "/api/v1/boundary/records", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "listBoundaryRecords", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/boundary/records/{record_id}", MuxPattern: "/api/v1/boundary/records/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "getBoundaryRecord", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/boundary/records/{record_id}/verify", MuxPattern: "/api/v1/boundary/records/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "verifyBoundaryRecord", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/boundary/checkpoints", MuxPattern: "/api/v1/boundary/checkpoints", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "listBoundaryCheckpoints", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/boundary/checkpoints", MuxPattern: "/api/v1/boundary/checkpoints", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "createBoundaryCheckpoint", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/boundary/checkpoints/{checkpoint_id}/verify", MuxPattern: "/api/v1/boundary/checkpoints/", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "verifyBoundaryCheckpoint", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/evidence/envelopes", MuxPattern: "/api/v1/evidence/envelopes", Auth: RouteAuthAdmin, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "createEvidenceEnvelopeManifest", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/evidence/envelopes", MuxPattern: "/api/v1/evidence/envelopes", Auth: RouteAuthAdmin, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "listEvidenceEnvelopeManifests", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/evidence/envelopes/{manifest_id}", MuxPattern: "/api/v1/evidence/envelopes/", Auth: RouteAuthAdmin, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "getEvidenceEnvelopeManifest", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/evidence/envelopes/{manifest_id}/payload", MuxPattern: "/api/v1/evidence/envelopes/", Auth: RouteAuthAdmin, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "getEvidenceEnvelopePayload", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/evidence/envelopes/{manifest_id}/verify", MuxPattern: "/api/v1/evidence/envelopes/", Auth: RouteAuthAdmin, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "verifyEvidenceEnvelopeManifest", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/conformance/reports", MuxPattern: "/api/v1/conformance/reports", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "listConformanceReports", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/conformance/vectors", MuxPattern: "/api/v1/conformance/vectors", Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "listConformanceVectors", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/conformance/negative", MuxPattern: "/api/v1/conformance/negative", Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "listNegativeConformanceVectors", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/mcp/registry", MuxPattern: "/api/v1/mcp/registry", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "listMcpRegistry", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/mcp/registry", MuxPattern: "/api/v1/mcp/registry", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "discoverMcpServer", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/mcp/registry/approve", MuxPattern: "/api/v1/mcp/registry/approve", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "approveMcpServer", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/mcp/registry/{server_id}", MuxPattern: "/api/v1/mcp/registry/", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "getMcpRegistryRecord", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/mcp/registry/{server_id}/approve", MuxPattern: "/api/v1/mcp/registry/", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "approveMcpRegistryRecord", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/mcp/registry/{server_id}/revoke", MuxPattern: "/api/v1/mcp/registry/", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "revokeMcpRegistryRecord", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/mcp/scan", MuxPattern: "/api/v1/mcp/scan", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "scanMcpServer", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/mcp/auth-profiles", MuxPattern: "/api/v1/mcp/auth-profiles", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "listMcpAuthProfiles", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPut, Path: "/api/v1/mcp/auth-profiles/{profile_id}", MuxPattern: "/api/v1/mcp/auth-profiles/", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "putMcpAuthProfile", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/mcp/authorize-call", MuxPattern: "/api/v1/mcp/authorize-call", Auth: RouteAuthAdmin, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "authorizeMcpCall", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/sandbox/profiles", MuxPattern: "/api/v1/sandbox/profiles", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "listSandboxProfiles", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/sandbox/grants", MuxPattern: "/api/v1/sandbox/grants", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "listSandboxGrants", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/sandbox/grants", MuxPattern: "/api/v1/sandbox/grants", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "createSandboxGrant", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/sandbox/grants/{grant_id}", MuxPattern: "/api/v1/sandbox/grants/", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "getSandboxGrant", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/sandbox/grants/{grant_id}/verify", MuxPattern: "/api/v1/sandbox/grants/", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "verifySandboxGrant", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/sandbox/preflight", MuxPattern: "/api/v1/sandbox/preflight", Auth: RouteAuthAdmin, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "preflightSandboxGrant", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/sandbox/grants/inspect", MuxPattern: "/api/v1/sandbox/grants/inspect", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "inspectSandboxGrants", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/identity/agents", MuxPattern: "/api/v1/identity/agents", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "listAgentIdentities", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/authz/health", MuxPattern: "/api/v1/authz/health", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "getAuthzHealth", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/authz/check", MuxPattern: "/api/v1/authz/check", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "checkAuthz", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/authz/snapshots", MuxPattern: "/api/v1/authz/snapshots", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "listAuthzSnapshots", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/authz/snapshots/{snapshot_id}", MuxPattern: "/api/v1/authz/snapshots/", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "getAuthzSnapshot", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/approvals", MuxPattern: "/api/v1/approvals", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "listApprovalCeremonies", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/approvals", MuxPattern: "/api/v1/approvals", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "createApprovalCeremony", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/approvals/{approval_id}/webauthn/challenge", MuxPattern: "/api/v1/approvals/", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "createApprovalWebAuthnChallenge", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/approvals/{approval_id}/webauthn/assert", MuxPattern: "/api/v1/approvals/", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "assertApprovalWebAuthnChallenge", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/approvals/{approval_id}/{action}", MuxPattern: "/api/v1/approvals/", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "transitionApprovalCeremony", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/budgets", MuxPattern: "/api/v1/budgets", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "listBudgetCeilings", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPut, Path: "/api/v1/budgets/{budget_id}", MuxPattern: "/api/v1/budgets/", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "putBudgetCeiling", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/coexistence/capabilities", MuxPattern: "/api/v1/coexistence/capabilities", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "getCoexistenceCapabilities", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/telemetry/otel/config", MuxPattern: "/api/v1/telemetry/otel/config", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "getTelemetryOTelConfig", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/telemetry/export", MuxPattern: "/api/v1/telemetry/export", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "exportTelemetry", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/evidence/soc2", MuxPattern: "/api/v1/evidence/soc2", Auth: RouteAuthAdmin, RateLimit: RouteRateEvidence, ContractStatus: RouteContractImplementation, OperationID: "exportSOC2Evidence", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/merkle/root", MuxPattern: "/api/v1/merkle/root", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractImplementation, OperationID: "getMerkleRoot", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/budget/status", MuxPattern: "/api/v1/budget/status", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractImplementation, OperationID: "getBudgetStatus", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/authz/check", MuxPattern: "/api/v1/authz/check", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractImplementation, OperationID: "getAuthzStatus", Owner: "core/cmd/helm-ai-kernel"},
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
