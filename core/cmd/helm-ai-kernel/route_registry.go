package main

import "net/http"

type RouteAuth string
type RouteRateLimit string
type RouteContractStatus string

const (
	RouteAuthPublic              RouteAuth = "public"
	RouteAuthAuthenticated       RouteAuth = "authenticated"
	RouteAuthAdmin               RouteAuth = "admin"
	RouteAuthService             RouteAuth = "service_internal"
	RouteAuthWorkload            RouteAuth = "workload_jwt"
	RouteAuthTenant              RouteAuth = "tenant_scoped"
	RouteAuthOrganizationRuntime RouteAuth = "organization_runtime_service"
	RouteAuthConfiguredTenant    RouteAuth = "configured_tenant"
	RouteAuthLoopback            RouteAuth = "loopback_peer_proof"

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
		{Method: http.MethodPost, Path: "/api/v1/obligation/create", MuxPattern: "/api/v1/obligation/create", Auth: RouteAuthAdmin, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "createObligation", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/boundary/check", MuxPattern: "/api/v1/boundary/check", Auth: RouteAuthAdmin, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "checkBoundaryEgress", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/sandbox/status", MuxPattern: "/api/v1/sandbox/status", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractInternal, OperationID: "getSandboxStatus", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/config/status", MuxPattern: "/api/v1/config/status", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractInternal, OperationID: "getConfigStatus", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/context/bundles", MuxPattern: "/api/v1/context/bundles", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractInternal, OperationID: "listContextBundles", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/economic/authorities", MuxPattern: "/api/v1/economic/authorities", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractInternal, OperationID: "listEconomicAuthorities", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/economic/charges", MuxPattern: "/api/v1/economic/charges", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractInternal, OperationID: "listEconomicCharges", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/economic/allocations", MuxPattern: "/api/v1/economic/allocations", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractInternal, OperationID: "listEconomicAllocations", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/governance/edge/status", MuxPattern: "/api/v1/governance/edge/status", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractInternal, OperationID: "getEdgeGovernanceStatus", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/compatibility", MuxPattern: "/api/v1/compatibility", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractInternal, OperationID: "getCompatibility", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/v1/chat/completions", MuxPattern: "/v1/chat/completions", Auth: RouteAuthConfiguredTenant, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "chatCompletions", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/internal/policy/reconcile", MuxPattern: "/internal/policy/reconcile", Auth: RouteAuthService, RateLimit: RouteRateAdmin, ContractStatus: RouteContractInternal, OperationID: "wakePolicyReconciler", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: emergencyStopFencePath, MuxPattern: emergencyStopFencePath, Auth: RouteAuthService, RateLimit: RouteRateAdmin, ContractStatus: RouteContractInternal, OperationID: "fenceEmergencyStop", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/extauthz/authorize", MuxPattern: "/api/v1/extauthz/authorize", Auth: RouteAuthService, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "authorizeExtAuthz", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: approvalGrantConsumePath, MuxPattern: approvalGrantConsumePath, Auth: RouteAuthWorkload, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "consumeApprovalGrant", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: approvalGrantConsumptionRecoverPath, MuxPattern: approvalGrantConsumptionRecoverPath, Auth: RouteAuthWorkload, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "recoverApprovalGrantConsumption", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: approvalDispatchAdmissionPath, MuxPattern: approvalDispatchAdmissionPath, Auth: RouteAuthWorkload, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "admitApprovalDispatch", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: approvalDispatchAdmissionRecoverPath, MuxPattern: approvalDispatchAdmissionRecoverPath, Auth: RouteAuthWorkload, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "recoverApprovalDispatchAdmission", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: approvalCeremoniesPath, MuxPattern: approvalCeremoniesPath, Auth: RouteAuthWorkload, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "beginApprovalCeremony", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: approvalCeremoniesPath + "/{approval_id}", MuxPattern: approvalCeremoniesPath + "/", Auth: RouteAuthWorkload, RateLimit: RouteRateEvidence, ContractStatus: RouteContractInternal, OperationID: "getApprovalCeremony", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: approvalCeremoniesPath + "/{approval_id}/challenge", MuxPattern: approvalCeremoniesPath + "/", Auth: RouteAuthWorkload, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "issueApprovalCeremonyChallenge", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: approvalCeremoniesPath + "/{approval_id}/assertions", MuxPattern: approvalCeremoniesPath + "/", Auth: RouteAuthWorkload, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "submitApprovalCeremonyAssertions", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: effectDispositionPath, MuxPattern: effectDispositionPath, Auth: RouteAuthWorkload, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "recordEffectDisposition", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: effectDispositionRecoverPath, MuxPattern: effectDispositionRecoverPath, Auth: RouteAuthWorkload, RateLimit: RouteRateEvidence, ContractStatus: RouteContractInternal, OperationID: "recoverEffectDisposition", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: effectReconciliationCandidatesPath, MuxPattern: effectReconciliationCandidatesPath, Auth: RouteAuthWorkload, RateLimit: RouteRateEvidence, ContractStatus: RouteContractInternal, OperationID: "listEffectReconciliationCandidates", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: localConsolePeerProofPath, MuxPattern: localConsolePeerProofPath, Auth: RouteAuthLoopback, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "getLocalConsolePeerProof", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodHead, Path: localConsolePeerProofPath, MuxPattern: localConsolePeerProofPath, Auth: RouteAuthLoopback, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "checkLocalConsolePeerProof", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: desktopTransportV1ProofPath, MuxPattern: desktopTransportV1ProofPath, Auth: RouteAuthLoopback, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "proveDesktopTransport", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/kernel/approve", MuxPattern: "/api/v1/kernel/approve", Auth: RouteAuthService, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "approveIntent", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/health", MuxPattern: "/api/health", Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "getPublicDemoHealth", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/demo/run", MuxPattern: "/api/demo/run", Auth: RouteAuthPublic, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "runPublicDemo", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/demo/verify", MuxPattern: "/api/demo/verify", Auth: RouteAuthPublic, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "verifyPublicDemoReceipt", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/demo/tamper", MuxPattern: "/api/demo/tamper", Auth: RouteAuthPublic, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "tamperPublicDemoReceipt", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/evaluate", MuxPattern: "/api/v1/evaluate", Auth: RouteAuthTenant, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "evaluateDecision", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: companyActivationOrganizationRuntimePath, MuxPattern: companyActivationOrganizationRuntimePath, Auth: RouteAuthOrganizationRuntime, RateLimit: RouteRateKernel, ContractStatus: RouteContractInternal, OperationID: "evaluateOrganizationRuntimeDecision", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/receipts", MuxPattern: "/api/v1/receipts", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "listReceipts", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/receipts/tail", MuxPattern: "/api/v1/receipts/tail", Auth: RouteAuthTenant, RateLimit: RouteRateStream, ContractStatus: RouteContractPublic, OperationID: "tailReceipts", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/receipts/{receipt_id}", MuxPattern: "/api/v1/receipts/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "getConsoleReceipt", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/__helm/config.json", MuxPattern: "/__helm/config.json", Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "getLocalConsoleRuntimeConfig", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/local-session/exchange", MuxPattern: "/api/v1/local-session/exchange", Auth: RouteAuthPublic, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "exchangeLocalQuickstartSession", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/onboarding/state", MuxPattern: "/api/v1/onboarding/state", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "getLocalOnboardingState", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/onboarding/run-step", MuxPattern: "/api/v1/onboarding/run-step", Auth: RouteAuthTenant, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "runLocalOnboardingStep", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/onboarding/export", MuxPattern: "/api/v1/onboarding/export", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "exportLocalOnboardingEvidence", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/console/bootstrap", MuxPattern: "/api/v1/console/bootstrap", Auth: RouteAuthTenant, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "getConsoleBootstrap", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/console/diagnostics", MuxPattern: "/api/v1/console/diagnostics", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractPublic, OperationID: "getConsoleDiagnostics", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/console/surfaces", MuxPattern: "/api/v1/console/surfaces", Auth: RouteAuthTenant, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "listConsoleSurfaces", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/console/surfaces/{surface_id}", MuxPattern: "/api/v1/console/surfaces/", Auth: RouteAuthTenant, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "getConsoleSurface", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/agent-ui/info", MuxPattern: "/api/v1/agent-ui/info", Auth: RouteAuthTenant, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "getAgentUIRuntimeInfo", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/agent-ui/run", MuxPattern: "/api/v1/agent-ui/run", Auth: RouteAuthTenant, RateLimit: RouteRateStream, ContractStatus: RouteContractPublic, OperationID: "runAgentUIRuntime", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/launchpad/apps", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "listLaunchpadApps", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/launchpad/substrates", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "listLaunchpadSubstrates", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/launchpad/matrix", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "getLaunchpadMatrix", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/launchpad/plan", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "planLaunchpadRun", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/launchpad/launch", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "createLaunchpadRun", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/launchpad/imports", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "listLaunchpadImports", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/launchpad/imports", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "createLaunchpadImport", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/launchpad/imports/{import_id}", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "getLaunchpadImport", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/launchpad/imports/{import_id}/preflight", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "preflightLaunchpadImport", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/launchpad/imports/{import_id}/promote", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "promoteLaunchpadImport", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/launchpad/imports/{import_id}/launch", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "launchImportedApp", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/launchpad/imports/{import_id}/teardown", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "teardownLaunchpadImport", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/launchpad/runs", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "listLaunchpadRuns", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/launchpad/runs", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "createLaunchpadRuntimeRun", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/launchpad/runs/{run_id}", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "getLaunchpadRuntimeRun", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/launchpad/runs/{run_id}/events", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "listLaunchpadRunEvents", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/launchpad/runs/{run_id}/receipts", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "listLaunchpadRunReceipts", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/launchpad/runs/{run_id}/logs", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "getLaunchpadRunLogs", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/launchpad/runs/{run_id}/evidence/export", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "exportLaunchpadRunEvidence", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/launchpad/runs/{run_id}/teardown", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "teardownLaunchpadRuntimeRun", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/launchpad/policy/simulate", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "simulateLaunchpadPolicy", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/launchpad/sandbox/{run_id}", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "inspectLaunchpadSandbox", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/launchpad/mcp/threat-reviews", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "listLaunchpadMcpThreatReviews", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/launchpad/mcp/approvals", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "approveLaunchpadMcpTools", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/launchpad/launches/{launch_id}", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "getLaunchpadRun", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/launchpad/launches/{launch_id}/repair", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "repairLaunchpadRun", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/launchpad/launches/{launch_id}/delete", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "deleteLaunchpadRun", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/launchpad/secrets", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "listLaunchpadSecretGrants", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/launchpad/secrets", MuxPattern: "/api/v1/launchpad/", Auth: RouteAuthTenant, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "bindLaunchpadSecretGrant", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/ag-ui/info", MuxPattern: "/api/ag-ui/info", Auth: RouteAuthTenant, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "getAGUIRuntimeInfoCompat", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/ag-ui/run", MuxPattern: "/api/ag-ui/run", Auth: RouteAuthTenant, RateLimit: RouteRateStream, ContractStatus: RouteContractPublic, OperationID: "runAGUIRuntimeCompat", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/mcp", MuxPattern: "/mcp", Auth: RouteAuthAdmin, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "getMCPTransport", Owner: "core/pkg/mcp"},
		{Method: http.MethodPost, Path: "/mcp", MuxPattern: "/mcp", Auth: RouteAuthAdmin, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "postMCPJSONRPC", Owner: "core/pkg/mcp"},
		{Method: http.MethodGet, Path: "/.well-known/oauth-protected-resource/mcp", MuxPattern: "/.well-known/oauth-protected-resource/mcp", Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "getMCPProtectedResourceMetadata", Owner: "core/pkg/mcp"},
		{Method: http.MethodGet, Path: "/.well-known/agent-card.json", MuxPattern: "/.well-known/agent-card.json", Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "getA2AAgentCard", Owner: "core/pkg/a2a"},
		{Method: http.MethodGet, Path: "/api/v1/proofgraph/sessions", MuxPattern: "/api/v1/proofgraph/sessions", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "listSessions", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/proofgraph/sessions/{session_id}/receipts", MuxPattern: "/api/v1/proofgraph/sessions/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "getSessionReceipts", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/proofgraph/receipts/{receipt_hash}", MuxPattern: "/api/v1/proofgraph/receipts/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "getReceipt", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/evidence/export", MuxPattern: "/api/v1/evidence/export", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "exportEvidence", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/evidence/verify", MuxPattern: "/api/v1/evidence/verify", Auth: RouteAuthPublic, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "verifyEvidence", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/evidence/verification-scopes", MuxPattern: "/api/v1/evidence/verification-scopes", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "listVerificationScopes", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/evidence/verification-scopes", MuxPattern: "/api/v1/evidence/verification-scopes", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "createVerificationScope", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/evidence/verification-scopes/{scope_id}", MuxPattern: "/api/v1/evidence/verification-scopes/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "getVerificationScope", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/evidence/verification-scopes/{scope_id}/verify", MuxPattern: "/api/v1/evidence/verification-scopes/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "verifyVerificationScope", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/telemetry/harness-traces", MuxPattern: "/api/v1/telemetry/harness-traces", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "listHarnessTraces", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/telemetry/harness-traces", MuxPattern: "/api/v1/telemetry/harness-traces", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "createHarnessTrace", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/telemetry/harness-traces/{trace_id}", MuxPattern: "/api/v1/telemetry/harness-traces/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "getHarnessTrace", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/telemetry/harness-traces/{trace_id}/verify", MuxPattern: "/api/v1/telemetry/harness-traces/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "verifyHarnessTrace", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/plans/transactions", MuxPattern: "/api/v1/plans/transactions", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "listPlanTransactions", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/plans/transactions", MuxPattern: "/api/v1/plans/transactions", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "createPlanTransaction", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/plans/transactions/{transaction_id}", MuxPattern: "/api/v1/plans/transactions/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "getPlanTransaction", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/plans/transactions/{transaction_id}/verify", MuxPattern: "/api/v1/plans/transactions/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "verifyPlanTransaction", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/harness/change-contracts", MuxPattern: "/api/v1/harness/change-contracts", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "listHarnessChangeContracts", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/harness/change-contracts", MuxPattern: "/api/v1/harness/change-contracts", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "createHarnessChangeContract", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/harness/change-contracts/{change_id}", MuxPattern: "/api/v1/harness/change-contracts/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "getHarnessChangeContract", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/harness/change-contracts/{change_id}/approve", MuxPattern: "/api/v1/harness/change-contracts/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "approveHarnessChangeContract", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/harness/change-contracts/{change_id}/verify", MuxPattern: "/api/v1/harness/change-contracts/", Auth: RouteAuthTenant, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "verifyHarnessChangeContract", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/replay/verify", MuxPattern: "/api/v1/replay/verify", Auth: RouteAuthPublic, RateLimit: RouteRateEvidence, ContractStatus: RouteContractPublic, OperationID: "replayVerify", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/mcp/v1/capabilities", MuxPattern: "/mcp/v1/capabilities", Auth: RouteAuthAdmin, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "listMCPCapabilities", Owner: "core/pkg/mcp"},
		{Method: http.MethodPost, Path: "/mcp/v1/execute", MuxPattern: "/mcp/v1/execute", Auth: RouteAuthAdmin, RateLimit: RouteRateKernel, ContractStatus: RouteContractPublic, OperationID: "executeMCPTool", Owner: "core/pkg/mcp"},
		{Method: http.MethodGet, Path: "/healthz", MuxPattern: "/healthz", Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "healthCheck", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/version", MuxPattern: "/version", Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "getVersion", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/v1/meta/capabilities", MuxPattern: "/v1/meta/capabilities", Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "getCanonicalMetaCapabilities", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/meta/capabilities", MuxPattern: "/api/v1/meta/capabilities", Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractPublic, OperationID: "getMetaCapabilities", Owner: "core/cmd/helm-ai-kernel"},

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
		{Method: http.MethodGet, Path: "/api/v1/authz/check", MuxPattern: "/api/v1/authz/check", Auth: RouteAuthAdmin, RateLimit: RouteRateAdmin, ContractStatus: RouteContractImplementation, OperationID: "getAuthzStatus", Owner: "core/cmd/helm-ai-kernel"},
		// Mounted routes that had no registry entry before HELM-755. Their rate
		// class records the bucket they already fell into (unmatched paths are
		// classed public); moving them is a behavior change for a later slice.
		{Method: http.MethodGet, Path: "/api/v1/version", MuxPattern: "/api/v1/version", Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractCompatibility, OperationID: "getVersionCompat", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/.well-known/oauth-protected-resource", MuxPattern: "/.well-known/oauth-protected-resource", Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractInternal, OperationID: "getOAuthProtectedResourceMetadata", Owner: "core/pkg/mcp"},
		{Method: http.MethodGet, Path: desktopReadyPath, MuxPattern: desktopReadyPath, Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractInternal, OperationID: "proveDesktopKernelReady", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodHead, Path: desktopReadyPath, MuxPattern: desktopReadyPath, Auth: RouteAuthPublic, RateLimit: RouteRatePublic, ContractStatus: RouteContractInternal, OperationID: "checkDesktopKernelReady", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: "/api/v1/admin/principal-bindings", MuxPattern: "/api/v1/admin/principal-bindings", Auth: RouteAuthAdmin, RateLimit: RouteRatePublic, ContractStatus: RouteContractInternal, OperationID: "upsertPrincipalBinding", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: generatedSpecApprovalBeginPath, MuxPattern: generatedSpecApprovalBeginPath, Auth: RouteAuthWorkload, RateLimit: RouteRatePublic, ContractStatus: RouteContractInternal, OperationID: "beginGeneratedSpecApproval", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: generatedSpecApprovalGetPath, MuxPattern: generatedSpecApprovalGetPath, Auth: RouteAuthWorkload, RateLimit: RouteRatePublic, ContractStatus: RouteContractInternal, OperationID: "getGeneratedSpecApproval", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: generatedSpecApprovalChallengePath, MuxPattern: generatedSpecApprovalChallengePath, Auth: RouteAuthWorkload, RateLimit: RouteRatePublic, ContractStatus: RouteContractInternal, OperationID: "issueGeneratedSpecApprovalChallenge", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: generatedSpecApprovalSubmitPath, MuxPattern: generatedSpecApprovalSubmitPath, Auth: RouteAuthWorkload, RateLimit: RouteRatePublic, ContractStatus: RouteContractInternal, OperationID: "submitGeneratedSpecApprovalAssertions", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: generatedSpecApprovalConsumePath, MuxPattern: generatedSpecApprovalConsumePath, Auth: RouteAuthWorkload, RateLimit: RouteRatePublic, ContractStatus: RouteContractInternal, OperationID: "consumeGeneratedSpecApproval", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodPost, Path: generatedSpecApprovalRecoverPath, MuxPattern: generatedSpecApprovalRecoverPath, Auth: RouteAuthWorkload, RateLimit: RouteRatePublic, ContractStatus: RouteContractInternal, OperationID: "recoverGeneratedSpecApprovalConsumption", Owner: "core/cmd/helm-ai-kernel"},
		{Method: http.MethodGet, Path: "/api/v1/credentials/status", MuxPattern: "/api/v1/credentials/status", Auth: RouteAuthAdmin, RateLimit: RouteRatePublic, ContractStatus: RouteContractInternal, OperationID: "getCredentialStatus", Owner: "core/pkg/credentials"},
		{Method: http.MethodGet, Path: "/api/v1/credentials/config", MuxPattern: "/api/v1/credentials/config", Auth: RouteAuthAdmin, RateLimit: RouteRatePublic, ContractStatus: RouteContractInternal, OperationID: "getCredentialConfig", Owner: "core/pkg/credentials"},
		{Method: http.MethodPost, Path: "/api/v1/credentials/google/token", MuxPattern: "/api/v1/credentials/google/token", Auth: RouteAuthAdmin, RateLimit: RouteRatePublic, ContractStatus: RouteContractInternal, OperationID: "exchangeGoogleCredential", Owner: "core/pkg/credentials"},
		{Method: http.MethodPost, Path: "/api/v1/credentials/google/refresh", MuxPattern: "/api/v1/credentials/google/refresh", Auth: RouteAuthAdmin, RateLimit: RouteRatePublic, ContractStatus: RouteContractInternal, OperationID: "refreshGoogleCredential", Owner: "core/pkg/credentials"},
		{Method: http.MethodDelete, Path: "/api/v1/credentials/google", MuxPattern: "/api/v1/credentials/google", Auth: RouteAuthAdmin, RateLimit: RouteRatePublic, ContractStatus: RouteContractInternal, OperationID: "deleteGoogleCredential", Owner: "core/pkg/credentials"},
		{Method: http.MethodPost, Path: "/api/v1/credentials/openai", MuxPattern: "/api/v1/credentials/openai", Auth: RouteAuthAdmin, RateLimit: RouteRatePublic, ContractStatus: RouteContractInternal, OperationID: "storeOpenAICredential", Owner: "core/pkg/credentials"},
		{Method: http.MethodDelete, Path: "/api/v1/credentials/openai", MuxPattern: "/api/v1/credentials/openai", Auth: RouteAuthAdmin, RateLimit: RouteRatePublic, ContractStatus: RouteContractInternal, OperationID: "deleteOpenAICredential", Owner: "core/pkg/credentials"},
		{Method: http.MethodPost, Path: "/api/v1/credentials/anthropic", MuxPattern: "/api/v1/credentials/anthropic", Auth: RouteAuthAdmin, RateLimit: RouteRatePublic, ContractStatus: RouteContractInternal, OperationID: "storeAnthropicCredential", Owner: "core/pkg/credentials"},
		{Method: http.MethodDelete, Path: "/api/v1/credentials/anthropic", MuxPattern: "/api/v1/credentials/anthropic", Auth: RouteAuthAdmin, RateLimit: RouteRatePublic, ContractStatus: RouteContractInternal, OperationID: "deleteAnthropicCredential", Owner: "core/pkg/credentials"},
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

// The binary's other HTTP listeners. RuntimeRouteSpecs() declares the API
// listener; ListenerRouteSpecs() declares these, and each mounts its routes on
// a newListenerRouteMux that refuses a pattern not declared for it.
const (
	listenerHealth     = "health"      // server: HELM_HEALTH_PORT
	listenerMetrics    = "metrics"     // server: HELM_METRICS_PORT when it differs from the health port
	listenerMCP        = "mcp serve"   // mcp serve --transport http
	listenerProxy      = "proxy"       // proxy
	listenerSpendProxy = "spend-proxy" // spend-proxy
)

const (
	// RouteAuthMetricsToken is HELM_METRICS_BEARER_TOKEN; without one the route
	// answers loopback peers only (protectedMetricsHandler).
	RouteAuthMetricsToken RouteAuth = "metrics_token"
	// RouteAuthListenerCredential is the subcommand's own credential: mcp serve
	// --auth static-header|oauth, or the proxy's HELM_PROXY_TOKEN. Without one,
	// requireListenerAuth refuses a non-loopback bind.
	RouteAuthListenerCredential RouteAuth = "listener_credential"
)

// ListenerRouteSpec declares a route on a listener other than the API
// listener. None of these listeners binds a tenant per request, so Scope says
// whose data the route serves.
type ListenerRouteSpec struct {
	Listener   string
	MuxPattern string
	Auth       RouteAuth
	Scope      string
}

func ListenerRouteSpecs() []ListenerRouteSpec {
	const (
		liveness      = "liveness only; no data"
		processWide   = "process-wide metrics across every tenant"
		localMCP      = "the local MCP catalog, policy and data directory; no tenant"
		proxyTenant   = "the proxy's single --tenant-id"
		spendEnvelope = "the spend-proxy's configured envelopes; no caller credential, bound to --addr (127.0.0.1 by default)"
	)
	return []ListenerRouteSpec{
		{Listener: listenerHealth, MuxPattern: "/health", Auth: RouteAuthPublic, Scope: liveness},
		{Listener: listenerHealth, MuxPattern: "/healthz", Auth: RouteAuthPublic, Scope: liveness},
		{Listener: listenerHealth, MuxPattern: "/metrics", Auth: RouteAuthMetricsToken, Scope: processWide + "; mounted here when the metrics port is the health port"},
		{Listener: listenerMetrics, MuxPattern: "/metrics", Auth: RouteAuthMetricsToken, Scope: processWide},

		{Listener: listenerMCP, MuxPattern: "/mcp", Auth: RouteAuthListenerCredential, Scope: localMCP},
		{Listener: listenerMCP, MuxPattern: "/mcp/v1/capabilities", Auth: RouteAuthListenerCredential, Scope: localMCP},
		{Listener: listenerMCP, MuxPattern: "/mcp/v1/execute", Auth: RouteAuthListenerCredential, Scope: localMCP},
		{Listener: listenerMCP, MuxPattern: "/.well-known/oauth-protected-resource", Auth: RouteAuthListenerCredential, Scope: "RFC 9728 metadata, no data; --auth oauth exempts it"},
		{Listener: listenerMCP, MuxPattern: "/.well-known/oauth-protected-resource/mcp", Auth: RouteAuthListenerCredential, Scope: "RFC 9728 metadata, no data; --auth oauth exempts it"},
		{Listener: listenerMCP, MuxPattern: "/.well-known/agent-card.json", Auth: RouteAuthListenerCredential, Scope: "A2A agent card; no data"},
		{Listener: listenerMCP, MuxPattern: "/health", Auth: RouteAuthListenerCredential, Scope: liveness},
		{Listener: listenerMCP, MuxPattern: "/healthz", Auth: RouteAuthListenerCredential, Scope: liveness},

		{Listener: listenerProxy, MuxPattern: "/health", Auth: RouteAuthPublic, Scope: "liveness; names the upstream URL"},
		{Listener: listenerProxy, MuxPattern: "/healthz", Auth: RouteAuthPublic, Scope: "liveness; names the upstream URL"},
		{Listener: listenerProxy, MuxPattern: "/helm/receipts", Auth: RouteAuthListenerCredential, Scope: "the receipt log of " + proxyTenant},
		{Listener: listenerProxy, MuxPattern: "/helm/proofgraph", Auth: RouteAuthListenerCredential, Scope: "the ProofGraph of " + proxyTenant},
		{Listener: listenerProxy, MuxPattern: "/", Auth: RouteAuthListenerCredential, Scope: "every other path, forwarded to --upstream under governance as " + proxyTenant},

		{Listener: listenerSpendProxy, MuxPattern: "/v1/chat/completions", Auth: RouteAuthPublic, Scope: spendEnvelope},
		{Listener: listenerSpendProxy, MuxPattern: "/v1/responses", Auth: RouteAuthPublic, Scope: spendEnvelope},
		{Listener: listenerSpendProxy, MuxPattern: "/v1/embeddings", Auth: RouteAuthPublic, Scope: spendEnvelope},
		{Listener: listenerSpendProxy, MuxPattern: "/v1/models", Auth: RouteAuthPublic, Scope: spendEnvelope},
		{Listener: listenerSpendProxy, MuxPattern: "/helm/spend/health", Auth: RouteAuthPublic, Scope: "liveness, balance and receipt-log path"},
	}
}
