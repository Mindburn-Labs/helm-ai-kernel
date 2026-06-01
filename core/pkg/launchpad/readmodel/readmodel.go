package readmodel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/secrets"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/session"
)

type AppStatus struct {
	State             string   `json:"state"`
	Verdict           string   `json:"verdict"`
	ReasonCode        string   `json:"reason_code,omitempty"`
	Summary           string   `json:"summary"`
	MissingSecrets    []string `json:"missing_secrets,omitempty"`
	QuarantinedMCP    int      `json:"quarantined_mcp"`
	LastEvidencePack  string   `json:"last_evidence_pack,omitempty"`
	OfflineVerifiable bool     `json:"offline_verifiable"`
}

type RegistryApp struct {
	ID                   string                     `json:"id"`
	AppID                string                     `json:"app_id"`
	Name                 string                     `json:"name"`
	Version              string                     `json:"version"`
	OCIRef               string                     `json:"oci_ref,omitempty"`
	ImmutableDigest      string                     `json:"immutable_digest,omitempty"`
	OSSSupported         bool                       `json:"oss_supported"`
	Availability         registry.Availability      `json:"availability"`
	Redistribution       string                     `json:"redistribution,omitempty"`
	InstallStrategy      string                     `json:"install_strategy,omitempty"`
	RequiredSecrets      []string                   `json:"required_secrets"`
	ModelGatewayEnv      []string                   `json:"model_gateway_env,omitempty"`
	DeclaredCapabilities []string                   `json:"declared_capabilities"`
	MCPServers           []MCPServerNeed            `json:"mcp_servers"`
	FilesystemNeeds      []string                   `json:"filesystem_needs"`
	NetworkNeeds         []string                   `json:"network_needs"`
	Healthcheck          []registry.HealthcheckSpec `json:"healthcheck"`
	TeardownRecipe       map[string]any             `json:"teardown_recipe"`
	EvidenceProfile      []string                   `json:"evidence_profile"`
	RiskClass            string                     `json:"risk_class,omitempty"`
	PolicyRef            string                     `json:"policy_ref,omitempty"`
	Status               AppStatus                  `json:"status"`
	BlockedReason        string                     `json:"blocked_reason,omitempty"`
	UserState            string                     `json:"user_state,omitempty"`
	RequiredCapability   string                     `json:"required_capability,omitempty"`
	UpgradeReason        string                     `json:"upgrade_reason,omitempty"`
	EntitlementDecision  any                        `json:"entitlement_decision,omitempty"`
	ActionStates         map[string]any             `json:"action_states,omitempty"`
}

type MCPServerNeed struct {
	ID                  string `json:"id"`
	Transport           string `json:"transport,omitempty"`
	RiskClass           string `json:"risk_class,omitempty"`
	UnknownServerPolicy string `json:"unknown_server_policy"`
	UnknownToolPolicy   string `json:"unknown_tool_policy"`
	SchemaPinRequired   bool   `json:"schema_pin_required"`
}

type GateResult struct {
	ID              string      `json:"id"`
	Group           string      `json:"group"`
	Label           string      `json:"label"`
	Verdict         string      `json:"verdict"`
	ReasonCode      string      `json:"reason_code,omitempty"`
	ProofStatus     string      `json:"proof_status"`
	Summary         string      `json:"summary"`
	Why             string      `json:"why,omitempty"`
	ReceiptRefs     []string    `json:"receipt_refs,omitempty"`
	ProofgraphNode  string      `json:"proofgraph_node,omitempty"`
	EvidenceRefs    []string    `json:"evidence_refs,omitempty"`
	RawDetailRef    string      `json:"raw_detail_ref,omitempty"`
	Required        bool        `json:"required"`
	ReceiptRequired bool        `json:"receipt_required"`
	ActionableError string      `json:"actionable_error,omitempty"`
	FixActions      []FixAction `json:"fix_actions,omitempty"`
	CLIEquivalent   string      `json:"cli_equivalent,omitempty"`
}

type RunEvent struct {
	ID              string      `json:"id"`
	RunID           string      `json:"run_id"`
	Stage           string      `json:"stage"`
	Label           string      `json:"label"`
	Verdict         string      `json:"verdict"`
	ReasonCode      string      `json:"reason_code,omitempty"`
	ProofStatus     string      `json:"proof_status"`
	HumanSummary    string      `json:"human_summary"`
	Why             string      `json:"why,omitempty"`
	ReceiptRef      string      `json:"receipt_ref,omitempty"`
	ProofgraphNode  string      `json:"proofgraph_node,omitempty"`
	EvidenceRefs    []string    `json:"evidence_refs,omitempty"`
	RawPayloadRef   string      `json:"raw_payload_ref,omitempty"`
	ReceiptRequired bool        `json:"receipt_required"`
	ActionableError string      `json:"actionable_error,omitempty"`
	FixActions      []FixAction `json:"fix_actions,omitempty"`
	CLIEquivalent   string      `json:"cli_equivalent,omitempty"`
}

type RuntimeInstance struct {
	RunID                    string            `json:"run_id"`
	ContainerID              string            `json:"container_id,omitempty"`
	LaunchPlanHash           string            `json:"launchplan_hash,omitempty"`
	State                    session.State     `json:"state"`
	Verdict                  string            `json:"verdict"`
	AppID                    string            `json:"app_id"`
	SubstrateID              string            `json:"substrate_id"`
	Runtime                  string            `json:"runtime"`
	ActiveGrants             []string          `json:"active_grants"`
	Receipts                 []string          `json:"receipts"`
	EvidencePackRef          string            `json:"evidencepack_ref,omitempty"`
	EvidencePackRefs         []string          `json:"evidencepack_refs,omitempty"`
	OfflineVerifyCommand     string            `json:"offline_verify_command,omitempty"`
	TeardownCommand          string            `json:"teardown_command,omitempty"`
	RuntimeHandles           map[string]string `json:"runtime_handles,omitempty"`
	LocalVerificationStatus  string            `json:"local_verification_status"`
	OfflineVerificationReady bool              `json:"offline_verification_ready"`
	SandboxGrant             SandboxGrantView  `json:"sandbox_grant"`
	CLIEquivalent            string            `json:"cli_equivalent,omitempty"`
}

type RunDetail struct {
	Run      session.LaunchRun `json:"run"`
	Instance RuntimeInstance   `json:"instance"`
	Gates    []GateResult      `json:"gates"`
	Events   []RunEvent        `json:"events"`
}

type FixAction struct {
	Label       string `json:"label"`
	CLI         string `json:"cli"`
	Description string `json:"description,omitempty"`
}

type SandboxGrantView struct {
	BackendProfile     string            `json:"backend_profile"`
	Runtime            string            `json:"runtime"`
	RuntimeVersion     string            `json:"runtime_version"`
	ImageDigest        string            `json:"image_digest,omitempty"`
	FilesystemPreopens []string          `json:"filesystem_preopens"`
	NetworkPolicy      []string          `json:"network_policy"`
	Env                []string          `json:"env"`
	ResourceLimits     map[string]string `json:"resource_limits"`
	PolicyEpoch        string            `json:"policy_epoch"`
	GrantHash          string            `json:"grant_hash,omitempty"`
	ProofStatus        string            `json:"proof_status"`
}

type MCPThreatReview struct {
	ServerID            string          `json:"server_id"`
	AppID               string          `json:"app_id"`
	Transport           string          `json:"transport,omitempty"`
	Endpoint            string          `json:"endpoint,omitempty"`
	PackageSource       string          `json:"package_source,omitempty"`
	Publisher           string          `json:"publisher,omitempty"`
	Digest              string          `json:"digest,omitempty"`
	Signature           string          `json:"signature,omitempty"`
	Tools               []MCPToolThreat `json:"tools"`
	UnknownTools        bool            `json:"unknown_tools"`
	State               string          `json:"state"`
	RiskClass           string          `json:"risk_class,omitempty"`
	PolicyHash          string          `json:"policy_hash,omitempty"`
	ApprovalReceipt     string          `json:"approval_receipt,omitempty"`
	LastDispatchReceipt string          `json:"last_dispatch_receipt,omitempty"`
	ProofStatus         string          `json:"proof_status"`
	Summary             string          `json:"summary"`
	FixActions          []FixAction     `json:"fix_actions,omitempty"`
	CLIEquivalent       string          `json:"cli_equivalent,omitempty"`
}

type MCPToolThreat struct {
	Name            string   `json:"name"`
	SideEffectClass string   `json:"side_effect_class"`
	FilesystemNeeds []string `json:"filesystem_needs,omitempty"`
	NetworkNeeds    []string `json:"network_needs,omitempty"`
	SecretNeeds     []string `json:"secret_needs,omitempty"`
	RiskClass       string   `json:"risk_class,omitempty"`
	ApprovalState   string   `json:"approval_state"`
	DispatchReceipt string   `json:"dispatch_receipt,omitempty"`
}

type PolicySimulation struct {
	AppID         string         `json:"app_id"`
	Verdict       string         `json:"verdict"`
	ReasonCode    string         `json:"reason_code,omitempty"`
	PlainEnglish  string         `json:"plain_english"`
	Structured    map[string]any `json:"structured"`
	Diff          []string       `json:"diff"`
	Raw           map[string]any `json:"raw"`
	ReceiptRef    string         `json:"receipt_ref,omitempty"`
	ProofStatus   string         `json:"proof_status"`
	FixActions    []FixAction    `json:"fix_actions,omitempty"`
	CLIEquivalent string         `json:"cli_equivalent,omitempty"`
}

type SecretGrantStatus struct {
	Name         string `json:"name"`
	Provider     string `json:"provider,omitempty"`
	ValueEnv     string `json:"value_env,omitempty"`
	Present      bool   `json:"present"`
	Scope        string `json:"scope"`
	GrantMode    string `json:"grant_mode"`
	GrantHash    string `json:"grant_hash,omitempty"`
	LaunchImpact string `json:"launch_impact"`
}

func RegistryApps(catalog *registry.Catalog, secretStatuses []secrets.Status, runs []session.LaunchRun) []RegistryApp {
	if catalog == nil {
		return []RegistryApp{}
	}
	secretMap := map[string]secrets.Status{}
	for _, status := range secretStatuses {
		secretMap[status.Name] = status
	}
	latestEvidence := map[string]string{}
	for _, run := range runs {
		if len(run.EvidencePackRefs) == 0 {
			continue
		}
		latestEvidence[run.AppID] = run.EvidencePackRefs[len(run.EvidencePackRefs)-1]
	}
	apps := make([]RegistryApp, 0, len(catalog.Apps))
	for _, app := range catalog.Apps {
		missing := missingSecrets(app, secretMap)
		status := appStatus(app, missing, latestEvidence[app.ID])
		apps = append(apps, RegistryApp{
			ID:                   app.ID,
			AppID:                app.ID,
			Name:                 app.Name,
			Version:              app.Version,
			OCIRef:               app.Install.Image,
			ImmutableDigest:      app.Install.Digest,
			OSSSupported:         app.Availability == registry.AvailabilityOSSSupported,
			Availability:         app.Availability,
			Redistribution:       app.Redistribution,
			InstallStrategy:      app.Install.Strategy,
			RequiredSecrets:      cloneStrings(app.RequiredSecrets),
			ModelGatewayEnv:      cloneStrings(app.ModelGatewayEnv),
			DeclaredCapabilities: declaredCapabilities(app),
			MCPServers:           mcpServers(app),
			FilesystemNeeds:      cloneStrings(app.FilesystemPolicy.Mounts),
			NetworkNeeds:         cloneStrings(app.NetworkPolicy.Allowlist),
			Healthcheck:          app.Healthchecks,
			TeardownRecipe:       map[string]any{"cascade": true, "remove_container": true, "revoke_secret_grants": true, "close_mcp_sessions": true},
			EvidenceProfile:      cloneStrings(app.EvidenceRequirements),
			RiskClass:            app.RiskClass,
			PolicyRef:            app.FilesystemPolicy.PolicyRef,
			Status:               status,
			BlockedReason:        status.ReasonCode,
		})
	}
	return apps
}

func GatesFromPlan(app registry.AppSpec, substrate registry.SubstrateSpec, compiled plan.LaunchPlan, run *session.LaunchRun) []GateResult {
	receiptRefs := []string{}
	evidenceRefs := []string{}
	state := session.State(compiled.Status)
	if run != nil {
		receiptRefs = ReceiptRefs(*run)
		evidenceRefs = cloneStrings(run.EvidencePackRefs)
		state = run.State
	}
	artifactVerdict := "ALLOW"
	artifactProof := "proven"
	artifactReason := ""
	if compiled.KernelVerdict == "DENY" && strings.Contains(compiled.ReasonCode, "ARTIFACT") {
		artifactVerdict = "DENY"
		artifactProof = "proven"
		artifactReason = compiled.ReasonCode
	}
	secretVerdict := "ALLOW"
	secretProof := "proven"
	secretReason := ""
	secretSummary := "Required secret grants are present or not required."
	if compiled.ReasonCode == "ERR_LAUNCHPAD_REQUIRED_SECRET_MISSING" {
		secretVerdict = "ESCALATE"
		secretReason = compiled.ReasonCode
		secretSummary = "Required secret is missing. Container was not started."
	}
	runtimeProof := "unproven"
	runtimeVerdict := "ESCALATE"
	runtimeSummary := "Runtime has not started."
	if run != nil && run.RuntimeHandles.ContainerID != "" {
		runtimeProof = "proven"
		runtimeVerdict = "ALLOW"
		runtimeSummary = "Runtime container handle was emitted by the backend."
	}
	if state == session.StateRepairRequired {
		runtimeVerdict = "ESCALATE"
		runtimeSummary = "Runtime requires repair before RUNNING."
	}
	ossSupported := app.Availability == registry.AvailabilityOSSSupported && app.Conformance.FullyVerified()
	ossReason := ""
	if !ossSupported {
		ossReason = "ERR_LAUNCHPAD_APP_CONFORMANCE_REQUIRED"
	}
	mcpVerdict, mcpReason, mcpSummary := mcpQuarantineState(compiled, run)
	secretGate := gate("secrets.required", "Secrets", "Check required secrets", secretVerdict, secretReason, secretProof, secretSummary, refsWithPrefix(receiptRefs, "secret"), evidenceRefs)
	if secretReason == "ERR_LAUNCHPAD_REQUIRED_SECRET_MISSING" {
		secretGate.FixActions = secretFixActions(app)
	}
	return []GateResult{
		gate("registry.read", "Preflight", "Read registry spec", "ALLOW", "", "proven", "Registry AppSpec was loaded from the local registry.", nil, nil),
		gate("app.oss_supported", "Preflight", "Check oss_supported", verdictFor(ossSupported), ossReason, "proven", "OSS support and conformance were evaluated from AppSpec.", nil, nil),
		gate("artifact.digest", "Artifact verification", "Digest pinned", artifactVerdict, artifactReason, artifactProof, "Immutable artifact digest is pinned in AppSpec.", nil, nil),
		gate("artifact.signature", "Artifact verification", "Signature valid", artifactVerdict, artifactReason, artifactProof, "Cosign signature evidence is declared by AppSpec.", nil, nil),
		gate("artifact.sbom", "Artifact verification", "SBOM present", artifactVerdict, artifactReason, artifactProof, "SBOM evidence is declared by AppSpec.", nil, nil),
		gate("artifact.vuln_scan", "Artifact verification", "Scan accepted", artifactVerdict, artifactReason, artifactProof, "Vulnerability scan evidence is declared by AppSpec.", nil, nil),
		gate("launchplan.compile", "LaunchPlan", "Compile LaunchPlan", compiled.KernelVerdict, compiled.ReasonCode, "proven", "LaunchPlan was compiled before any runtime side effect.", nil, nil),
		gate("policy.evaluate", "Policy", "Apply policy and CPI", compiled.KernelVerdict, compiled.ReasonCode, "proven", "Policy hash and CPI output are bound to the LaunchPlan.", nil, nil),
		secretGate,
		gate("sandbox.grant", "Sandbox", "Prepare sandbox grant", compiled.KernelVerdict, compiled.ReasonCode, proofFromRefs(runRefs(run, "sandbox")), "Sandbox grant is required before runtime dispatch.", runRefs(run, "sandbox"), evidenceRefs),
		gate("mcp.quarantine", "MCP Firewall", "Register / quarantine MCP", mcpVerdict, mcpReason, proofFromRefs(runRefs(run, "mcp")), mcpSummary, runRefs(run, "mcp"), evidenceRefs),
		gate("runtime.start", "Runtime", "Start local container", runtimeVerdict, "", runtimeProof, runtimeSummary, runRefs(run, "start"), evidenceRefs),
		gate("healthcheck", "Runtime", "Run healthcheck", verdictFromRefs(runRefs(run, "healthcheck")), "", proofFromRefs(runRefs(run, "healthcheck")), "Healthcheck status is proven only by a healthcheck receipt.", runRefs(run, "healthcheck"), evidenceRefs),
		gate("receipts.emit", "Receipts", "Emit receipts", verdictFromRefs(receiptRefs), "", proofFromRefs(receiptRefs), "Receipts are attached to the runtime instance.", receiptRefs, evidenceRefs),
		gate("evidence.export", "Evidence", "Export EvidencePack", verdictFromRefs(evidenceRefs), "", proofFromRefs(evidenceRefs), "EvidencePack is exported for local/offline verification.", receiptRefs, evidenceRefs),
		gate("offline.verify", "OfflineVerification", "Print offline verify command", verdictFor(run != nil && run.VerificationCommand != ""), "", proofFromBool(run != nil && run.VerificationCommand != ""), "Offline verification command is available only after EvidencePack export.", nil, evidenceRefs),
		{ID: "teardown.cascade", Group: "CascadeTeardown", Label: "Cascade teardown", Verdict: verdictFromRefs(runRefs(run, "teardown")), ProofStatus: proofFromRefs(runRefs(run, "teardown")), Summary: "Cascade teardown is proven by teardown receipt.", ReceiptRefs: runRefs(run, "teardown"), EvidenceRefs: evidenceRefs, Required: true},
	}
}

func EventsFromRun(run session.LaunchRun) []RunEvent {
	mcpVerdict := "ESCALATE"
	mcpReason := "ERR_MCP_QUARANTINE_UNPROVEN"
	mcpSummary := "MCP quarantine is unproven until the backend emits a quarantine receipt."
	if len(run.MCPRefs) > 0 {
		mcpVerdict = "ALLOW"
		mcpReason = ""
		mcpSummary = "MCP quarantine policy was enforced; unknown tools remain unavailable until approval receipt exists."
	}
	events := []RunEvent{
		event(run, "registry_read", "Registry read", run.KernelVerdict, "", "proven", "Registry spec was read for this run.", first(run.BoundaryRecordRefs), ""),
		event(run, "supply_chain_verification", "Supply-chain verification", run.KernelVerdict, "", "proven", "Artifact digest, signature, SBOM, and scan evidence were evaluated before runtime.", "", "launch_plan.json"),
		event(run, "launchplan_compiled", "LaunchPlan compiled", run.KernelVerdict, "", proofFromBool(run.PlanHash != ""), "LaunchPlan hash is bound to the run.", "", "launch_plan.json"),
		event(run, "policy_evaluated", "Policy evaluated", run.KernelVerdict, "", proofFromBool(len(run.CPIRefs) > 0), "CPI and policy outputs were evaluated.", first(run.CPIRefs), "cpi_output.json"),
		event(run, "secrets_granted", "Secrets granted", verdictFromRefs(run.SecretGrantRefs), "", proofFromRefs(run.SecretGrantRefs), "Secret grant receipts prove runtime env injection; missing grants remain unproven.", first(run.SecretGrantRefs), "receipts/launchpad-secret-grants.json"),
		event(run, "sandbox_grant_issued", "Sandbox grant issued", verdictFromRefs(run.SandboxGrantRefs), "", proofFromRefs(run.SandboxGrantRefs), "Sandbox grant is required before side effects.", first(run.SandboxGrantRefs), "sandbox_grant.json"),
		event(run, "mcp_quarantine_enforced", "MCP quarantine enforced", mcpVerdict, mcpReason, proofFromRefs(run.MCPRefs), mcpSummary, first(run.MCPRefs), "mcp_quarantine.json"),
		event(run, "container_started", "Container started", verdictFor(run.RuntimeHandles.ContainerID != ""), "", proofFromBool(run.RuntimeHandles.ContainerID != ""), "Container status is proven only when runtime handle exists.", first(run.StartReceiptRefs), "runtime_environment.json"),
		event(run, "healthcheck_passed", "Healthcheck passed", verdictFromRefs(run.HealthcheckRefs), "", proofFromRefs(run.HealthcheckRefs), "Healthcheck status is proven by healthcheck receipt.", first(run.HealthcheckRefs), "receipts/launchpad-healthcheck.json"),
		event(run, "install_receipt_emitted", "Install receipt emitted", verdictFromRefs(run.InstallReceiptRefs), "", proofFromRefs(run.InstallReceiptRefs), "Install receipt was emitted.", first(run.InstallReceiptRefs), "receipts/launchpad-install.json"),
		event(run, "launch_receipt_emitted", "Launch receipt emitted", verdictFromRefs(run.LaunchReceiptRefs), "", proofFromRefs(run.LaunchReceiptRefs), "Launch receipt was emitted.", first(run.LaunchReceiptRefs), "receipts/launchpad-launch.json"),
		event(run, "evidencepack_exported", "EvidencePack exported", verdictFromRefs(run.EvidencePackRefs), "", proofFromRefs(run.EvidencePackRefs), "EvidencePack refs are available for offline verification.", first(run.EvidencePackRefs), "04_EXPORTS/launchpad_manifest.json"),
		event(run, "teardown_receipt_emitted", "Teardown receipt emitted", verdictFromRefs(run.TeardownReceiptRefs), "", proofFromRefs(run.TeardownReceiptRefs), "Teardown receipt proves cascade cleanup.", first(run.TeardownReceiptRefs), "receipts/launchpad-teardown.json"),
	}
	if run.State == session.StateEscalated {
		for index := range events {
			if events[index].ProofStatus == "unproven" {
				events[index].ActionableError = "Run escalated before this stage; container was not started."
			}
		}
	}
	return events
}

func RuntimeFromRun(run session.LaunchRun) RuntimeInstance {
	handles := map[string]string{}
	if run.RuntimeHandles.ContainerID != "" {
		handles["container_id"] = run.RuntimeHandles.ContainerID
	}
	if run.RuntimeHandles.EgressNetworkName != "" {
		handles["egress_network_name"] = run.RuntimeHandles.EgressNetworkName
	}
	if run.RuntimeHandles.EgressProxyID != "" {
		handles["egress_proxy_id"] = run.RuntimeHandles.EgressProxyID
	}
	for key, value := range run.RuntimeHandles.CloudResourceIDs {
		handles[key] = value
	}
	evidenceRef := ""
	if len(run.EvidencePackRefs) > 0 {
		evidenceRef = run.EvidencePackRefs[len(run.EvidencePackRefs)-1]
	}
	active := append([]string{}, run.SandboxGrantRefs...)
	active = append(active, run.SecretGrantRefs...)
	active = append(active, run.EgressReceiptRefs...)
	return RuntimeInstance{
		RunID:                    run.LaunchID,
		ContainerID:              run.RuntimeHandles.ContainerID,
		LaunchPlanHash:           run.PlanHash,
		State:                    run.State,
		Verdict:                  run.KernelVerdict,
		AppID:                    run.AppID,
		SubstrateID:              run.SubstrateID,
		Runtime:                  runtimeName(run),
		ActiveGrants:             compactStrings(active),
		Receipts:                 ReceiptRefs(run),
		EvidencePackRef:          evidenceRef,
		EvidencePackRefs:         cloneStrings(run.EvidencePackRefs),
		OfflineVerifyCommand:     run.VerificationCommand,
		TeardownCommand:          run.TeardownCommand,
		RuntimeHandles:           handles,
		LocalVerificationStatus:  verificationStatus(run),
		OfflineVerificationReady: run.VerificationCommand != "",
		SandboxGrant:             SandboxGrantFromRun(run),
		CLIEquivalent:            "helm-ai-kernel run open " + run.LaunchID,
	}
}

func Detail(app registry.AppSpec, substrate registry.SubstrateSpec, compiled plan.LaunchPlan, run session.LaunchRun) RunDetail {
	instance := RuntimeFromRun(run)
	instance.SandboxGrant = SandboxGrant(app, substrate, run)
	return RunDetail{
		Run:      run,
		Instance: instance,
		Gates:    GatesFromPlan(app, substrate, compiled, &run),
		Events:   EventsFromRun(run),
	}
}

func ReceiptRefs(run session.LaunchRun) []string {
	refs := []string{}
	refs = append(refs, run.InstallReceiptRefs...)
	refs = append(refs, run.LaunchReceiptRefs...)
	refs = append(refs, run.StartReceiptRefs...)
	refs = append(refs, run.SecretGrantRefs...)
	refs = append(refs, run.SandboxGrantRefs...)
	refs = append(refs, run.EgressReceiptRefs...)
	refs = append(refs, run.MCPRefs...)
	refs = append(refs, run.HealthcheckRefs...)
	refs = append(refs, run.TeardownReceiptRefs...)
	return compactStrings(refs)
}

func SecretGrantStatuses(statuses []secrets.Status) []SecretGrantStatus {
	out := make([]SecretGrantStatus, 0, len(statuses))
	for _, status := range statuses {
		out = append(out, SecretGrantStatus{
			Name:         status.Name,
			Provider:     status.Provider,
			ValueEnv:     status.ValueEnv,
			Present:      status.Available,
			Scope:        "runtime env",
			GrantMode:    "just-in-time",
			GrantHash:    stableHash("secret-grant", status.Name, status.ValueEnv),
			LaunchImpact: impactForSecret(status.Available),
		})
	}
	return out
}

func SandboxGrant(app registry.AppSpec, substrate registry.SubstrateSpec, run session.LaunchRun) SandboxGrantView {
	grant := SandboxGrantFromRun(run)
	grant.BackendProfile = firstNonEmptyString(substrate.ID, grant.BackendProfile)
	grant.Runtime = firstNonEmptyString(substrate.Kind, grant.Runtime)
	grant.ImageDigest = firstNonEmptyString(app.Install.Digest, run.ArtifactDigest)
	grant.FilesystemPreopens = cloneStrings(app.FilesystemPolicy.Mounts)
	if len(grant.FilesystemPreopens) == 0 {
		grant.FilesystemPreopens = []string{"deny-by-default"}
	}
	grant.NetworkPolicy = cloneStrings(app.NetworkPolicy.Allowlist)
	if len(grant.NetworkPolicy) == 0 {
		grant.NetworkPolicy = []string{"default-deny"}
	}
	grant.Env = cloneStrings(app.ModelGatewayEnv)
	if len(grant.Env) == 0 {
		grant.Env = []string{"none"}
	}
	grant.GrantHash = firstNonEmptyString(first(run.SandboxGrantRefs), stableHash("sandbox", run.LaunchID, run.PlanHash))
	grant.ProofStatus = proofFromRefs(run.SandboxGrantRefs)
	return grant
}

func SandboxGrantFromRun(run session.LaunchRun) SandboxGrantView {
	return SandboxGrantView{
		BackendProfile:     firstNonEmptyString(run.SubstrateID, "local-container"),
		Runtime:            runtimeName(run),
		RuntimeVersion:     "local",
		ImageDigest:        run.ArtifactDigest,
		FilesystemPreopens: []string{"unproven"},
		NetworkPolicy:      []string{"unproven"},
		Env:                []string{"unproven"},
		ResourceLimits:     map[string]string{"cpu": "2", "memory": "2GB", "timeout": "30m"},
		PolicyEpoch:        firstNonEmptyString(run.PlanHash, "unproven"),
		GrantHash:          first(run.SandboxGrantRefs),
		ProofStatus:        proofFromRefs(run.SandboxGrantRefs),
	}
}

func MCPThreatReviews(catalog *registry.Catalog, runs []session.LaunchRun) []MCPThreatReview {
	if catalog == nil {
		return []MCPThreatReview{}
	}
	lastRunByApp := map[string]session.LaunchRun{}
	for _, run := range runs {
		if _, exists := lastRunByApp[run.AppID]; !exists {
			lastRunByApp[run.AppID] = run
		}
	}
	reviews := make([]MCPThreatReview, 0, len(catalog.Apps))
	for _, app := range catalog.Apps {
		run := lastRunByApp[app.ID]
		mcpRef := first(run.MCPRefs)
		state := "quarantined"
		proof := "unproven"
		if mcpRef != "" {
			proof = "proven"
		}
		if app.MCPPolicy.UnknownServerPolicy == "" && app.MCPPolicy.UnknownToolPolicy == "" {
			state = "unproven"
		}
		serverID := app.ID + "-mcp"
		reviews = append(reviews, MCPThreatReview{
			ServerID:            serverID,
			AppID:               app.ID,
			Transport:           "declared-by-appspec",
			Endpoint:            "unproven",
			PackageSource:       app.Install.Source,
			Publisher:           app.Metadata["upstream_repo"],
			Digest:              app.Install.Digest,
			Signature:           app.SupplyChainEvidence.SignatureRef,
			Tools:               []MCPToolThreat{},
			UnknownTools:        true,
			State:               state,
			RiskClass:           app.RiskClass,
			PolicyHash:          app.FilesystemPolicy.PolicyRef,
			ApprovalReceipt:     "",
			LastDispatchReceipt: "",
			ProofStatus:         proof,
			Summary:             "No MCP tool dispatch is allowed until server identity, tool names, risk class, approval receipt, expiration, and revocation semantics are bound.",
			FixActions: []FixAction{{
				Label:       "Review MCP tools",
				CLI:         "helm-ai-kernel mcp quarantine",
				Description: "Inspect quarantined MCP servers before issuing a scoped approval.",
			}},
			CLIEquivalent: "helm-ai-kernel mcp approve " + serverID + " --tools <tool> --ttl 1h --reason <reason>",
		})
	}
	return reviews
}

func PolicySimulationForApp(app registry.AppSpec, compiled plan.LaunchPlan) PolicySimulation {
	verdict := compiled.KernelVerdict
	reason := compiled.ReasonCode
	plain := fmt.Sprintf("%s uses deny-by-default filesystem policy %q and network policy with %d allowlisted destination(s).", app.Name, app.FilesystemPolicy.PolicyRef, len(app.NetworkPolicy.Allowlist))
	if reason == "ERR_LAUNCHPAD_REQUIRED_SECRET_MISSING" {
		plain = "Policy simulation is blocked until required secret grants exist; runtime remains fail-closed."
	}
	return PolicySimulation{
		AppID:        app.ID,
		Verdict:      verdict,
		ReasonCode:   reason,
		PlainEnglish: plain,
		Structured: map[string]any{
			"filesystem": map[string]any{"default": "deny", "allow": app.FilesystemPolicy.Mounts, "policy_ref": app.FilesystemPolicy.PolicyRef},
			"network":    map[string]any{"default": app.NetworkPolicy.Default, "allow": app.NetworkPolicy.Allowlist},
			"mcp":        app.MCPPolicy,
			"secrets":    app.RequiredSecrets,
		},
		Diff: []string{
			"deny-by-default filesystem retained",
			"deny-by-default network retained",
			"unknown MCP tools remain quarantined",
		},
		Raw: map[string]any{
			"launchplan_hash": compiled.PlanHash,
			"policy_hash":     compiled.PolicyHash,
			"reason_code":     compiled.ReasonCode,
		},
		ProofStatus:   proofFromBool(compiled.PlanHash != ""),
		CLIEquivalent: "helm-ai-kernel policy simulate " + app.ID,
	}
}

func missingSecrets(app registry.AppSpec, secretMap map[string]secrets.Status) []string {
	missing := []string{}
	for _, envName := range app.ModelGatewayEnv {
		if os.Getenv(envName) != "" {
			continue
		}
		bound := false
		for _, logical := range app.RequiredSecrets {
			if status, ok := secretMap[logical]; ok && status.Available {
				bound = true
				break
			}
		}
		if !bound {
			missing = append(missing, envName)
		}
	}
	if len(app.ModelGatewayEnv) == 0 {
		for _, logical := range app.RequiredSecrets {
			if status, ok := secretMap[logical]; !ok || !status.Available {
				missing = append(missing, logical)
			}
		}
	}
	return missing
}

func appStatus(app registry.AppSpec, missing []string, lastEvidence string) AppStatus {
	base := AppStatus{Verdict: "ALLOW", State: "ready", Summary: "Ready for fail-closed preflight.", MissingSecrets: missing, QuarantinedMCP: 0, LastEvidencePack: lastEvidence, OfflineVerifiable: lastEvidence != ""}
	if app.Availability != registry.AvailabilityOSSSupported || !app.Conformance.FullyVerified() {
		base.State = "verification_failed"
		base.Verdict = "ESCALATE"
		base.ReasonCode = "ERR_LAUNCHPAD_APP_CONFORMANCE_REQUIRED"
		base.Summary = "App is not fully verified for OSS launch."
		return base
	}
	if len(missing) > 0 {
		base.State = "needs_secret"
		base.Verdict = "ESCALATE"
		base.ReasonCode = "ERR_LAUNCHPAD_REQUIRED_SECRET_MISSING"
		base.Summary = "Required secret grant is missing; launch will not start a container."
		return base
	}
	return base
}

func declaredCapabilities(app registry.AppSpec) []string {
	values := []string{"artifact-first-launch", "receipt-backed-runtime", "evidencepack-export"}
	if len(app.NetworkPolicy.Allowlist) > 0 {
		values = append(values, "scoped-network-egress")
	}
	if len(app.MCPPolicy.UnknownServerPolicy) > 0 {
		values = append(values, "mcp-firewall")
	}
	return values
}

func mcpServers(app registry.AppSpec) []MCPServerNeed {
	return []MCPServerNeed{{
		ID:                  app.ID + "-mcp",
		RiskClass:           app.RiskClass,
		UnknownServerPolicy: app.MCPPolicy.UnknownServerPolicy,
		UnknownToolPolicy:   app.MCPPolicy.UnknownToolPolicy,
		SchemaPinRequired:   app.MCPPolicy.RequireSchemaPin,
	}}
}

func gate(id, group, label, verdict, reason, proof, summary string, receipts, evidence []string) GateResult {
	return GateResult{
		ID:              id,
		Group:           group,
		Label:           label,
		Verdict:         verdict,
		ReasonCode:      reason,
		ProofStatus:     proof,
		Summary:         summary,
		Why:             summary,
		ReceiptRefs:     compactStrings(receipts),
		EvidenceRefs:    compactStrings(evidence),
		RawDetailRef:    rawRefForGate(id),
		Required:        true,
		ReceiptRequired: true,
		FixActions:      fixActionsFor(reason, id),
		CLIEquivalent:   cliForGate(id),
	}
}

func event(run session.LaunchRun, stage, label, verdict, reason, proof, summary, receipt, raw string) RunEvent {
	return RunEvent{ID: run.LaunchID + ":" + stage, RunID: run.LaunchID, Stage: stage, Label: label, Verdict: verdict, ReasonCode: reason, ProofStatus: proof, HumanSummary: summary, Why: summary, ReceiptRef: receipt, EvidenceRefs: cloneStrings(run.EvidencePackRefs), RawPayloadRef: raw, ReceiptRequired: true, FixActions: fixActionsFor(reason, stage), CLIEquivalent: cliForEvent(run, stage)}
}

func verdictFor(ok bool) string {
	if ok {
		return "ALLOW"
	}
	return "ESCALATE"
}

func verdictFromRefs(refs []string) string {
	if len(compactStrings(refs)) > 0 {
		return "ALLOW"
	}
	return "ESCALATE"
}

func proofFromRefs(refs []string) string {
	if len(compactStrings(refs)) > 0 {
		return "proven"
	}
	return "unproven"
}

func proofFromBool(ok bool) string {
	if ok {
		return "proven"
	}
	return "unproven"
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func refsWithPrefix(refs []string, prefix string) []string {
	out := []string{}
	for _, ref := range refs {
		if strings.Contains(ref, prefix) {
			out = append(out, ref)
		}
	}
	return out
}

func mcpQuarantineState(compiled plan.LaunchPlan, run *session.LaunchRun) (string, string, string) {
	if len(runRefs(run, "mcp")) > 0 {
		return "ALLOW", "", "MCP quarantine policy was enforced; unknown tools remain unavailable unless a scoped approval receipt exists."
	}
	if compiled.MCPPolicy.UnknownServerPolicy == "quarantine" || compiled.MCPPolicy.UnknownToolPolicy != "" {
		return "ESCALATE", "ERR_MCP_QUARANTINE_UNPROVEN", "MCP quarantine is required but no quarantine receipt is attached yet."
	}
	return "ALLOW", "", "No MCP quarantine requirement was declared by AppSpec."
}

func fixActionsFor(reason, id string) []FixAction {
	switch reason {
	case "ERR_LAUNCHPAD_REQUIRED_SECRET_MISSING", "ERR_REQUIRED_SECRET_MISSING":
		return []FixAction{{Label: "Add local secret", CLI: "helm-ai-kernel secret set <logical_name> --provider env --value-env <ENV>", Description: "Bind the required env-backed secret, then resume the run."}}
	case "ERR_LAUNCHPAD_APP_CONFORMANCE_REQUIRED":
		return []FixAction{{Label: "Promote verified AppSpec", CLI: "helm-ai-kernel launch promote --app <app> --manifest <promotion-manifest.json> --write", Description: "Attach live conformance evidence before enabling OSS launch."}}
	case "ERR_MCP_QUARANTINE_UNPROVEN", "ERR_MCP_SERVER_QUARANTINED":
		return []FixAction{{Label: "Review MCP threat", CLI: "helm-ai-kernel mcp quarantine", Description: "Keep unknown tools quarantined or approve a scoped subset with TTL."}}
	}
	if strings.Contains(id, "policy") {
		return []FixAction{{Label: "Simulate policy", CLI: "helm-ai-kernel policy simulate <app>", Description: "Review least-privilege policy before applying."}}
	}
	return nil
}

func secretFixActions(app registry.AppSpec) []FixAction {
	logical := firstNonEmptyString(first(app.RequiredSecrets), first(app.ModelGatewayEnv), "<name>")
	env := firstNonEmptyString(first(app.ModelGatewayEnv), logical)
	return []FixAction{{
		Label:       "Bind AppSpec secret",
		CLI:         fmt.Sprintf("helm-ai-kernel secret set %s --provider env --value-env %s", logical, env),
		Description: "Bind the logical AppSpec secret to a local environment variable, then resume the run.",
	}}
}

func cliForGate(id string) string {
	switch id {
	case "launchplan.compile", "policy.evaluate":
		return "helm-ai-kernel app preflight <app>"
	case "secrets.required":
		return "helm-ai-kernel secret set <name>"
	case "sandbox.grant":
		return "helm-ai-kernel sandbox inspect <run_id>"
	case "mcp.quarantine":
		return "helm-ai-kernel mcp quarantine"
	case "runtime.start":
		return "helm-ai-kernel app run <app>"
	case "healthcheck":
		return "helm-ai-kernel run logs <run_id>"
	case "receipts.emit":
		return "helm-ai-kernel run receipts <run_id>"
	case "evidence.export", "offline.verify":
		return "helm-ai-kernel verify --bundle <file>"
	case "teardown.cascade":
		return "helm-ai-kernel teardown <run_id> --cascade"
	default:
		return "helm-ai-kernel app inspect <app>"
	}
}

func cliForEvent(run session.LaunchRun, stage string) string {
	id := firstNonEmptyString(run.LaunchID, "<run_id>")
	switch {
	case strings.Contains(stage, "secret"):
		return "helm-ai-kernel secret set <name>"
	case strings.Contains(stage, "sandbox"):
		return "helm-ai-kernel sandbox inspect " + id
	case strings.Contains(stage, "mcp"):
		return "helm-ai-kernel mcp quarantine"
	case strings.Contains(stage, "evidence"):
		return "helm-ai-kernel evidence export " + id
	case strings.Contains(stage, "teardown"):
		return "helm-ai-kernel teardown " + id + " --cascade"
	case strings.Contains(stage, "receipt"):
		return "helm-ai-kernel run receipts " + id
	default:
		return "helm-ai-kernel run open " + id
	}
}

func rawRefForGate(id string) string {
	return strings.ReplaceAll(id, ".", "_") + ".json"
}

func stableHash(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func runRefs(run *session.LaunchRun, kind string) []string {
	if run == nil {
		return nil
	}
	switch kind {
	case "sandbox":
		return run.SandboxGrantRefs
	case "mcp":
		return run.MCPRefs
	case "start":
		return run.StartReceiptRefs
	case "healthcheck":
		return run.HealthcheckRefs
	case "teardown":
		return run.TeardownReceiptRefs
	default:
		return nil
	}
}

func runtimeName(run session.LaunchRun) string {
	if run.SubstrateID != "" {
		return run.SubstrateID
	}
	return "local-container"
}

func verificationStatus(run session.LaunchRun) string {
	if run.VerificationCommand == "" {
		return "unavailable"
	}
	return "available"
}

func impactForSecret(present bool) string {
	if present {
		return "allows launch after preflight"
	}
	return "blocks launch"
}

func cloneStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func compactStrings(values []string) []string {
	out := []string{}
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
