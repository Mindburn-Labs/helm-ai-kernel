package agentsafety

import (
	"sort"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policybundles"
)

const (
	ScenarioAgentSafetyBaseline = "pkg/conformance/scenarios:TestAgentSafetyBaselineRegistryScenarios"
)

// CaseCoverage is the machine-readable implementation mapping for one matrix case.
type CaseCoverage struct {
	CaseID               string `json:"case_id"`
	Group                string `json:"group"`
	PolicyRuleID         string `json:"policy_rule_id"`
	ConfigGuard          string `json:"config_guard"`
	PackageTest          string `json:"package_test"`
	ConformanceScenario  string `json:"conformance_scenario"`
	ResidualRisk         string `json:"residual_risk"`
	ExpectedPolicyAction string `json:"expected_policy_action"`
	ExpectedReasonCode   string `json:"expected_reason_code,omitempty"`
	ReceiptRequired      bool   `json:"receipt_required"`
}

// Registry returns a stable coverage registry for agent-safety matrix cases.
func Registry() []CaseCoverage {
	out := make([]CaseCoverage, len(registry))
	copy(out, registry)
	return out
}

// CaseIDs returns sorted registry case IDs.
func CaseIDs() []string {
	ids := make([]string, 0, len(registry))
	for _, c := range registry {
		ids = append(ids, c.CaseID)
	}
	sort.Strings(ids)
	return ids
}

func cov(id, group, rule, guard, pkgTest, residual, action string, reason contracts.ReasonCode, receipt bool) CaseCoverage {
	return CaseCoverage{
		CaseID:               id,
		Group:                group,
		PolicyRuleID:         rule,
		ConfigGuard:          guard,
		PackageTest:          pkgTest,
		ConformanceScenario:  ScenarioAgentSafetyBaseline,
		ResidualRisk:         residual,
		ExpectedPolicyAction: action,
		ExpectedReasonCode:   string(reason),
		ReceiptRequired:      receipt,
	}
}

var registry = []CaseCoverage{
	// ASI01: Agent Goal Hijack.
	cov("AGH-01", "ASI01 Agent Goal Hijack", policybundles.AgentSafetyRuleTaintedHighRisk, "FailClosedOnMissingContext", "pkg/policybundles:TestAgentSafetyBaselineConditionsCompile", "Requires deployment-specific source tainting adapters.", "deny", contracts.ReasonTaintedInputDeny, true),
	cov("AGH-02", "ASI01 Agent Goal Hijack", policybundles.AgentSafetyRuleMemoryInfluenceOnly, "LKSMemoryInfluenceOnly", "pkg/memory:provenance and promotion tests", "Longitudinal drift detection depends on runtime observation windows.", "deny", contracts.ReasonSessionRiskDeny, true),
	cov("AGH-03", "ASI01 Agent Goal Hijack", policybundles.AgentSafetyRuleEgressBoundary, "DenyUnknownEgress", "pkg/firewall:deny-all and allowlist tests", "Enterprise DLP may add richer data classification.", "deny", contracts.ReasonDataEgressBlocked, true),
	cov("AGH-04", "ASI01 Agent Goal Hijack", policybundles.AgentSafetyRuleTaintedHighRisk, "RequireManifestValidation", "pkg/manifest:arg and output validation tests", "Authenticated browser adapters must supply taint labels.", "deny", contracts.ReasonTaintedInputDeny, true),
	cov("AGH-05", "ASI01 Agent Goal Hijack", policybundles.AgentSafetyRuleProtectedConfig, "BaselinePolicyEnabled", "pkg/policybundles:TestAgentSafetyBaselineBundleShape", "Signed config provenance is enforced by policy reconciliation outside this registry.", "deny", contracts.ReasonPolicyViolation, true),

	// ASI02: Tool Misuse and Exploitation.
	cov("TME-01", "ASI02 Tool Misuse and Exploitation", policybundles.AgentSafetyRuleTaintedHighRisk, "FailClosedOnMissingContext", "pkg/policycel:taint helper tests", "Requires tool adapters to preserve output taint.", "deny", contracts.ReasonTaintedInputDeny, true),
	cov("TME-02", "ASI02 Tool Misuse and Exploitation", policybundles.AgentSafetyRuleEgressBoundary, "DenyUnknownEgress", "pkg/firewall:egress deny tests", "Covert-channel detection beyond payload/destination remains deployment-specific.", "deny", contracts.ReasonDataEgressBlocked, true),
	cov("TME-03", "ASI02 Tool Misuse and Exploitation", policybundles.AgentSafetyRuleHighImpactApproval, "RequireManifestValidation", "pkg/contracts:effect risk class tests", "Real approval ceremonies are validated by governance flows.", "require_approval", contracts.ReasonApprovalRequired, false),
	cov("TME-04", "ASI02 Tool Misuse and Exploitation", policybundles.AgentSafetyRuleToolContract, "DenyUnknownTools", "pkg/manifest:tool schema validation tests", "Typosquat similarity scoring can be strengthened by registry reputation data.", "deny", contracts.ReasonVerification, true),
	cov("TME-05", "ASI02 Tool Misuse and Exploitation", policybundles.AgentSafetyRuleEgressBoundary, "DenyUnknownEgress", "pkg/firewall:protocol and domain deny tests", "DNS-level covert-channel signatures are outside OSS kernel scope.", "deny", contracts.ReasonDataEgressBlocked, true),
	cov("TME-06", "ASI02 Tool Misuse and Exploitation", policybundles.AgentSafetyRuleApprovedArgs, "RequireApprovedArgBinding", "pkg/contracts:approval binding tests", "Adapters must provide approved-argument hash bindings.", "deny", contracts.ReasonPolicyViolation, true),

	// ASI03: Identity and Privilege Abuse.
	cov("IPA-01", "ASI03 Identity and Privilege Abuse", policybundles.AgentSafetyRuleDelegationIdentity, "RequireA2ASignatures", "pkg/a2a:negotiation and policy rule tests", "Fine-grained privilege attenuation depends on tenant RBAC data.", "deny", contracts.ReasonDelegationInvalid, true),
	cov("IPA-02", "ASI03 Identity and Privilege Abuse", policybundles.AgentSafetyRuleDelegationIdentity, "FailClosedOnMissingContext", "pkg/identity:credential isolation tests", "Credential backends must emit session-bound scope facts.", "deny", contracts.ReasonDelegationInvalid, true),
	cov("IPA-03", "ASI03 Identity and Privilege Abuse", policybundles.AgentSafetyRuleDelegationIdentity, "FailClosedOnMissingContext", "pkg/a2a:expiry and task-window tests", "Clock trust is inherited from runtime attestation.", "deny", contracts.ReasonDelegationInvalid, true),
	cov("IPA-04", "ASI03 Identity and Privilege Abuse", policybundles.AgentSafetyRuleA2AVerification, "RequireA2ASignatures", "pkg/a2a:signature verifier tests", "Registry authenticity depends on configured trust roots.", "deny", contracts.ReasonDelegationInvalid, true),
	cov("IPA-05", "ASI03 Identity and Privilege Abuse", policybundles.AgentSafetyRuleDelegationIdentity, "RequireApprovedArgBinding", "pkg/contracts:approval binding tests", "OAuth provider scope names remain connector-specific.", "deny", contracts.ReasonDelegationInvalid, true),
	cov("IPA-06", "ASI03 Identity and Privilege Abuse", policybundles.AgentSafetyRuleToolContract, "RequireManifestValidation", "pkg/contracts:receipt schema tests", "Sponsor identity population is enforced by calling workflow.", "deny", contracts.ReasonVerification, true),

	// ASI04: Agentic Supply Chain Vulnerabilities.
	cov("ASC-01", "ASI04 Agentic Supply Chain Vulnerabilities", policybundles.AgentSafetyRuleSupplyChain, "RequireManifestValidation", "pkg/pack and evidencepack hash tests", "External transparency logs are optional deployment hardening.", "deny", contracts.ReasonProvenance, true),
	cov("ASC-02", "ASI04 Agentic Supply Chain Vulnerabilities", policybundles.AgentSafetyRuleTaintedHighRisk, "DenyUnknownTools", "pkg/policycel:taint helper tests", "Descriptor scanners must label prompt-like metadata.", "deny", contracts.ReasonTaintedInputDeny, true),
	cov("ASC-03", "ASI04 Agentic Supply Chain Vulnerabilities", policybundles.AgentSafetyRuleSupplyChain, "RequireManifestValidation", "pkg/evidencepack:manifest hash tests", "Remote registry availability is outside local deterministic tests.", "deny", contracts.ReasonProvenance, true),
	cov("ASC-04", "ASI04 Agentic Supply Chain Vulnerabilities", policybundles.AgentSafetyRuleToolContract, "DenyUnknownTools", "pkg/manifest:capability validation tests", "Name-similarity heuristics can be extended in registry policy.", "deny", contracts.ReasonVerification, true),
	cov("ASC-05", "ASI04 Agentic Supply Chain Vulnerabilities", policybundles.AgentSafetyRuleEgressBoundary, "DenyUnknownEgress", "pkg/conformance/sandbox:sandbox grant tests", "Install-time syscall coverage depends on sandbox backend.", "deny", contracts.ReasonDataEgressBlocked, true),
	cov("ASC-06", "ASI04 Agentic Supply Chain Vulnerabilities", policybundles.AgentSafetyRuleSafeDepOverride, "EnforceSafeDepGates", "pkg/safedep:controller gate tests", "Revocation propagation latency depends on deployment watch path.", "deny", contracts.ReasonSystemFrozen, true),

	// ASI05: Unexpected Code Execution.
	cov("RCE-01", "ASI05 Unexpected Code Execution", policybundles.AgentSafetyRuleApprovedArgs, "RequireApprovedArgBinding", "pkg/manifest:argument schema tests", "Shell-free executors remain responsible for avoiding string expansion.", "deny", contracts.ReasonPolicyViolation, true),
	cov("RCE-02", "ASI05 Unexpected Code Execution", policybundles.AgentSafetyRuleTaintedHighRisk, "FailClosedOnMissingContext", "pkg/conformance/scenarios:CI and publish tests", "Static code scanning depth is implementation-specific.", "deny", contracts.ReasonTaintedInputDeny, true),
	cov("RCE-03", "ASI05 Unexpected Code Execution", policybundles.AgentSafetyRuleEgressBoundary, "DenyUnknownEgress", "pkg/conformance/sandbox:network grant tests", "Dependency manager integrations must surface install-time effects.", "deny", contracts.ReasonDataEgressBlocked, true),
	cov("RCE-04", "ASI05 Unexpected Code Execution", policybundles.AgentSafetyRuleTaintedHighRisk, "LKSMemoryInfluenceOnly", "pkg/memory:provenance tests", "Language-specific deserializers need adapter-level deny hooks.", "deny", contracts.ReasonTaintedInputDeny, true),
	cov("RCE-05", "ASI05 Unexpected Code Execution", policybundles.AgentSafetyRuleProtectedConfig, "RequireManifestValidation", "pkg/conformance/sandbox:filesystem grant tests", "Protected path lists are deployment-configurable.", "deny", contracts.ReasonPolicyViolation, true),
	cov("RCE-06", "ASI05 Unexpected Code Execution", policybundles.AgentSafetyRuleSafeDepOverride, "EnforceSafeDepGates", "pkg/conformance/sandbox:isolation tests", "Host kernel hardening is validated by deployment conformance.", "deny", contracts.ReasonSystemFrozen, true),

	// ASI06: Memory and Context Poisoning.
	cov("MEM-01", "ASI06 Memory and Context Poisoning", policybundles.AgentSafetyRuleMemoryInfluenceOnly, "LKSMemoryInfluenceOnly", "pkg/memory:dual-source provenance tests", "Memory scoring quality depends on upstream provenance capture.", "deny", contracts.ReasonSessionRiskDeny, true),
	cov("MEM-02", "ASI06 Memory and Context Poisoning", policybundles.AgentSafetyRuleMemoryInfluenceOnly, "LKSMemoryInfluenceOnly", "pkg/memory:promotion tests", "Tool-ranking models must preserve the LKS authority boundary.", "deny", contracts.ReasonSessionRiskDeny, true),
	cov("MEM-03", "ASI06 Memory and Context Poisoning", policybundles.AgentSafetyRuleMemoryInfluenceOnly, "FailClosedOnMissingContext", "pkg/memory:namespace and store tests", "Tenant-filter correctness depends on caller-provided tenant context.", "deny", contracts.ReasonSessionRiskDeny, true),
	cov("MEM-04", "ASI06 Memory and Context Poisoning", policybundles.AgentSafetyRuleMemoryInfluenceOnly, "LKSMemoryInfluenceOnly", "pkg/memory:review-state tests", "Instruction stripping quality depends on threat scanner adapters.", "deny", contracts.ReasonSessionRiskDeny, true),
	cov("MEM-05", "ASI06 Memory and Context Poisoning", policybundles.AgentSafetyRuleMemoryInfluenceOnly, "RequireA2ASignatures", "pkg/a2a:trust propagation tests", "Shared memory federation depends on signed peer identity.", "deny", contracts.ReasonSessionRiskDeny, true),
	cov("MEM-06", "ASI06 Memory and Context Poisoning", policybundles.AgentSafetyRuleMemoryInfluenceOnly, "LKSMemoryInfluenceOnly", "pkg/memory:store and promotion tests", "Rollback evidence format can be enriched by verifier packages.", "deny", contracts.ReasonSessionRiskDeny, true),

	// ASI07: Insecure Inter-Agent Communication.
	cov("A2A-01", "ASI07 Insecure Inter-Agent Communication", policybundles.AgentSafetyRuleA2AVerification, "RequireA2ASignatures", "pkg/a2a:signature and expiry tests", "Nonce persistence depends on transport-specific replay cache.", "deny", contracts.ReasonDelegationInvalid, true),
	cov("A2A-02", "ASI07 Insecure Inter-Agent Communication", policybundles.AgentSafetyRuleA2AVerification, "RequireA2ASignatures", "pkg/a2a:protocol negotiation tests", "Schema fingerprint pinning must be supplied by each protocol adapter.", "deny", contracts.ReasonDelegationInvalid, true),
	cov("A2A-03", "ASI07 Insecure Inter-Agent Communication", policybundles.AgentSafetyRuleA2AVerification, "RequireA2ASignatures", "pkg/a2a:agent card verifier tests", "Discovery transport trust anchors remain deployment-specific.", "deny", contracts.ReasonDelegationInvalid, true),
	cov("A2A-04", "ASI07 Insecure Inter-Agent Communication", policybundles.AgentSafetyRuleA2AVerification, "FailClosedOnMissingContext", "pkg/a2a:policy negotiation tests", "Semantic adjudication beyond signature validity remains higher-level governance.", "deny", contracts.ReasonDelegationInvalid, true),
	cov("A2A-05", "ASI07 Insecure Inter-Agent Communication", policybundles.AgentSafetyRuleToolContract, "DenyUnknownTools", "pkg/manifest:connector contract tests", "MCP endpoint reputation requires registry integration.", "deny", contracts.ReasonVerification, true),

	// ASI08: Cascading Failures.
	cov("CAS-01", "ASI08 Cascading Failures", policybundles.AgentSafetyRuleHighImpactApproval, "BaselinePolicyEnabled", "pkg/effectgraph:deny cascade tests", "Planner quality is advisory until effect policies approve.", "require_approval", contracts.ReasonApprovalRequired, false),
	cov("CAS-02", "ASI08 Cascading Failures", policybundles.AgentSafetyRuleBudgetCircuitBreaker, "EnforceBudgetCircuitBreakers", "pkg/contracts:budget and risk tests", "Distributed rate limits need deployment metrics.", "deny", contracts.ReasonBudgetExceeded, true),
	cov("CAS-03", "ASI08 Cascading Failures", policybundles.AgentSafetyRuleSupplyChain, "RequireManifestValidation", "pkg/conformance/scenarios:CI publish tests", "CI/CD provider rollback evidence is connector-specific.", "deny", contracts.ReasonProvenance, true),
	cov("CAS-04", "ASI08 Cascading Failures", policybundles.AgentSafetyRuleBudgetCircuitBreaker, "EnforceBudgetCircuitBreakers", "pkg/contracts:budget reason-code tests", "Runtime scheduler must emit retry counters.", "deny", contracts.ReasonBudgetExceeded, true),
	cov("CAS-05", "ASI08 Cascading Failures", policybundles.AgentSafetyRuleSupplyChain, "FailClosedOnMissingContext", "pkg/conformance:replay determinism tests", "Policy learning remains out of execution authority without promotion.", "deny", contracts.ReasonProvenance, true),
	cov("CAS-06", "ASI08 Cascading Failures", policybundles.AgentSafetyRuleSafeDepOverride, "EnforceSafeDepGates", "pkg/safedep:terminal freeze tests", "Incident runbooks are deployment-specific.", "deny", contracts.ReasonSystemFrozen, true),

	// ASI09: Human-Agent Trust Exploitation.
	cov("HITL-01", "ASI09 Human-Agent Trust Exploitation", policybundles.AgentSafetyRuleHighImpactApproval, "RequireManifestValidation", "pkg/contracts:approval binding tests", "UI presentation requirements live outside core package tests.", "require_approval", contracts.ReasonApprovalRequired, false),
	cov("HITL-02", "ASI09 Human-Agent Trust Exploitation", policybundles.AgentSafetyRuleHighImpactApproval, "BaselinePolicyEnabled", "pkg/contracts:effect risk class tests", "Independent verification workflow depends on action inbox integration.", "require_approval", contracts.ReasonApprovalRequired, false),
	cov("HITL-03", "ASI09 Human-Agent Trust Exploitation", policybundles.AgentSafetyRulePreviewSideEffect, "RequireManifestValidation", "pkg/manifest:side-effect schema tests", "Connector preview modes must set inspection_only.", "deny", contracts.ReasonPolicyViolation, true),
	cov("HITL-04", "ASI09 Human-Agent Trust Exploitation", policybundles.AgentSafetyRuleSafeDepOverride, "EnforceSafeDepGates", "pkg/safedep:degraded narrowing tests", "Human report intake is product-surface specific.", "deny", contracts.ReasonSystemFrozen, true),

	// ASI10: Rogue Agents.
	cov("ROG-01", "ASI10 Rogue Agents", policybundles.AgentSafetyRuleProtectedConfig, "FailClosedOnMissingContext", "pkg/contracts:receipt and evidence hash tests", "Observer store hardening depends on production evidence backend.", "deny", contracts.ReasonPolicyViolation, true),
	cov("ROG-02", "ASI10 Rogue Agents", policybundles.AgentSafetyRuleSafeDepOverride, "EnforceSafeDepGates", "pkg/safedep:agent killed and freeze tests", "Signal delivery is runtime-specific.", "deny", contracts.ReasonSystemFrozen, true),
	cov("ROG-03", "ASI10 Rogue Agents", policybundles.AgentSafetyRuleHighImpactApproval, "BaselinePolicyEnabled", "pkg/effectgraph:high-impact classification tests", "Provisioning API adapters must label self-replication effects.", "require_approval", contracts.ReasonApprovalRequired, false),
	cov("ROG-04", "ASI10 Rogue Agents", policybundles.AgentSafetyRuleEgressBoundary, "DenyUnknownEgress", "pkg/firewall:egress deny tests", "Persistent behavior detection depends on runtime telemetry windows.", "deny", contracts.ReasonDataEgressBlocked, true),
	cov("ROG-05", "ASI10 Rogue Agents", policybundles.AgentSafetyRuleA2AVerification, "RequireA2ASignatures", "pkg/a2a:vouching and verifier tests", "Collusion detection beyond identity attestation requires governance review.", "deny", contracts.ReasonDelegationInvalid, true),
	cov("ROG-06", "ASI10 Rogue Agents", policybundles.AgentSafetyRuleProtectedConfig, "RequireManifestValidation", "pkg/contracts:receipt hash tests", "Append-only storage guarantees depend on evidence backend.", "deny", contracts.ReasonPolicyViolation, true),

	// Benchmark imports.
	cov("BENCH-01", "Benchmark Imports", policybundles.AgentSafetyRuleBenchmarkEvidence, "BaselinePolicyEnabled", "pkg/conformance:benchmark registry tests", "Imported suites need local fixture licensing review.", "log", "", false),
	cov("BENCH-02", "Benchmark Imports", policybundles.AgentSafetyRuleBenchmarkEvidence, "BaselinePolicyEnabled", "pkg/conformance:benchmark registry tests", "Harmful workflow scoring needs isolated fixture adapters.", "log", "", false),
	cov("BENCH-03", "Benchmark Imports", policybundles.AgentSafetyRuleBenchmarkEvidence, "BaselinePolicyEnabled", "pkg/conformance:benchmark registry tests", "Benign utility controls must evolve with imported suites.", "log", "", false),
	cov("BENCH-04", "Benchmark Imports", policybundles.AgentSafetyRuleBenchmarkEvidence, "EnforceBudgetCircuitBreakers", "pkg/conformance:adaptive red-team registry tests", "Adaptive red-team loops need runtime attempt budgeting.", "log", "", false),
}
