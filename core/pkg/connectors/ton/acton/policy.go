package acton

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type P0Ceilings struct {
	MaxTONSpendPerAction        string   `json:"MAX_TON_SPEND_PER_ACTION"`
	MaxTONSpendPerDay           string   `json:"MAX_TON_SPEND_PER_DAY"`
	MaxTONMainnetSpendPerAction string   `json:"MAX_TON_MAINNET_SPEND_PER_ACTION"`
	MaxTONMainnetSpendPerDay    string   `json:"MAX_TON_MAINNET_SPEND_PER_DAY"`
	AllowTestnetDeploy          bool     `json:"ALLOW_TESTNET_DEPLOY"`
	AllowMainnetDeploy          bool     `json:"ALLOW_MAINNET_DEPLOY"`
	AllowMainnetLibraryPublish  bool     `json:"ALLOW_MAINNET_LIBRARY_PUBLISH"`
	RequireSourceVerification   bool     `json:"REQUIRE_SOURCE_VERIFICATION"`
	RequireCompilerPin          bool     `json:"REQUIRE_COMPILER_PIN"`
	RequireMutationScoreMin     int      `json:"REQUIRE_MUTATION_SCORE_MIN"`
	RequireCoverageMin          int      `json:"REQUIRE_COVERAGE_MIN"`
	ForbidPlaintextMnemonic     bool     `json:"FORBID_PLAINTEXT_MNEMONIC"`
	ForbidGenericMainnetScript  bool     `json:"FORBID_GENERIC_MAINNET_SCRIPT"`
	RequireApprovalForMainnet   bool     `json:"REQUIRE_APPROVAL_CEREMONY_FOR_MAINNET"`
	AllowedActonVersions        []string `json:"allowed_acton_versions,omitempty"`
	AllowedTolkCompilerVersions []string `json:"allowed_tolk_compiler_versions,omitempty"`
}

type PolicyDecision struct {
	Verdict    contracts.Verdict `json:"verdict"`
	ReasonCode ReasonCode        `json:"reason_code"`
	Reason     string            `json:"reason,omitempty"`
	Dispatch   bool              `json:"dispatch"`
}

func DefaultP0Ceilings() P0Ceilings {
	return P0Ceilings{
		MaxTONSpendPerAction:        "0",
		MaxTONSpendPerDay:           "0",
		MaxTONMainnetSpendPerAction: "0",
		MaxTONMainnetSpendPerDay:    "0",
		AllowTestnetDeploy:          false,
		AllowMainnetDeploy:          false,
		AllowMainnetLibraryPublish:  false,
		RequireSourceVerification:   true,
		RequireCompilerPin:          true,
		RequireMutationScoreMin:     0,
		RequireCoverageMin:          0,
		ForbidPlaintextMnemonic:     true,
		ForbidGenericMainnetScript:  true,
		RequireApprovalForMainnet:   true,
		AllowedActonVersions:        SupportedActonVersions,
		AllowedTolkCompilerVersions: SupportedTolkCompilerVersions,
	}
}

func (c P0Ceilings) Hash() string {
	h, err := canonicalize.CanonicalHash(c)
	if err != nil {
		return ""
	}
	return "sha256:" + h
}

func EvaluatePolicy(env *ActonCommandEnvelope, ceilings P0Ceilings, grant *contracts.SandboxGrant, manifest *ScriptManifest) PolicyDecision {
	spec, ok := commandSpecs[env.ActionURN]
	if !ok {
		return deny(ReasonUnknownCommand, "unknown Acton action")
	}
	if err := env.Validate(); err != nil {
		if strings.Contains(err.Error(), string(ReasonGenericMainnetScriptDenied)) {
			return deny(ReasonGenericMainnetScriptDenied, "generic mainnet script is denied")
		}
		return deny(ReasonArgvRejected, err.Error())
	}
	if IsGenericMainnet(env) && ceilings.ForbidGenericMainnetScript {
		return deny(ReasonGenericMainnetScriptDenied, "generic mainnet script is denied")
	}
	if ceilings.ForbidPlaintextMnemonic && HasPlaintextSecretRisk(env) {
		return deny(ReasonPlaintextMnemonicForbidden, "plaintext wallet material is forbidden")
	}
	if err := ValidateWalletPolicy(env); err != nil {
		return deny(reasonFromError(err, ReasonWalletRefRequired), err.Error())
	}
	if err := ValidateSandboxGrant(env, grant); err != nil {
		return deny(reasonFromError(err, ReasonSandboxGrantRequired), err.Error())
	}
	if spec.RequiresManifest {
		if manifest == nil {
			return deny(ReasonScriptManifestRequired, "networked script requires HELM sidecar manifest")
		}
		if err := manifest.ValidateForEnvelope(env); err != nil {
			return deny(reasonFromError(err, ReasonExpectedEffectMismatch), err.Error())
		}
	}
	if spec.RequiresExpectedEffects && len(env.ExpectedEffects) == 0 {
		return deny(ReasonExpectedEffectMismatch, "expected effects are required")
	}
	if spec.RequiresCompilerPin || ceilings.RequireCompilerPin || env.EvidenceRequirements.RequireCompilerPin {
		if env.TolkCompilerVersion == "" {
			return deny(ReasonCompilerUnpinned, "Tolk compiler version must be pinned")
		}
		if len(ceilings.AllowedTolkCompilerVersions) > 0 && !stringIn(env.TolkCompilerVersion, ceilings.AllowedTolkCompilerVersions) {
			return deny(ReasonCompilerMismatch, "Tolk compiler version is not allowed")
		}
	}
	if err := ValidateSourceVerification(env); err != nil {
		return deny(reasonFromError(err, ReasonSourceVerificationRequired), err.Error())
	}
	if ceilings.RequireSourceVerification && env.ActionURN == ActionScriptMainnet && !env.EvidenceRequirements.RequireVerifierDryRun {
		return deny(ReasonVerifyDryRunRequired, "mainnet deploy requires source verification dry-run evidence")
	}
	if env.ActonVersion != "" && len(ceilings.AllowedActonVersions) > 0 && !stringIn(env.ActonVersion, ceilings.AllowedActonVersions) {
		return deny(ReasonUnsupportedVersion, "Acton version is not allowed")
	}
	if spec.RequiresSpendCap {
		if env.MaxTONSpend == "" {
			return deny(ReasonSpendCeilingExceeded, "spend cap is required")
		}
		if exceedsSpendCeiling(env, ceilings) {
			if env.ActionURN == ActionLibraryPublishMN || env.ActionURN == ActionLibraryTopupMN {
				return deny(ReasonLibrarySpendCeilingExceeded, "library spend exceeds ceiling")
			}
			return deny(ReasonSpendCeilingExceeded, "spend exceeds ceiling")
		}
	}
	if spec.Network == NetworkTestnet && spec.Broadcast && !ceilings.AllowTestnetDeploy {
		return deny(ReasonSpendCeilingExceeded, "testnet broadcast is not policy-allowed")
	}
	if spec.Network == NetworkMainnet && spec.Broadcast {
		if spec.RequiresApproval && ceilings.RequireApprovalForMainnet && env.ApprovalRef == "" {
			if env.ActionURN == ActionLibraryPublishMN || env.ActionURN == ActionLibraryTopupMN {
				return escalate(ReasonLibraryMainnetRequiresApproval, "mainnet library action requires approval ceremony")
			}
			return escalate(ReasonApprovalCeremonyRequired, "mainnet action requires approval ceremony")
		}
		if env.ActionURN == ActionScriptMainnet && !ceilings.AllowMainnetDeploy {
			return escalate(ReasonMainnetRequiresApproval, "mainnet deploy is not policy-allowed")
		}
		if (env.ActionURN == ActionLibraryPublishMN || env.ActionURN == ActionLibraryTopupMN) && !ceilings.AllowMainnetLibraryPublish {
			return escalate(ReasonLibraryMainnetRequiresApproval, "mainnet library publish/top-up is not policy-allowed")
		}
	}
	return PolicyDecision{Verdict: contracts.VerdictAllow, ReasonCode: ReasonOK, Dispatch: true}
}

func deny(code ReasonCode, reason string) PolicyDecision {
	return PolicyDecision{Verdict: contracts.VerdictDeny, ReasonCode: code, Reason: reason}
}

func escalate(code ReasonCode, reason string) PolicyDecision {
	return PolicyDecision{Verdict: contracts.VerdictEscalate, ReasonCode: code, Reason: reason}
}

func reasonFromError(err error, fallback ReasonCode) ReasonCode {
	if err == nil {
		return fallback
	}
	for _, code := range allReasonCodes() {
		if strings.Contains(err.Error(), string(code)) {
			return code
		}
	}
	return fallback
}

func exceedsSpendCeiling(env *ActonCommandEnvelope, ceilings P0Ceilings) bool {
	amount, err := strconv.ParseFloat(env.MaxTONSpend, 64)
	if err != nil {
		return true
	}
	limit := ceilings.MaxTONSpendPerAction
	if env.Network == NetworkMainnet {
		limit = ceilings.MaxTONMainnetSpendPerAction
	}
	limitValue, err := strconv.ParseFloat(limit, 64)
	if err != nil {
		return true
	}
	return amount > limitValue
}

func stringIn(value string, allowed []string) bool {
	for _, item := range allowed {
		if item == value {
			return true
		}
	}
	return false
}

func IsGenericMainnet(env *ActonCommandEnvelope) bool {
	if env == nil {
		return false
	}
	if generic, ok := env.Metadata["generic"].(bool); ok && generic {
		return env.Network == NetworkMainnet
	}
	return env.Network == NetworkMainnet && containsFlagValue(env.Argv, "--net", "mainnet") && len(env.ExpectedEffects) == 0
}

func policyFromParams(params map[string]any) P0Ceilings {
	ceilings := DefaultP0Ceilings()
	raw, ok := params["p0_ceilings"]
	if !ok || raw == nil {
		return ceilings
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return ceilings
	}
	_ = json.Unmarshal(data, &ceilings)
	if len(ceilings.AllowedActonVersions) == 0 {
		ceilings.AllowedActonVersions = SupportedActonVersions
	}
	if len(ceilings.AllowedTolkCompilerVersions) == 0 {
		ceilings.AllowedTolkCompilerVersions = SupportedTolkCompilerVersions
	}
	return ceilings
}

func validateThresholds(env *ActonCommandEnvelope, metrics map[string]float64) PolicyDecision {
	if env.EvidenceRequirements.RequireCoverageMin > 0 {
		if metrics["coverage_percent"] < float64(env.EvidenceRequirements.RequireCoverageMin) {
			return escalate(ReasonCoverageThresholdFailed, fmt.Sprintf("coverage %.2f below threshold %d", metrics["coverage_percent"], env.EvidenceRequirements.RequireCoverageMin))
		}
	}
	if env.EvidenceRequirements.RequireMutationScoreMin > 0 {
		if metrics["mutation_score_percent"] < float64(env.EvidenceRequirements.RequireMutationScoreMin) {
			return escalate(ReasonMutationThresholdFailed, fmt.Sprintf("mutation score %.2f below threshold %d", metrics["mutation_score_percent"], env.EvidenceRequirements.RequireMutationScoreMin))
		}
	}
	return PolicyDecision{Verdict: contracts.VerdictAllow, ReasonCode: ReasonOK, Dispatch: true}
}
