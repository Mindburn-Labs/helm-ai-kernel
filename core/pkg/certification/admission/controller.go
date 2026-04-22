// Package admission implements attestation-based admission control
// for packs and deployments. It blocks execution if required
// attestations are missing or invalid.
package admission

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/certification"
)

// AdmissionDecision represents the outcome of an admission check.
type AdmissionDecision string

const (
	DecisionAllow      AdmissionDecision = "allow"
	DecisionDeny       AdmissionDecision = "deny"
	DecisionQuarantine AdmissionDecision = "quarantine"
	DecisionAudit      AdmissionDecision = "audit"
)

// EnforcementMode defines how violations are handled.
type EnforcementMode string

const (
	ModeEnforce  EnforcementMode = "enforce"
	ModeAudit    EnforcementMode = "audit"
	ModeDisabled EnforcementMode = "disabled"
)

// PackAdmissionProfile defines requirements for pack admission.
type PackAdmissionProfile struct {
	ProfileID                 string          `json:"profile_id"`
	Version                   string          `json:"version"`
	Name                      string          `json:"name"`
	Description               string          `json:"description,omitempty"`
	Enabled                   bool            `json:"enabled"`
	TrustTier                 string          `json:"trust_tier,omitempty"`
	AdmissionRequirements     AdmissionReqs   `json:"admission_requirements"`
	SignatureRequirements     *SignatureReqs  `json:"signature_requirements,omitempty"`
	ProvenanceRequirements    *ProvenanceReqs `json:"provenance_requirements,omitempty"`
	CertificationRequirements *CertReqs       `json:"certification_requirements,omitempty"`
	Enforcement               Enforcement     `json:"enforcement"`
}

// AdmissionReqs defines core admission requirements.
type AdmissionReqs struct {
	RequireAttestation     bool     `json:"require_attestation"`
	RequireValidSignatures bool     `json:"require_valid_signatures"`
	MinimumSigners         int      `json:"minimum_signers,omitempty"`
	RequiredSignerRoles    []string `json:"required_signer_roles,omitempty"`
	AllowedRegistries      []string `json:"allowed_registries,omitempty"`
	DeniedRegistries       []string `json:"denied_registries,omitempty"`
	MaxAttestationAgeHours int      `json:"max_attestation_age_hours,omitempty"`
}

// SignatureReqs defines signature requirements.
type SignatureReqs struct {
	AllowedAlgorithms  []string `json:"allowed_algorithms,omitempty"`
	TrustedSigners     []string `json:"trusted_signers,omitempty"`
	KeyRotationMaxDays int      `json:"key_rotation_max_days,omitempty"`
}

// ProvenanceReqs defines provenance requirements.
type ProvenanceReqs struct {
	RequireReproducibleBuild bool     `json:"require_reproducible_build,omitempty"`
	AllowedBuilders          []string `json:"allowed_builders,omitempty"`
	RequireSourceRepo        bool     `json:"require_source_repo,omitempty"`
	AllowedSourceRepos       []string `json:"allowed_source_repos,omitempty"`
	RequireDependencyHashes  bool     `json:"require_dependency_hashes,omitempty"`
}

// CertReqs defines certification requirements.
type CertReqs struct {
	RequireSchemaConformance bool     `json:"require_schema_conformance"`
	RequireDeterminismTests  bool     `json:"require_determinism_tests"`
	RequireSecurityAudit     bool     `json:"require_security_audit,omitempty"`
	MinDeterminismTestCount  int      `json:"min_determinism_test_count,omitempty"`
	MaxEffectTypes           int      `json:"max_effect_types,omitempty"`
	DeniedEffectTypes        []string `json:"denied_effect_types,omitempty"`
}

// Enforcement defines enforcement configuration.
type Enforcement struct {
	Mode       EnforcementMode `json:"mode"`
	FailAction string          `json:"fail_action,omitempty"`
}

// AdmissionResult contains the full admission check result.
type AdmissionResult struct {
	Decision   AdmissionDecision `json:"decision"`
	Violations []Violation       `json:"violations,omitempty"`
	Timestamp  time.Time         `json:"timestamp"`
	ProfileID  string            `json:"profile_id"`
	Subject    string            `json:"subject"`
	AuditOnly  bool              `json:"audit_only"`
}

// Violation represents a single admission violation.
type Violation struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	Severity    string `json:"severity"`
	Requirement string `json:"requirement"`
}

// Controller implements attestation-based admission control.
type Controller struct {
	mu             sync.RWMutex
	profiles       map[string]*PackAdmissionProfile
	deployProfiles map[string]*DeployAdmissionProfile
	publicKeys     map[string]ed25519.PublicKey
	handlers       []ViolationHandler
}

// DeployAdmissionProfile defines requirements for deployment admission.
type DeployAdmissionProfile struct {
	ProfileID               string           `json:"profile_id"`
	Version                 string           `json:"version"`
	Name                    string           `json:"name"`
	Enabled                 bool             `json:"enabled"`
	Environments            []string         `json:"environments"`
	EnvironmentRequirements EnvReqs          `json:"environment_requirements"`
	ApprovalChain           *ApprovalChain   `json:"approval_chain,omitempty"`
	RolloutPolicy           *RolloutPolicy   `json:"rollout_policy,omitempty"`
	PreDeployChecks         *PreDeployChecks `json:"pre_deploy_checks,omitempty"`
	Enforcement             Enforcement      `json:"enforcement"`
}

// EnvReqs defines environment requirements.
type EnvReqs struct {
	RequirePackAttestation      bool   `json:"require_pack_attestation"`
	RequirePriorEnvironment     string `json:"require_prior_environment,omitempty"`
	MinSoakTimeHours            int    `json:"min_soak_time_hours,omitempty"`
	RequireHealthCheck          bool   `json:"require_health_check"`
	RequireSmokeTests           bool   `json:"require_smoke_tests,omitempty"`
	RequireErrorBudgetAvailable bool   `json:"require_error_budget_available,omitempty"`
}

// ApprovalChain defines approval requirements.
type ApprovalChain struct {
	RequiredApprovers    int      `json:"required_approvers"`
	ApproverRoles        []string `json:"approver_roles,omitempty"`
	ApprovalTimeoutHours int      `json:"approval_timeout_hours,omitempty"`
	RequireDeployWindow  bool     `json:"require_deploy_window,omitempty"`
}

// RolloutPolicy defines rollout strategy.
type RolloutPolicy struct {
	Strategy         string   `json:"strategy"`
	AutoRollback     bool     `json:"auto_rollback"`
	RollbackTriggers []string `json:"rollback_triggers,omitempty"`
}

// PreDeployChecks defines pre-deployment checks.
type PreDeployChecks struct {
	RequireFAS100           bool   `json:"require_fas_100,omitempty"`
	MinFASScore             int    `json:"min_fas_score,omitempty"`
	RequireIntegrationTests bool   `json:"require_integration_tests,omitempty"`
	RequireSecurityScan     bool   `json:"require_security_scan,omitempty"`
	BlockedOnCVESeverity    string `json:"blocked_on_cve_severity,omitempty"`
}

// ViolationHandler is called when violations are detected.
type ViolationHandler func(ctx context.Context, result AdmissionResult)

// NewController creates a new admission controller.
//
//nolint:gocognit // constructor complexity is acceptable
func NewController() *Controller {
	return &Controller{
		profiles:       make(map[string]*PackAdmissionProfile),
		deployProfiles: make(map[string]*DeployAdmissionProfile),
		publicKeys:     make(map[string]ed25519.PublicKey),
	}
}

// LoadPackProfile loads a pack admission profile.
func (c *Controller) LoadPackProfile(profile *PackAdmissionProfile) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.profiles[profile.ProfileID] = profile
	return nil
}

// LoadPackProfileJSON removed - was dead code

// LoadDeployProfile loads a deployment admission profile.
func (c *Controller) LoadDeployProfile(profile *DeployAdmissionProfile) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deployProfiles[profile.ProfileID] = profile
	return nil
}

// RegisterPublicKey registers a signer's public key.
func (c *Controller) RegisterPublicKey(signerID string, key ed25519.PublicKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.publicKeys[signerID] = key
}

// AddViolationHandler registers a handler for violations.
func (c *Controller) AddViolationHandler(h ViolationHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handlers = append(c.handlers, h)
}

// AdmitPack checks if a pack with attestation should be admitted.
//
//nolint:gocognit // complexity acceptable for admission logic
func (c *Controller) AdmitPack(ctx context.Context, profileID string, attestation *certification.ModuleAttestation, registryURI string) AdmissionResult {
	c.mu.RLock()
	profile, ok := c.profiles[profileID]
	publicKeys := c.publicKeys
	c.mu.RUnlock()

	// Determine subject safely
	subject := "unknown"
	if attestation != nil {
		subject = attestation.Module.ModuleID
	}

	result := AdmissionResult{
		Decision:  DecisionAllow,
		Timestamp: time.Now().UTC(),
		ProfileID: profileID,
		Subject:   subject,
	}

	if !ok {
		result.Decision = DecisionDeny
		result.Violations = append(result.Violations, Violation{
			Code:     "PROFILE_NOT_FOUND",
			Message:  fmt.Sprintf("Profile %s not found", profileID),
			Severity: "critical",
		})
		return result
	}

	if !profile.Enabled || profile.Enforcement.Mode == ModeDisabled {
		return result
	}

	// Check admission requirements
	violations := c.checkPackAdmission(profile, attestation, registryURI, publicKeys)
	result.Violations = violations

	if len(violations) > 0 {
		if profile.Enforcement.Mode == ModeEnforce {
			result.Decision = DecisionDeny
		} else {
			result.AuditOnly = true
		}
	}

	if len(violations) > 0 {
		c.notifyHandlers(ctx, result)
	}

	return result
}

// checkPackAdmission checks pack against profile requirements.
//
//nolint:gocognit,gocyclo // complexity acceptable for admission logic
func (c *Controller) checkPackAdmission(profile *PackAdmissionProfile, att *certification.ModuleAttestation, registryURI string, publicKeys map[string]ed25519.PublicKey) []Violation {
	var violations []Violation
	reqs := profile.AdmissionRequirements

	// Check attestation exists
	if reqs.RequireAttestation && att == nil {
		violations = append(violations, Violation{
			Code:        "NO_ATTESTATION",
			Message:     "Pack attestation is required",
			Severity:    "critical",
			Requirement: "require_attestation",
		})
		return violations
	}

	// Check attestation age
	if reqs.MaxAttestationAgeHours > 0 {
		age := time.Since(att.CreatedAt)
		if age.Hours() > float64(reqs.MaxAttestationAgeHours) {
			violations = append(violations, Violation{
				Code:        "ATTESTATION_EXPIRED",
				Message:     fmt.Sprintf("Attestation is %.1f hours old (max %d)", age.Hours(), reqs.MaxAttestationAgeHours),
				Severity:    "high",
				Requirement: "max_attestation_age_hours",
			})
		}
	}

	// Check signatures
	if reqs.RequireValidSignatures {
		if err := att.Verify(publicKeys); err != nil {
			violations = append(violations, Violation{
				Code:        "INVALID_SIGNATURE",
				Message:     fmt.Sprintf("Signature verification failed: %v", err),
				Severity:    "critical",
				Requirement: "require_valid_signatures",
			})
		}
	}

	// Check minimum signers
	if reqs.MinimumSigners > 0 && len(att.Signatures) < reqs.MinimumSigners {
		violations = append(violations, Violation{
			Code:        "INSUFFICIENT_SIGNERS",
			Message:     fmt.Sprintf("Pack has %d signers but requires %d", len(att.Signatures), reqs.MinimumSigners),
			Severity:    "high",
			Requirement: "minimum_signers",
		})
	}

	// Check required signer roles
	for _, requiredRole := range reqs.RequiredSignerRoles {
		found := false
		for _, sig := range att.Signatures {
			if sig.SignerRole == requiredRole {
				found = true
				break
			}
		}
		if !found {
			violations = append(violations, Violation{
				Code:        "MISSING_SIGNER_ROLE",
				Message:     fmt.Sprintf("Missing required signer role: %s", requiredRole),
				Severity:    "high",
				Requirement: "required_signer_roles",
			})
		}
	}

	// Check registry allowlist
	if len(reqs.AllowedRegistries) > 0 {
		allowed := false
		for _, r := range reqs.AllowedRegistries {
			if r == registryURI {
				allowed = true
				break
			}
		}
		if !allowed {
			violations = append(violations, Violation{
				Code:        "REGISTRY_NOT_ALLOWED",
				Message:     fmt.Sprintf("Registry %s not in allowlist", registryURI),
				Severity:    "high",
				Requirement: "allowed_registries",
			})
		}
	}

	// Check registry denylist
	for _, r := range reqs.DeniedRegistries {
		if r == registryURI {
			violations = append(violations, Violation{
				Code:        "REGISTRY_DENIED",
				Message:     fmt.Sprintf("Registry %s is denied", registryURI),
				Severity:    "critical",
				Requirement: "denied_registries",
			})
		}
	}

	// Check provenance
	if profile.ProvenanceRequirements != nil {
		prov := profile.ProvenanceRequirements
		if prov.RequireReproducibleBuild && !att.Provenance.Reproducible {
			violations = append(violations, Violation{
				Code:        "NOT_REPRODUCIBLE",
				Message:     "Build is not reproducible",
				Severity:    "high",
				Requirement: "require_reproducible_build",
			})
		}
		if prov.RequireSourceRepo && att.Module.SourceRepo == "" {
			violations = append(violations, Violation{
				Code:        "NO_SOURCE_REPO",
				Message:     "Source repository is required",
				Severity:    "medium",
				Requirement: "require_source_repo",
			})
		}
	}

	// Check certification
	if profile.CertificationRequirements != nil {
		cert := profile.CertificationRequirements
		if cert.RequireSchemaConformance && !att.Certification.SchemaConformance.Passed {
			violations = append(violations, Violation{
				Code:        "SCHEMA_NONCONFORMANT",
				Message:     "Schema conformance tests did not pass",
				Severity:    "high",
				Requirement: "require_schema_conformance",
			})
		}
		if cert.RequireDeterminismTests && !att.Certification.DeterminismTests.Passed {
			violations = append(violations, Violation{
				Code:        "DETERMINISM_FAILED",
				Message:     "Determinism tests did not pass",
				Severity:    "high",
				Requirement: "require_determinism_tests",
			})
		}
		if cert.MinDeterminismTestCount > 0 && att.Certification.DeterminismTests.TestCount < cert.MinDeterminismTestCount {
			violations = append(violations, Violation{
				Code:        "INSUFFICIENT_TESTS",
				Message:     fmt.Sprintf("Only %d determinism tests (min %d)", att.Certification.DeterminismTests.TestCount, cert.MinDeterminismTestCount),
				Severity:    "medium",
				Requirement: "min_determinism_test_count",
			})
		}
	}

	return violations
}

// AdmitDeploy checks if a deployment should be admitted.
func (c *Controller) AdmitDeploy(ctx context.Context, profileID string, packAttestation *certification.ModuleAttestation, env string, fasScore int, approvals int) AdmissionResult {
	c.mu.RLock()
	profile, ok := c.deployProfiles[profileID]
	c.mu.RUnlock()

	// Determine subject safely
	subject := "unknown@" + env
	if packAttestation != nil {
		subject = packAttestation.Module.ModuleID + "@" + env
	}

	result := AdmissionResult{
		Decision:  DecisionAllow,
		Timestamp: time.Now().UTC(),
		ProfileID: profileID,
		Subject:   subject,
	}

	if !ok {
		result.Decision = DecisionDeny
		result.Violations = append(result.Violations, Violation{
			Code:     "PROFILE_NOT_FOUND",
			Message:  fmt.Sprintf("Deploy profile %s not found", profileID),
			Severity: "critical",
		})
		return result
	}

	if !profile.Enabled || profile.Enforcement.Mode == ModeDisabled {
		return result
	}

	var violations []Violation

	// Check environment requirements
	envReqs := profile.EnvironmentRequirements
	if envReqs.RequirePackAttestation && packAttestation == nil {
		violations = append(violations, Violation{
			Code:        "NO_PACK_ATTESTATION",
			Message:     "Pack attestation required for deployment",
			Severity:    "critical",
			Requirement: "require_pack_attestation",
		})
	}

	// Check pre-deploy checks
	if profile.PreDeployChecks != nil {
		checks := profile.PreDeployChecks
		if checks.RequireFAS100 && fasScore < 100 {
			violations = append(violations, Violation{
				Code:        "FAS_BELOW_100",
				Message:     fmt.Sprintf("FAS score is %d but 100 required", fasScore),
				Severity:    "critical",
				Requirement: "require_fas_100",
			})
		}
		if checks.MinFASScore > 0 && fasScore < checks.MinFASScore {
			violations = append(violations, Violation{
				Code:        "FAS_TOO_LOW",
				Message:     fmt.Sprintf("FAS score %d below minimum %d", fasScore, checks.MinFASScore),
				Severity:    "high",
				Requirement: "min_fas_score",
			})
		}
	}

	// Check approval chain
	if profile.ApprovalChain != nil && profile.ApprovalChain.RequiredApprovers > 0 {
		if approvals < profile.ApprovalChain.RequiredApprovers {
			violations = append(violations, Violation{
				Code:        "INSUFFICIENT_APPROVALS",
				Message:     fmt.Sprintf("Has %d approvals but requires %d", approvals, profile.ApprovalChain.RequiredApprovers),
				Severity:    "high",
				Requirement: "required_approvers",
			})
		}
	}

	result.Violations = violations
	if len(violations) > 0 {
		if profile.Enforcement.Mode == ModeEnforce {
			result.Decision = DecisionDeny
		} else {
			result.AuditOnly = true
		}
		c.notifyHandlers(ctx, result)
	}

	return result
}

// notifyHandlers notifies violation handlers.
func (c *Controller) notifyHandlers(ctx context.Context, result AdmissionResult) {
	c.mu.RLock()
	handlers := c.handlers
	c.mu.RUnlock()
	for _, h := range handlers {
		h(ctx, result)
	}
}
