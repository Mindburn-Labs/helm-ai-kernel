package riskenvelope

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

const SchemaVersion = "risk-envelope/v1"

var (
	hmacRefPattern   = regexp.MustCompile(`^hmac:[a-f0-9]{64}$`)
	sha256RefPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

type CohortBucket string

const (
	CohortUnknown      CohortBucket = "unknown"
	CohortRepos1To10   CohortBucket = "1-10repos"
	CohortRepos11To50  CohortBucket = "11-50repos"
	CohortRepos51To200 CohortBucket = "51-200repos"
	CohortRepos201Plus CohortBucket = "201plusrepos"
)

type ResourceType string

const (
	ResourceRepo              ResourceType = "repo"
	ResourceMCPServer         ResourceType = "mcp_server"
	ResourceWorkflow          ResourceType = "workflow"
	ResourceSecretClass       ResourceType = "secret_class"
	ResourcePermissionProfile ResourceType = "permission_profile"
	ResourceEnvironment       ResourceType = "environment"
	ResourceOAuthClient       ResourceType = "oauth_client"
	ResourceIAMPrincipal      ResourceType = "iam_principal"
)

type RiskCode string

const (
	RiskAgentWriteWithoutEnvApproval RiskCode = "AGENT_WRITE_WITHOUT_ENV_APPROVAL"
	RiskBroadShellAllow              RiskCode = "BROAD_SHELL_ALLOW"
	RiskBypassPermissionsEnabled     RiskCode = "BYPASS_PERMISSIONS_ENABLED"
	RiskMCPWriteScopeWithoutApproval RiskCode = "MCP_WRITE_SCOPE_WITHOUT_APPROVAL"
	RiskProdEnvWithoutReviewers      RiskCode = "PROD_ENV_WITHOUT_REVIEWERS"
	RiskSecretClassAgentReadable     RiskCode = "SECRET_CLASS_AGENT_READABLE"
	RiskDirectDispatchSeen           RiskCode = "DIRECT_DISPATCH_SEEN"
	RiskNoManagedSettings            RiskCode = "NO_MANAGED_SETTINGS"
	RiskNoAuditExport                RiskCode = "NO_AUDIT_EXPORT"
	RiskNoBranchProtection           RiskCode = "NO_BRANCH_PROTECTION"
	RiskSchemaPinMissing             RiskCode = "SCHEMA_PIN_MISSING"
	RiskIAMAdminGrantVisible         RiskCode = "IAM_ADMIN_GRANT_VISIBLE"
	RiskOAuthHighRiskScope           RiskCode = "OAUTH_HIGH_RISK_SCOPE"
	RiskCIWorkflowWriteToken         RiskCode = "CI_WORKFLOW_WRITE_TOKEN"
)

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type AgentSurface string

const (
	AgentSurfaceUnknown       AgentSurface = "unknown"
	AgentSurfaceClaudeCode    AgentSurface = "claude_code"
	AgentSurfaceCodex         AgentSurface = "codex"
	AgentSurfaceGitHubActions AgentSurface = "github_actions"
	AgentSurfaceMCP           AgentSurface = "mcp"
)

type ToolClass string

const (
	ToolClassUnknown          ToolClass = "unknown"
	ToolClassGitPush          ToolClass = "git_push"
	ToolClassGitWrite         ToolClass = "git_write"
	ToolClassDBWrite          ToolClass = "db_write"
	ToolClassMCPWrite         ToolClass = "mcp_write"
	ToolClassMCPRead          ToolClass = "mcp_read"
	ToolClassDeployPublish    ToolClass = "deploy_publish"
	ToolClassSecretRead       ToolClass = "secret_read"
	ToolClassPaymentInitiate  ToolClass = "payment_initiate"
	ToolClassShellOperate     ToolClass = "shell_operate"
	ToolClassNetworkEgress    ToolClass = "network_egress"
	ToolClassWorkflowDispatch ToolClass = "workflow_dispatch"
)

type PermissionMode string

const (
	PermissionModeUnknown           PermissionMode = "unknown"
	PermissionModePlan              PermissionMode = "plan"
	PermissionModeAsk               PermissionMode = "ask"
	PermissionModeAcceptEdits       PermissionMode = "accept_edits"
	PermissionModeBypassPermissions PermissionMode = "bypass_permissions"
)

type OAuthScopeBucket string

const (
	OAuthScopeNone     OAuthScopeBucket = "none"
	OAuthScopeRead     OAuthScopeBucket = "read"
	OAuthScopeWrite    OAuthScopeBucket = "write"
	OAuthScopeAdmin    OAuthScopeBucket = "admin"
	OAuthScopeRepo     OAuthScopeBucket = "repo"
	OAuthScopeWorkflow OAuthScopeBucket = "workflow"
	OAuthScopeCloud    OAuthScopeBucket = "cloud"
	OAuthScopeDB       OAuthScopeBucket = "db"
	OAuthScopeUnknown  OAuthScopeBucket = "unknown"
)

type IAMGrantBucket string

const (
	IAMGrantNone    IAMGrantBucket = "none"
	IAMGrantRead    IAMGrantBucket = "read"
	IAMGrantWrite   IAMGrantBucket = "write"
	IAMGrantAdmin   IAMGrantBucket = "admin"
	IAMGrantCloud   IAMGrantBucket = "cloud"
	IAMGrantDeploy  IAMGrantBucket = "deploy"
	IAMGrantBilling IAMGrantBucket = "billing"
	IAMGrantUnknown IAMGrantBucket = "unknown"
)

type RiskEnvelope struct {
	SchemaVersion  string               `json:"schema_version"`
	EnvelopeID     string               `json:"envelope_id"`
	CohortBucket   CohortBucket         `json:"cohort_bucket"`
	SourcePackHash string               `json:"source_pack_hash"`
	Findings       []EnvelopeFinding    `json:"findings"`
	Posture        PostureProbe         `json:"posture"`
	Privacy        PrivacyNonCollection `json:"privacy"`
	GeneratedAt    time.Time            `json:"generated_at"`
}

type EnvelopeFinding struct {
	ResourceID   string           `json:"resource_id"`
	ResourceType ResourceType     `json:"resource_type"`
	RiskCode     RiskCode         `json:"risk_code"`
	Severity     Severity         `json:"severity"`
	Evidence     EnvelopeEvidence `json:"evidence"`
}

type EnvelopeEvidence struct {
	AgentTool             ToolClass      `json:"agent_tool,omitempty"`
	PermissionMode        PermissionMode `json:"permission_mode,omitempty"`
	BranchProtection      *bool          `json:"branch_protection,omitempty"`
	ProdEnvReviewers      *int           `json:"prod_env_reviewers,omitempty"`
	MCPWriteScopes        *bool          `json:"mcp_write_scopes,omitempty"`
	ManagedSettings       *bool          `json:"managed_settings,omitempty"`
	AuditLogging          *bool          `json:"audit_logging,omitempty"`
	SchemaPinned          *bool          `json:"schema_pinned,omitempty"`
	DirectDispatchSeen    *bool          `json:"direct_dispatch_seen,omitempty"`
	SecretValueAccessible *bool          `json:"secret_value_accessible,omitempty"`
}

type PostureProbe struct {
	AgentSurface           AgentSurface            `json:"agent_surface"`
	PermissionMode         PermissionMode          `json:"permission_mode"`
	ManagedSettingsPresent bool                    `json:"managed_settings_present"`
	MCPServerCount         int                     `json:"mcp_server_count"`
	OAuthScopeBuckets      []OAuthScopeBucketCount `json:"oauth_scope_buckets"`
	IAMGrantBuckets        []IAMGrantBucketCount   `json:"iam_grant_buckets"`
	StaticConfigFilesRead  int                     `json:"static_config_files_read"`
	MetadataAPICalls       int                     `json:"metadata_api_calls"`
}

type OAuthScopeBucketCount struct {
	Bucket OAuthScopeBucket `json:"bucket"`
	Count  int              `json:"count"`
}

type IAMGrantBucketCount struct {
	Bucket IAMGrantBucket `json:"bucket"`
	Count  int            `json:"count"`
}

type PrivacyNonCollection struct {
	RawPromptsCollected   bool `json:"raw_prompts_collected"`
	SourceCodeCollected   bool `json:"source_code_collected"`
	SecretValuesCollected bool `json:"secret_values_collected"`
	CommandBodiesExported bool `json:"command_bodies_exported"`
}

func Pseudonym(salt []byte, rawID string) (string, error) {
	if len(salt) < 16 {
		return "", fmt.Errorf("risk envelope pseudonym salt must be at least 16 bytes")
	}
	if strings.TrimSpace(rawID) == "" {
		return "", fmt.Errorf("risk envelope pseudonym raw id is required")
	}
	mac := hmac.New(sha256.New, salt)
	_, _ = mac.Write([]byte(rawID))
	return "hmac:" + hex.EncodeToString(mac.Sum(nil)), nil
}

func EnvelopeID(salt []byte, sourcePackHash string) (string, error) {
	if !sha256RefPattern.MatchString(sourcePackHash) {
		return "", fmt.Errorf("source pack hash must be sha256:<64 lowercase hex>")
	}
	return Pseudonym(salt, sourcePackHash)
}

func SHA256Ref(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func CanonicalSHA256Ref(v any) (string, error) {
	hash, err := canonicalize.CanonicalHash(v)
	if err != nil {
		return "", err
	}
	return "sha256:" + hash, nil
}

func (e RiskEnvelope) Validate() error {
	if e.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version must be %q", SchemaVersion)
	}
	if !hmacRefPattern.MatchString(e.EnvelopeID) {
		return fmt.Errorf("envelope_id must be hmac:<64 lowercase hex>")
	}
	if !validCohortBucket(e.CohortBucket) {
		return fmt.Errorf("invalid cohort_bucket %q", e.CohortBucket)
	}
	if !sha256RefPattern.MatchString(e.SourcePackHash) {
		return fmt.Errorf("source_pack_hash must be sha256:<64 lowercase hex>")
	}
	if e.GeneratedAt.IsZero() {
		return fmt.Errorf("generated_at is required")
	}
	if e.Findings == nil {
		return fmt.Errorf("findings must be an array, not null")
	}
	if err := e.Posture.validate(); err != nil {
		return fmt.Errorf("posture: %w", err)
	}
	if err := e.Privacy.validate(); err != nil {
		return fmt.Errorf("privacy: %w", err)
	}
	for i, finding := range e.Findings {
		if err := finding.validate(); err != nil {
			return fmt.Errorf("findings[%d]: %w", i, err)
		}
	}
	return nil
}

func (f EnvelopeFinding) validate() error {
	if !hmacRefPattern.MatchString(f.ResourceID) {
		return fmt.Errorf("resource_id must be hmac:<64 lowercase hex>")
	}
	if !validResourceType(f.ResourceType) {
		return fmt.Errorf("invalid resource_type %q", f.ResourceType)
	}
	if !validRiskCode(f.RiskCode) {
		return fmt.Errorf("invalid risk_code %q", f.RiskCode)
	}
	if !validSeverity(f.Severity) {
		return fmt.Errorf("invalid severity %q", f.Severity)
	}
	if err := f.Evidence.validate(); err != nil {
		return fmt.Errorf("evidence: %w", err)
	}
	return nil
}

func (e EnvelopeEvidence) validate() error {
	if e.AgentTool != "" && !validToolClass(e.AgentTool) {
		return fmt.Errorf("invalid agent_tool %q", e.AgentTool)
	}
	if e.PermissionMode != "" && !validPermissionMode(e.PermissionMode) {
		return fmt.Errorf("invalid permission_mode %q", e.PermissionMode)
	}
	if e.ProdEnvReviewers != nil && *e.ProdEnvReviewers < 0 {
		return fmt.Errorf("prod_env_reviewers cannot be negative")
	}
	return nil
}

func (p PostureProbe) validate() error {
	if !validAgentSurface(p.AgentSurface) {
		return fmt.Errorf("invalid agent_surface %q", p.AgentSurface)
	}
	if !validPermissionMode(p.PermissionMode) {
		return fmt.Errorf("invalid permission_mode %q", p.PermissionMode)
	}
	if p.MCPServerCount < 0 || p.StaticConfigFilesRead < 0 || p.MetadataAPICalls < 0 {
		return fmt.Errorf("counts cannot be negative")
	}
	if p.OAuthScopeBuckets == nil {
		return fmt.Errorf("oauth_scope_buckets must be an array, not null")
	}
	if p.IAMGrantBuckets == nil {
		return fmt.Errorf("iam_grant_buckets must be an array, not null")
	}
	for i, bucket := range p.OAuthScopeBuckets {
		if !validOAuthScopeBucket(bucket.Bucket) {
			return fmt.Errorf("oauth_scope_buckets[%d] invalid bucket %q", i, bucket.Bucket)
		}
		if bucket.Count < 0 {
			return fmt.Errorf("oauth_scope_buckets[%d] count cannot be negative", i)
		}
	}
	for i, bucket := range p.IAMGrantBuckets {
		if !validIAMGrantBucket(bucket.Bucket) {
			return fmt.Errorf("iam_grant_buckets[%d] invalid bucket %q", i, bucket.Bucket)
		}
		if bucket.Count < 0 {
			return fmt.Errorf("iam_grant_buckets[%d] count cannot be negative", i)
		}
	}
	return nil
}

func (p PrivacyNonCollection) validate() error {
	if p.RawPromptsCollected || p.SourceCodeCollected || p.SecretValuesCollected || p.CommandBodiesExported {
		return fmt.Errorf("risk envelope upload must not collect prompts, source code, secret values, or command bodies")
	}
	return nil
}

func validCohortBucket(v CohortBucket) bool {
	switch v {
	case CohortUnknown, CohortRepos1To10, CohortRepos11To50, CohortRepos51To200, CohortRepos201Plus:
		return true
	default:
		return false
	}
}

func validResourceType(v ResourceType) bool {
	switch v {
	case ResourceRepo, ResourceMCPServer, ResourceWorkflow, ResourceSecretClass, ResourcePermissionProfile, ResourceEnvironment, ResourceOAuthClient, ResourceIAMPrincipal:
		return true
	default:
		return false
	}
}

func validRiskCode(v RiskCode) bool {
	switch v {
	case RiskAgentWriteWithoutEnvApproval, RiskBroadShellAllow, RiskBypassPermissionsEnabled, RiskMCPWriteScopeWithoutApproval, RiskProdEnvWithoutReviewers, RiskSecretClassAgentReadable, RiskDirectDispatchSeen, RiskNoManagedSettings, RiskNoAuditExport, RiskNoBranchProtection, RiskSchemaPinMissing, RiskIAMAdminGrantVisible, RiskOAuthHighRiskScope, RiskCIWorkflowWriteToken:
		return true
	default:
		return false
	}
}

func validSeverity(v Severity) bool {
	switch v {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

func validAgentSurface(v AgentSurface) bool {
	switch v {
	case AgentSurfaceUnknown, AgentSurfaceClaudeCode, AgentSurfaceCodex, AgentSurfaceGitHubActions, AgentSurfaceMCP:
		return true
	default:
		return false
	}
}

func validToolClass(v ToolClass) bool {
	switch v {
	case ToolClassUnknown, ToolClassGitPush, ToolClassGitWrite, ToolClassDBWrite, ToolClassMCPWrite, ToolClassMCPRead, ToolClassDeployPublish, ToolClassSecretRead, ToolClassPaymentInitiate, ToolClassShellOperate, ToolClassNetworkEgress, ToolClassWorkflowDispatch:
		return true
	default:
		return false
	}
}

func validPermissionMode(v PermissionMode) bool {
	switch v {
	case PermissionModeUnknown, PermissionModePlan, PermissionModeAsk, PermissionModeAcceptEdits, PermissionModeBypassPermissions:
		return true
	default:
		return false
	}
}

func validOAuthScopeBucket(v OAuthScopeBucket) bool {
	switch v {
	case OAuthScopeNone, OAuthScopeRead, OAuthScopeWrite, OAuthScopeAdmin, OAuthScopeRepo, OAuthScopeWorkflow, OAuthScopeCloud, OAuthScopeDB, OAuthScopeUnknown:
		return true
	default:
		return false
	}
}

func validIAMGrantBucket(v IAMGrantBucket) bool {
	switch v {
	case IAMGrantNone, IAMGrantRead, IAMGrantWrite, IAMGrantAdmin, IAMGrantCloud, IAMGrantDeploy, IAMGrantBilling, IAMGrantUnknown:
		return true
	default:
		return false
	}
}
