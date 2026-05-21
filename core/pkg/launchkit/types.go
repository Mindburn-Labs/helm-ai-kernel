package launchkit

import (
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/session"
)

type Mode string

const (
	ModeAuto       Mode = "auto"
	ModeDemo       Mode = "demo"
	ModeVerifyOnly Mode = "verify-only"
	ModeLive       Mode = "live"
)

type Target string

const (
	TargetLocal           Target = "local"
	TargetCloudHELM       Target = "cloud:helm"
	TargetCloudAWS        Target = "cloud:aws"
	TargetCloudKubernetes Target = "cloud:kubernetes"
)

type GateStatus string

const (
	GatePending  GateStatus = "PENDING"
	GateAllow    GateStatus = "ALLOW"
	GateDeny     GateStatus = "DENY"
	GateEscalate GateStatus = "ESCALATE"
	GateSkipped  GateStatus = "SKIPPED"
)

type Gate struct {
	ID            string     `json:"id"`
	Label         string     `json:"label"`
	Status        GateStatus `json:"status"`
	ReasonCode    string     `json:"reason_code,omitempty"`
	Summary       string     `json:"summary"`
	ReceiptRefs   []string   `json:"receipt_refs,omitempty"`
	EvidenceRefs  []string   `json:"evidence_refs,omitempty"`
	CLIEquivalent string     `json:"cli_equivalent,omitempty"`
}

type Options struct {
	AppID          string
	Target         Target
	Mode           Mode
	ResumeRunID    string
	Yes            bool
	Principal      string
	CatalogRoot    string
	StoreRoot      string
	ConsoleBaseURL string
	NoOpen         bool
}

type Result struct {
	AppID                string                `json:"app_id"`
	Mode                 Mode                  `json:"mode"`
	Target               Target                `json:"target"`
	SubstrateID          string                `json:"substrate_id,omitempty"`
	Run                  *session.LaunchRun    `json:"run,omitempty"`
	Plan                 *plan.LaunchPlan      `json:"plan,omitempty"`
	Gates                []Gate                `json:"gates"`
	Provider             EnvironmentCapability `json:"provider"`
	ConsoleURL           string                `json:"console_url,omitempty"`
	OfflineVerifyCommand string                `json:"offline_verify_command,omitempty"`
	ResumeCommand        string                `json:"resume_command,omitempty"`
	VerifyOnly           bool                  `json:"verify_only"`
	StartedRuntime       bool                  `json:"started_runtime"`
	GeneratedAt          time.Time             `json:"generated_at"`
}

type EnvironmentCapability struct {
	ID                    string            `json:"id"`
	Kind                  string            `json:"kind"`
	Available             bool              `json:"available"`
	AuthState             string            `json:"auth_state"`
	CostEstimate          string            `json:"cost_estimate"`
	Region                string            `json:"region,omitempty"`
	SecretBackend         string            `json:"secret_backend"`
	NetworkBoundary       string            `json:"network_boundary"`
	RuntimeBoundary       string            `json:"runtime_boundary"`
	LogBoundary           string            `json:"log_boundary"`
	TeardownSupport       string            `json:"teardown_support"`
	EvidenceExportSupport string            `json:"evidence_export_support"`
	Detail                string            `json:"detail,omitempty"`
	Metadata              map[string]string `json:"metadata,omitempty"`
}

type EnvironmentProvider interface {
	ID() Target
	SubstrateID() string
	Probe() EnvironmentCapability
}

type AppSpec struct {
	LegacyRegistryRef string `json:"legacy_registry_ref,omitempty"`
	DirectoryRef      string `json:"directory_ref,omitempty"`
}

type BootstrapPlan struct {
	Provider EnvironmentCapability `json:"provider"`
	Mode     Mode                  `json:"mode"`
	Target   Target                `json:"target"`
}

type GateChain struct {
	Gates []Gate `json:"gates"`
}

type SecretPlan struct {
	Required []string `json:"required"`
	Injected []string `json:"injected"`
	Mode     string   `json:"mode"`
}

type SandboxGrant struct {
	Hash      string   `json:"hash"`
	Runtime   string   `json:"runtime"`
	Mounts    []string `json:"mounts"`
	Network   []string `json:"network"`
	ProofRefs []string `json:"proof_refs"`
}

type MCPRegistryPlan struct {
	UnknownServerPolicy string   `json:"unknown_server_policy"`
	UnknownToolPolicy   string   `json:"unknown_tool_policy"`
	QuarantinedTools    []string `json:"quarantined_tools"`
}

type RuntimeInstance struct {
	RunID       string `json:"run_id"`
	Runtime     string `json:"runtime"`
	State       string `json:"state"`
	ContainerID string `json:"container_id,omitempty"`
}

type ReceiptStream struct {
	Refs []string `json:"refs"`
}

type EvidencePackRefSet struct {
	Refs                 []string `json:"refs"`
	OfflineVerifyCommand string   `json:"offline_verify_command,omitempty"`
}

type OfflineVerifier struct {
	Command string `json:"command"`
	Ready   bool   `json:"ready"`
}
