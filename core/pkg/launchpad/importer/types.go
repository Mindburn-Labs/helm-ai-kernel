package importer

import (
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
)

type ImportState string

const (
	StateImported    ImportState = "IMPORTED"
	StatePreflighted ImportState = "PREFLIGHTED"
	StatePromotable  ImportState = "PROMOTABLE"
	StateBlocked     ImportState = "BLOCKED"
	StateLaunched    ImportState = "LAUNCHED"
	StateTornDown    ImportState = "TORN_DOWN"
)

type ImportRequest struct {
	RepoURL       string `json:"repo_url"`
	Ref           string `json:"ref,omitempty"`
	DesiredTarget string `json:"desired_target,omitempty"`
}

type SourceSnapshot struct {
	RepoURL      string              `json:"repo_url"`
	Provider     string              `json:"provider"`
	Owner        string              `json:"owner,omitempty"`
	Repo         string              `json:"repo,omitempty"`
	Ref          string              `json:"ref,omitempty"`
	Commit       string              `json:"commit,omitempty"`
	LicenseSPDX  string              `json:"license_spdx,omitempty"`
	LicenseState string              `json:"license_state"`
	FetchedAt    time.Time           `json:"fetched_at"`
	Files        []SourceFileSummary `json:"files"`
	APISource    string              `json:"api_source,omitempty"`
}

type SourceFileSummary struct {
	Path     string `json:"path"`
	Kind     string `json:"kind"`
	Size     int64  `json:"size,omitempty"`
	SHA      string `json:"sha,omitempty"`
	Language string `json:"language,omitempty"`
	Content  string `json:"content,omitempty"`
}

type CapabilityGraph struct {
	Capabilities     []string            `json:"capabilities"`
	Modules          []DetectedModule    `json:"modules"`
	Frameworks       []DetectedFramework `json:"frameworks"`
	Secrets          []SecretContract    `json:"secrets"`
	OAuth            []OAuthRequirement  `json:"oauth"`
	Ports            []int               `json:"ports"`
	BuildSignals     []string            `json:"build_signals"`
	RuntimeSignals   []string            `json:"runtime_signals"`
	PolicySignals    []string            `json:"policy_signals"`
	SecuritySignals  []string            `json:"security_signals"`
	AdapterMatches   []AdapterMatch      `json:"adapter_matches"`
	Confidence       float64             `json:"confidence"`
	ConfidenceReason string              `json:"confidence_reason"`
}

type DetectedModule struct {
	Path          string   `json:"path"`
	Kind          string   `json:"kind"`
	Manifests     []string `json:"manifests"`
	Entrypoints   []string `json:"entrypoints,omitempty"`
	BuildStrategy string   `json:"build_strategy,omitempty"`
}

type DetectedFramework struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Confidence float64  `json:"confidence"`
	Evidence   []string `json:"evidence"`
}

type SecretContract struct {
	Name     string   `json:"name"`
	Source   string   `json:"source"`
	Required bool     `json:"required"`
	Reason   string   `json:"reason,omitempty"`
	Targets  []string `json:"targets,omitempty"`
}

type OAuthRequirement struct {
	Provider string   `json:"provider"`
	Scopes   []string `json:"scopes,omitempty"`
	Source   string   `json:"source"`
}

type AdapterMatch struct {
	AdapterID  string   `json:"adapter_id"`
	Confidence float64  `json:"confidence"`
	Evidence   []string `json:"evidence"`
}

type FrameworkAdapter struct {
	APIVersion   string             `json:"apiVersion" yaml:"apiVersion"`
	Kind         string             `json:"kind" yaml:"kind"`
	Metadata     AdapterMetadata    `json:"metadata" yaml:"metadata"`
	Match        AdapterMatchSpec   `json:"match" yaml:"match"`
	Capabilities []string           `json:"capabilities" yaml:"capabilities"`
	Entrypoints  AdapterEntrypoints `json:"entrypoints" yaml:"entrypoints"`
	Build        AdapterBuildSpec   `json:"build" yaml:"build"`
	Dependencies AdapterDeps        `json:"dependencies" yaml:"dependencies"`
	Secrets      AdapterSecrets     `json:"secrets" yaml:"secrets"`
	Network      AdapterNetwork     `json:"network" yaml:"network"`
	Tests        AdapterTests       `json:"tests" yaml:"tests"`
	Rollback     AdapterRollback    `json:"rollback" yaml:"rollback"`
}

type AdapterMetadata struct {
	ID       string `json:"id" yaml:"id"`
	Version  string `json:"version" yaml:"version"`
	Priority int    `json:"priority" yaml:"priority"`
}

type AdapterMatchSpec struct {
	FilesAny            []string `json:"filesAny,omitempty" yaml:"filesAny,omitempty"`
	FilesAll            []string `json:"filesAll,omitempty" yaml:"filesAll,omitempty"`
	ReadmeRegex         []string `json:"readmeRegex,omitempty" yaml:"readmeRegex,omitempty"`
	RepoTopics          []string `json:"repoTopics,omitempty" yaml:"repoTopics,omitempty"`
	ConfidenceThreshold float64  `json:"confidenceThreshold,omitempty" yaml:"confidenceThreshold,omitempty"`
}

type AdapterEntrypoints struct {
	Local []AdapterCommand `json:"local,omitempty" yaml:"local,omitempty"`
	Cloud []AdapterCommand `json:"cloud,omitempty" yaml:"cloud,omitempty"`
}

type AdapterCommand struct {
	Name    string   `json:"name" yaml:"name"`
	Command []string `json:"command" yaml:"command"`
}

type AdapterBuildSpec struct {
	Strategy string `json:"strategy" yaml:"strategy"`
}

type AdapterDeps struct {
	Files []string `json:"files,omitempty" yaml:"files,omitempty"`
}

type AdapterSecrets struct {
	Required []string `json:"required,omitempty" yaml:"required,omitempty"`
	Optional []string `json:"optional,omitempty" yaml:"optional,omitempty"`
}

type AdapterNetwork struct {
	Ports       []int              `json:"ports,omitempty" yaml:"ports,omitempty"`
	Healthcheck AdapterHealthcheck `json:"healthcheck,omitempty" yaml:"healthcheck,omitempty"`
}

type AdapterHealthcheck struct {
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
	Path string `json:"path,omitempty" yaml:"path,omitempty"`
}

type AdapterTests struct {
	Smoke [][]string `json:"smoke,omitempty" yaml:"smoke,omitempty"`
}

type AdapterRollback struct {
	Strategy string `json:"strategy,omitempty" yaml:"strategy,omitempty"`
}

type BuildStrategy struct {
	Strategy        string     `json:"strategy"`
	Confidence      float64    `json:"confidence"`
	Reason          string     `json:"reason"`
	Commands        [][]string `json:"commands,omitempty"`
	ManifestSources []string   `json:"manifest_sources,omitempty"`
}

type TargetPlan struct {
	TargetID         string            `json:"target_id"`
	Kind             string            `json:"kind"`
	SubstrateID      string            `json:"substrate_id,omitempty"`
	Deployable       bool              `json:"deployable"`
	RequiresApproval bool              `json:"requires_approval"`
	Commands         [][]string        `json:"commands,omitempty"`
	Artifacts        []string          `json:"artifacts,omitempty"`
	SecretsBackend   string            `json:"secrets_backend,omitempty"`
	Healthcheck      map[string]string `json:"healthcheck,omitempty"`
	Rollback         []string          `json:"rollback,omitempty"`
	Risk             string            `json:"risk"`
	Reason           string            `json:"reason"`
}

type LaunchRecipe struct {
	ImportID              string                      `json:"import_id"`
	GeneratedAt           time.Time                   `json:"generated_at"`
	DetectionOrder        []string                    `json:"detection_order"`
	BuildStrategy         BuildStrategy               `json:"build_strategy"`
	TargetPlans           []TargetPlan                `json:"target_plans"`
	GeneratedAppSpecs     []GeneratedAppSpecCandidate `json:"generated_app_specs"`
	PromotionState        string                      `json:"promotion_state"`
	PromotionRequirements []string                    `json:"promotion_requirements"`
	CLIEquivalent         string                      `json:"cli_equivalent"`
}

type GeneratedAppSpecCandidate struct {
	CandidateID           string           `json:"candidate_id"`
	Trusted               bool             `json:"trusted"`
	AppSpec               registry.AppSpec `json:"app_spec"`
	PromotionRequirements []string         `json:"promotion_requirements"`
}

type ImportEvidenceLedger struct {
	Status               string   `json:"status"`
	ReceiptRefs          []string `json:"receipt_refs"`
	EvidencePackRefs     []string `json:"evidence_pack_refs"`
	SBOMRef              string   `json:"sbom_ref,omitempty"`
	VulnerabilityScanRef string   `json:"vulnerability_scan_ref,omitempty"`
	ProvenanceRef        string   `json:"provenance_ref,omitempty"`
	LicenseRef           string   `json:"license_ref,omitempty"`
	PolicyRefs           []string `json:"policy_refs,omitempty"`
	OfflineVerifyCommand string   `json:"offline_verify_command,omitempty"`
}

type ImportPreflightResult struct {
	ImportID       string               `json:"import_id"`
	Status         string               `json:"status"`
	Checks         []PreflightCheck     `json:"checks"`
	BlockedReasons []string             `json:"blocked_reasons,omitempty"`
	EvidenceLedger ImportEvidenceLedger `json:"evidence_ledger"`
}

type PreflightCheck struct {
	ID          string   `json:"id"`
	Status      string   `json:"status"`
	Summary     string   `json:"summary"`
	EvidenceRef string   `json:"evidence_ref,omitempty"`
	FixActions  []string `json:"fix_actions,omitempty"`
}

type ImportRecord struct {
	ID              string                 `json:"id"`
	State           ImportState            `json:"state"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
	Request         ImportRequest          `json:"request"`
	SourceSnapshot  SourceSnapshot         `json:"source_snapshot"`
	CapabilityGraph CapabilityGraph        `json:"capability_graph"`
	LaunchRecipe    LaunchRecipe           `json:"launch_recipe"`
	Preflight       *ImportPreflightResult `json:"preflight,omitempty"`
	EvidenceLedger  ImportEvidenceLedger   `json:"evidence_ledger"`
}
