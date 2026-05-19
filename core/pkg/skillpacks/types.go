package skillpacks

import "time"

const (
	VerdictAllow    = "ALLOW"
	VerdictDeny     = "DENY"
	VerdictEscalate = "ESCALATE"

	StatusVerified     = "verified"
	StatusExperimental = "experimental"
	StatusBlocked      = "blocked"
	StatusExternal     = "external"

	ScopeRepo   = "repo"
	ScopeUser   = "user"
	ScopeGlobal = "global"
)

type Manifest struct {
	SchemaVersion              string   `json:"schema_version"`
	ID                         string   `json:"id"`
	Name                       string   `json:"name"`
	Version                    string   `json:"version"`
	Description                string   `json:"description"`
	Publisher                  string   `json:"publisher"`
	Status                     string   `json:"status"`
	ScopeDefault               string   `json:"scope_default"`
	Risk                       string   `json:"risk"`
	LicenseSPDX                string   `json:"license_spdx"`
	SignatureRef               string   `json:"signature_ref"`
	PublisherKeyRef            string   `json:"publisher_key_ref,omitempty"`
	ProvenanceRef              string   `json:"provenance_ref"`
	PolicyRef                  string   `json:"policy_ref"`
	AgentTargets               []string `json:"agent_targets"`
	RequestedMCPServers        []string `json:"requested_mcp_servers,omitempty"`
	RequestedMCPTools          []string `json:"requested_mcp_tools,omitempty"`
	Hooks                      []string `json:"hooks,omitempty"`
	Scripts                    []string `json:"scripts,omitempty"`
	PermissionsDoNotGrantTools bool     `json:"permissions_do_not_grant_tools"`
	ContentHash                string   `json:"content_hash,omitempty"`
}

type SkillPack struct {
	Manifest Manifest `json:"manifest"`
	SkillMD  string   `json:"skill_md"`
	Root     string   `json:"-"`
}

type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Path     string `json:"path,omitempty"`
}

type ScanAttestation struct {
	ID               string    `json:"id"`
	Type             string    `json:"type"`
	SkillID          string    `json:"skill_id"`
	Verdict          string    `json:"verdict"`
	ReasonCode       string    `json:"reason_code,omitempty"`
	SkillContentHash string    `json:"skill_content_hash"`
	CreatedAt        time.Time `json:"created_at"`
}

type ScanResult struct {
	SkillID          string          `json:"skill_id"`
	Verdict          string          `json:"verdict"`
	ReasonCode       string          `json:"reason_code,omitempty"`
	SkillContentHash string          `json:"skill_content_hash"`
	Findings         []Finding       `json:"findings"`
	Attestation      ScanAttestation `json:"attestation"`
}

type InstallRequest struct {
	Agent    string `json:"agent"`
	Scope    string `json:"scope"`
	RepoRoot string `json:"repo_root"`
}

type Projection struct {
	Agent string `json:"agent"`
	Path  string `json:"path"`
}

type Receipt struct {
	ID               string       `json:"id"`
	Type             string       `json:"type"`
	SkillID          string       `json:"skill_id"`
	Verdict          string       `json:"verdict"`
	ReasonCode       string       `json:"reason_code,omitempty"`
	SkillContentHash string       `json:"skill_content_hash,omitempty"`
	PolicyHash       string       `json:"policy_hash,omitempty"`
	ProjectionPaths  []Projection `json:"projection_paths,omitempty"`
	CreatedAt        time.Time    `json:"created_at"`
}

type InstallResult struct {
	SkillID           string       `json:"skill_id"`
	Status            string       `json:"status"`
	Verdict           string       `json:"verdict"`
	ReasonCode        string       `json:"reason_code,omitempty"`
	Scan              ScanResult   `json:"scan"`
	InstallReceipt    Receipt      `json:"install_receipt"`
	ProjectionReceipt Receipt      `json:"projection_receipt"`
	ProjectionPaths   []Projection `json:"projection_paths"`
	Message           string       `json:"message,omitempty"`
}

type Marketplace struct {
	SchemaVersion string              `json:"schema_version"`
	Plugins       []MarketplacePlugin `json:"plugins"`
}

type MarketplacePlugin struct {
	ID          string `json:"id"`
	Path        string `json:"path"`
	PolicyHash  string `json:"policy_hash"`
	SourceHash  string `json:"source_hash"`
	Status      string `json:"status"`
	ScannedAt   string `json:"scanned_at"`
	Description string `json:"description,omitempty"`
}
