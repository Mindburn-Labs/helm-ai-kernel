package skillpacks

import (
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

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

	// Publisher states say what a scan established about who published a
	// pack. Manifest fields never set them: status, publisher, signature_ref
	// and publisher_key_ref are written by the pack's author.

	// PublisherFirstParty: every file of the pack hashes to the digest this
	// binary was built with for the pack's id and version.
	PublisherFirstParty = "first_party"
	// PublisherFirstPartyMismatch: the binary pins this id and version, and
	// the pack's files are not the pinned ones.
	PublisherFirstPartyMismatch = "first_party_mismatch"
	// PublisherUnsigned: nothing was verified. HELM has no publisher signature
	// format or publisher key for SkillPacks, so a pack outside the
	// first-party manifest has no publisher HELM can name.
	PublisherUnsigned = "unsigned"
	// PublisherNotChecked: this scan did not judge the publisher because its
	// caller does (ProjectionLifecycle and its configured verifier).
	PublisherNotChecked = "not_checked"

	PublisherBasisFirstPartyManifest = "first_party_manifest"
	PublisherBasisProjectionVerifier = "projection_trust_verifier"
	PublisherBasisNone               = "none"

	// PolicySourceKernel marks a verdict reached under the rules compiled into
	// this binary.
	PolicySourceKernel = "kernel"
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

// PublisherVerification is the computed answer to "who published this pack".
// Basis names the trust material the answer rests on, ContentDigest is the
// digest over every file of the pack when one could be computed, and Reason
// says in words what was and was not checked.
type PublisherVerification struct {
	State         string `json:"state"`
	Basis         string `json:"basis"`
	ContentDigest string `json:"content_digest,omitempty"`
	Reason        string `json:"reason"`
}

// ScanPolicy names the policy a verdict was reached under. It is always the
// kernel's: a pack's policy_ref is a declaration and is never resolved, so a
// pack cannot choose the rules that judge it.
type ScanPolicy struct {
	Source string `json:"source"`
	Ref    string `json:"ref"`
	Hash   string `json:"hash"`
}

type ScanAttestation struct {
	ID                string    `json:"id"`
	Type              string    `json:"type"`
	SkillID           string    `json:"skill_id"`
	Verdict           string    `json:"verdict"`
	ReasonCode        string    `json:"reason_code,omitempty"`
	SkillContentHash  string    `json:"skill_content_hash"`
	PublisherState    string    `json:"publisher_state"`
	PackContentDigest string    `json:"pack_content_digest,omitempty"`
	PolicyHash        string    `json:"policy_hash"`
	CreatedAt         time.Time `json:"created_at"`
}

type ScanResult struct {
	SkillID               string                `json:"skill_id"`
	Verdict               string                `json:"verdict"`
	ReasonCode            string                `json:"reason_code,omitempty"`
	SkillContentHash      string                `json:"skill_content_hash"`
	PublisherVerification PublisherVerification `json:"publisher_verification"`
	Policy                ScanPolicy            `json:"policy"`
	Findings              []Finding             `json:"findings"`
	Attestation           ScanAttestation       `json:"attestation"`
}

// CatalogEntry is one pack of the working tree's registry with the publisher
// state computed for it. Manifest.Status is what the pack declares.
type CatalogEntry struct {
	Manifest              Manifest              `json:"manifest"`
	PublisherVerification PublisherVerification `json:"publisher_verification"`
}

type InstallRequest struct {
	Agent    string `json:"agent"`
	Scope    string `json:"scope"`
	RepoRoot string `json:"repo_root"`
}

type Projection = contracts.Projection

type Receipt = contracts.Receipt

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

// MarketplacePlugin is a marketplace entry. Adding a plugin records where it is
// and the hash of its plugin.json; it runs no scan, so Status says "recorded".
type MarketplacePlugin struct {
	ID          string `json:"id"`
	Path        string `json:"path"`
	PolicyHash  string `json:"policy_hash"`
	SourceHash  string `json:"source_hash"`
	Status      string `json:"status"`
	RecordedAt  string `json:"recorded_at"`
	Description string `json:"description,omitempty"`
}
