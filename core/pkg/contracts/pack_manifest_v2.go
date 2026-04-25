package contracts

import "time"

// PackChannel controls where an installable add-on can be surfaced.
//
// OSS recognizes all four channels as data (so manifests round-trip
// unchanged), but the OSS install runtime (core/pkg/packs/install) only
// installs core and community packs. Teams and enterprise channels are
// gated by commercial entitlement logic layered above.
type PackChannel string

const (
	PackChannelCore       PackChannel = "core"
	PackChannelCommunity  PackChannel = "community"
	PackChannelTeams      PackChannel = "teams"
	PackChannelEnterprise PackChannel = "enterprise"
)

// PackExtensionPoint is a declared integration seam for installable packs.
type PackExtensionPoint string

const (
	PackExtensionRoute     PackExtensionPoint = "route"
	PackExtensionPanel     PackExtensionPoint = "panel"
	PackExtensionConnector PackExtensionPoint = "connector"
	PackExtensionJob       PackExtensionPoint = "job"
	PackExtensionSetting   PackExtensionPoint = "setting"
	PackExtensionPolicy    PackExtensionPoint = "policy"
	PackExtensionDocs      PackExtensionPoint = "docs"
)

// PackPermission declares a runtime capability requested by a pack.
type PackPermission struct {
	ID            string `json:"id"`
	Justification string `json:"justification"`
}

// PackSecret declares a secret required during install or runtime.
type PackSecret struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

// PackCheck declares a deterministic install, smoke, or rollback check.
type PackCheck struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Command     string `json:"command,omitempty"`
}

// PackSignature attests to the integrity of a published pack.
type PackSignature struct {
	SignerID  string    `json:"signer_id"`
	KeyID     string    `json:"key_id,omitempty"`
	Algorithm string    `json:"algorithm"`
	SignedAt  time.Time `json:"signed_at"`
	Signature string    `json:"signature"`
}

// PackManifestV2 is the canonical manifest for one-click installable HELM add-ons.
//
// MinimumEdition is carried as a free-form string so OSS can round-trip
// manifests without depending on commercial Edition types. The OSS
// install runtime does not enforce edition gating; that belongs in the
// commercial entitlement layer that wraps this package.
type PackManifestV2 struct {
	PackID          string               `json:"pack_id"`
	Name            string               `json:"name"`
	Version         string               `json:"version"`
	Channel         PackChannel          `json:"channel"`
	Summary         string               `json:"summary,omitempty"`
	Description     string               `json:"description,omitempty"`
	MinimumEdition  string               `json:"minimum_edition,omitempty"`
	ExtensionPoints []PackExtensionPoint `json:"extension_points,omitempty"`
	Dependencies    []string             `json:"dependencies,omitempty"`
	Permissions     []PackPermission     `json:"permissions,omitempty"`
	Secrets         []PackSecret         `json:"secrets,omitempty"`
	Migrations      []PackCheck          `json:"migrations,omitempty"`
	InstallChecks   []PackCheck          `json:"install_checks,omitempty"`
	SmokeTests      []PackCheck          `json:"smoke_tests,omitempty"`
	RollbackChecks  []PackCheck          `json:"rollback_checks,omitempty"`
	Docs            []string             `json:"docs,omitempty"`
	Signatures      []PackSignature      `json:"signatures,omitempty"`
}

// InstalledPack is the runtime state of a pack after installation.
type InstalledPack struct {
	PackID      string     `json:"pack_id"`
	Version     string     `json:"version"`
	Status      string     `json:"status"`
	InstalledAt *time.Time `json:"installed_at,omitempty"`
}

// PackInstallPlan describes the canonical install flow before activation.
//
// The Eligible flag reflects OSS-layer checks only (secrets present,
// installable channel, not revoked). Commercial callers layer
// additional gates (edition minimums, entitlement capabilities) on top
// of this plan.
type PackInstallPlan struct {
	PackID            string   `json:"pack_id"`
	Version           string   `json:"version"`
	Action            string   `json:"action,omitempty"`
	DryRun            bool     `json:"dry_run"`
	Eligible          bool     `json:"eligible"`
	RequiresUpgrade   bool     `json:"requires_upgrade,omitempty"`
	MinimumEdition    string   `json:"minimum_edition,omitempty"`
	CurrentVersion    string   `json:"current_version,omitempty"`
	Steps             []string `json:"steps"`
	MissingSecrets    []string `json:"missing_secrets,omitempty"`
	IneligibleReasons []string `json:"ineligible_reasons,omitempty"`
}
