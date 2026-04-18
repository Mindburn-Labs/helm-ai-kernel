package contracts

import "time"

// PackChannel controls where an installable add-on can be surfaced.
type PackChannel string

const (
	// PackChannelCore marks a first-party HELM pack shipping with OSS.
	PackChannelCore PackChannel = "core"
	// PackChannelCommunity marks an unsigned/community-published pack.
	PackChannelCommunity PackChannel = "community"
	// PackChannelTeams marks a paid-tier pack gated by the commercial layer.
	PackChannelTeams PackChannel = "teams"
	// PackChannelEnterprise marks an enterprise-only pack gated by the commercial layer.
	PackChannelEnterprise PackChannel = "enterprise"
)

// PackExtensionPoint is a declared integration seam for installable packs.
type PackExtensionPoint string

const (
	// PackExtensionRoute is a Studio route surface.
	PackExtensionRoute PackExtensionPoint = "route"
	// PackExtensionPanel is a Studio panel surface.
	PackExtensionPanel PackExtensionPoint = "panel"
	// PackExtensionConnector is an execution-side connector surface.
	PackExtensionConnector PackExtensionPoint = "connector"
	// PackExtensionJob is a background job surface.
	PackExtensionJob PackExtensionPoint = "job"
	// PackExtensionSetting is a settings extension point.
	PackExtensionSetting PackExtensionPoint = "setting"
	// PackExtensionPolicy is a policy contribution point.
	PackExtensionPolicy PackExtensionPoint = "policy"
	// PackExtensionDocs is a documentation contribution point.
	PackExtensionDocs PackExtensionPoint = "docs"
)

// PackPermission declares a runtime capability requested by a pack.
type PackPermission struct {
	ID            string `json:"id" yaml:"id"`
	Justification string `json:"justification" yaml:"justification"`
}

// PackSecret declares a secret required during install or runtime.
type PackSecret struct {
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description" yaml:"description"`
	Required    bool   `json:"required" yaml:"required"`
}

// PackCheck declares a deterministic install, smoke, or rollback check.
type PackCheck struct {
	ID          string `json:"id" yaml:"id"`
	Description string `json:"description" yaml:"description"`
	Command     string `json:"command,omitempty" yaml:"command,omitempty"`
}

// PackSignature attests to the integrity of a published pack.
type PackSignature struct {
	SignerID  string    `json:"signer_id" yaml:"signer_id"`
	KeyID     string    `json:"key_id,omitempty" yaml:"key_id,omitempty"`
	Algorithm string    `json:"algorithm" yaml:"algorithm"`
	SignedAt  time.Time `json:"signed_at" yaml:"signed_at"`
	Signature string    `json:"signature" yaml:"signature"`
}

// PackManifestV2 is the canonical manifest for one-click installable HELM
// add-ons. MinimumEdition is kept as an untyped string in OSS so this package
// does not depend on commercial Edition/Capability types; entitlement
// enforcement is layered on top in the commercial control plane.
type PackManifestV2 struct {
	PackID          string               `json:"pack_id" yaml:"pack_id"`
	Name            string               `json:"name" yaml:"name"`
	Version         string               `json:"version" yaml:"version"`
	Channel         PackChannel          `json:"channel" yaml:"channel"`
	Summary         string               `json:"summary,omitempty" yaml:"summary,omitempty"`
	Description     string               `json:"description,omitempty" yaml:"description,omitempty"`
	MinimumEdition  string               `json:"minimum_edition" yaml:"minimum_edition"`
	ExtensionPoints []PackExtensionPoint `json:"extension_points,omitempty" yaml:"extension_points,omitempty"`
	Dependencies    []string             `json:"dependencies,omitempty" yaml:"dependencies,omitempty"`
	Permissions     []PackPermission     `json:"permissions,omitempty" yaml:"permissions,omitempty"`
	Secrets         []PackSecret         `json:"secrets,omitempty" yaml:"secrets,omitempty"`
	Migrations      []PackCheck          `json:"migrations,omitempty" yaml:"migrations,omitempty"`
	InstallChecks   []PackCheck          `json:"install_checks,omitempty" yaml:"install_checks,omitempty"`
	SmokeTests      []PackCheck          `json:"smoke_tests,omitempty" yaml:"smoke_tests,omitempty"`
	RollbackChecks  []PackCheck          `json:"rollback_checks,omitempty" yaml:"rollback_checks,omitempty"`
	Docs            []string             `json:"docs,omitempty" yaml:"docs,omitempty"`
	Signatures      []PackSignature      `json:"signatures,omitempty" yaml:"signatures,omitempty"`
}

// InstalledPack is the runtime state of a pack after installation.
type InstalledPack struct {
	PackID      string     `json:"pack_id"`
	Version     string     `json:"version"`
	Status      string     `json:"status"`
	InstalledAt *time.Time `json:"installed_at,omitempty"`
}

// PackInstallPlan describes the canonical install flow served to Studio
// before activation. IneligibleReasons carries plain-string diagnostics so the
// OSS contract is decoupled from the commercial Capability type; the
// commercial wrapper layer maps reasons to enterprise capability tokens.
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
	IneligibleReasons []string `json:"ineligible_reasons,omitempty"`
	MissingSecrets    []string `json:"missing_secrets,omitempty"`
}
