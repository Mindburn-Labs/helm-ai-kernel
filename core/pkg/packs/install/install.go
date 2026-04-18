// Package install provides the OSS-side pack install runner for
// installable HELM add-ons. It exposes a small Runner API
// (Plan, Install, Uninstall, Rollback) over a persistence Store interface.
//
// At the OSS boundary, only the "core" and "community" channels are
// eligible; "teams" and "enterprise" packs are rejected with ErrIneligible
// and an IneligibleReasons diagnostic so the commercial wrapper layer can
// attach entitlement semantics without changing this package.
package install

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// Action identifiers for pack lifecycle operations.
const (
	ActionInstall   = "install"
	ActionUpgrade   = "upgrade"
	ActionUninstall = "uninstall"
	ActionRollback  = "rollback"
)

// ErrStateNotFound indicates a lifecycle operation targeted a pack with no
// prior install state (e.g. Uninstall or Rollback before Install).
var ErrStateNotFound = errors.New("install: pack state not found")

// ErrIneligible indicates a pack cannot be installed by the OSS boundary
// because it targets a gated channel or is missing required inputs. Inspect
// the returned plan for the specific IneligibleReasons / MissingSecrets.
var ErrIneligible = errors.New("install: pack install plan is not eligible")

// Options carries per-operation toggles for Plan/Install.
type Options struct {
	// DryRun, when true, produces a plan without mutating state.
	DryRun bool
	// Secrets maps PackSecret name → provided value. Required secrets missing
	// from this map surface as plan.MissingSecrets.
	Secrets map[string]string
}

// InstallResult bundles the outputs of a successful Install call.
type InstallResult struct {
	Action        string
	PackID        string
	Plan          contracts.PackInstallPlan
	InstalledPack *contracts.InstalledPack
	State         *State
	Receipt       *Receipt
}

// Runner drives the pack lifecycle on top of a Store.
type Runner struct {
	store Store
}

// NewRunner constructs a Runner backed by store.
func NewRunner(store Store) *Runner {
	return &Runner{store: store}
}

// Plan returns the canonical install plan for (packID, manifest, action)
// without mutating state.
func (r *Runner) Plan(ctx context.Context, packID string, manifest contracts.PackManifestV2, action string, opts Options) (contracts.PackInstallPlan, error) {
	_ = ctx
	state, _ := r.store.Get(packID)
	return buildPlan(packID, manifest, state, action, opts), nil
}

// Install applies the manifest (install or upgrade, chosen from existing
// state) and returns the resulting InstallResult. Ineligible plans return
// ErrIneligible with plan populated for caller diagnostics.
func (r *Runner) Install(ctx context.Context, packID string, manifest contracts.PackManifestV2, opts Options) (*InstallResult, error) {
	_ = ctx
	state, _ := r.store.Get(packID)
	action := ActionInstall
	if state != nil && state.Version != "" && state.Version != manifest.Version {
		action = ActionUpgrade
	}
	plan := buildPlan(packID, manifest, state, action, opts)
	result := &InstallResult{Action: action, PackID: packID, Plan: plan}

	if !plan.Eligible {
		return result, ErrIneligible
	}
	if opts.DryRun {
		return result, nil
	}

	now := time.Now().UTC()
	if state == nil {
		state = &State{PackID: packID}
	}
	state.PackID = packID
	state.Version = manifest.Version
	state.Status = "installed"
	state.LastAction = action
	state.LastError = ""
	state.ManifestHash = ComputeManifestHash(canonicalManifestBytes(manifest))
	state.InstallCount++
	state.InstalledAt = &now
	state.UpdatedAt = now

	receipt := newReceipt(packID, action, state.ManifestHash, state.PrevReceiptHash, now)
	state.PrevReceiptHash = receipt.Hash

	if err := r.store.Put(state); err != nil {
		return result, fmt.Errorf("persist state: %w", err)
	}

	result.State = state
	result.InstalledPack = &contracts.InstalledPack{
		PackID:      state.PackID,
		Version:     state.Version,
		Status:      state.Status,
		InstalledAt: state.InstalledAt,
	}
	result.Receipt = receipt
	return result, nil
}

// Uninstall marks the pack uninstalled and appends an uninstall receipt.
func (r *Runner) Uninstall(ctx context.Context, packID string) (*Receipt, error) {
	_ = ctx
	state, err := r.store.Get(packID)
	if err != nil || state == nil {
		return nil, ErrStateNotFound
	}
	now := time.Now().UTC()
	receipt := newReceipt(packID, ActionUninstall, state.ManifestHash, state.PrevReceiptHash, now)
	state.Status = "uninstalled"
	state.LastAction = ActionUninstall
	state.InstalledAt = nil
	state.UpdatedAt = now
	state.PrevReceiptHash = receipt.Hash
	if err := r.store.Put(state); err != nil {
		return nil, fmt.Errorf("persist state: %w", err)
	}
	return receipt, nil
}

// Rollback marks the pack rolled back and appends a rollback receipt.
func (r *Runner) Rollback(ctx context.Context, packID string) (*Receipt, error) {
	_ = ctx
	state, err := r.store.Get(packID)
	if err != nil || state == nil {
		return nil, ErrStateNotFound
	}
	now := time.Now().UTC()
	receipt := newReceipt(packID, ActionRollback, state.ManifestHash, state.PrevReceiptHash, now)
	state.Status = "rolled_back"
	state.LastAction = ActionRollback
	state.InstalledAt = nil
	state.UpdatedAt = now
	state.PrevReceiptHash = receipt.Hash
	if err := r.store.Put(state); err != nil {
		return nil, fmt.Errorf("persist state: %w", err)
	}
	return receipt, nil
}

// IsKnownChannel reports whether ch is one of the four declared channels.
func IsKnownChannel(ch contracts.PackChannel) bool {
	switch ch {
	case contracts.PackChannelCore, contracts.PackChannelCommunity,
		contracts.PackChannelTeams, contracts.PackChannelEnterprise:
		return true
	default:
		return false
	}
}

// IsInstallableByOSS reports whether ch is within the OSS install boundary
// and, if not, returns a short human-readable reason suitable for
// IneligibleReasons.
func IsInstallableByOSS(ch contracts.PackChannel) (bool, string) {
	switch ch {
	case contracts.PackChannelCore, contracts.PackChannelCommunity:
		return true, ""
	case contracts.PackChannelTeams:
		return false, "channel teams requires the commercial control plane"
	case contracts.PackChannelEnterprise:
		return false, "channel enterprise requires the commercial control plane"
	default:
		return false, fmt.Sprintf("unknown channel %q", string(ch))
	}
}

// buildPlan is the deterministic plan builder used by Plan and Install.
func buildPlan(packID string, manifest contracts.PackManifestV2, state *State, action string, opts Options) contracts.PackInstallPlan {
	reasons := make([]string, 0)
	if ok, reason := IsInstallableByOSS(manifest.Channel); !ok {
		reasons = append(reasons, reason)
	}

	missingSecrets := make([]string, 0)
	if action != ActionRollback && action != ActionUninstall {
		for _, secret := range manifest.Secrets {
			if secret.Required && strings.TrimSpace(opts.Secrets[secret.Name]) == "" {
				missingSecrets = append(missingSecrets, secret.Name)
			}
		}
	}

	currentVersion := ""
	requiresUpgrade := false
	if state != nil {
		currentVersion = state.Version
		requiresUpgrade = state.Version != "" && state.Version != manifest.Version
	}

	return contracts.PackInstallPlan{
		PackID:            packID,
		Version:           manifest.Version,
		Action:            action,
		DryRun:            opts.DryRun,
		Eligible:          len(reasons) == 0 && len(missingSecrets) == 0,
		RequiresUpgrade:   requiresUpgrade,
		MinimumEdition:    manifest.MinimumEdition,
		CurrentVersion:    currentVersion,
		Steps:             installPlanSteps(action),
		IneligibleReasons: reasons,
		MissingSecrets:    missingSecrets,
	}
}

func installPlanSteps(action string) []string {
	switch action {
	case ActionRollback:
		return []string{
			"resolve installed pack",
			"verify previous receipt chain",
			"dry-run rollback",
			"apply rollback",
			"smoke-test",
			"activate",
			"receipt",
		}
	case ActionUninstall:
		return []string{
			"resolve installed pack",
			"dry-run removal",
			"deactivate",
			"receipt",
		}
	default:
		return []string{
			"resolve",
			"verify",
			"validate secrets",
			"dry-run",
			"apply",
			"smoke-test",
			"activate",
			"receipt",
		}
	}
}
