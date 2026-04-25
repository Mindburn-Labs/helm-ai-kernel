// Package install provides the OSS, tenant-free runtime for installing,
// uninstalling, and rolling back HELM add-on packs from the core and
// community channels.
//
// Commercial callers (helm/apps/helm-controlplane/internal/platform)
// layer entitlement, edition gating, and tenant-scoped persistence on
// top of this package. OSS consumers use it directly against a
// MemoryStore (or any other Store implementation) for single-operator
// local workflows.
//
// HTTP routing is deliberately not included — this package exposes the
// Runner API only; callers (CLI, local controlplane, or commercial
// tenant-scoped HTTP handlers) wrap it with their preferred transport.
//
// This package is distinct from core/pkg/packs/antispoof and
// core/pkg/packs/last30days, which implement proof-pack verification
// (a separate concern from installable add-on packs).
package install

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// ErrIneligible signals a pack install plan cannot proceed — required
// secrets are missing, the channel is not installable by the OSS
// runtime, or another precondition fails. The plan on the returned
// InstallResult carries a machine-readable reason list.
var ErrIneligible = errors.New("packs/install: plan is not eligible")

// Action names. These are stable strings; commercial callers rely on
// them when mapping HTTP verbs onto lifecycle transitions.
const (
	ActionInstall   = "install"
	ActionUpgrade   = "upgrade"
	ActionUninstall = "uninstall"
	ActionRollback  = "rollback"
)

// InstallOptions carries per-call parameters. The zero value is safe —
// Action defaults to "install", Now defaults to time.Now().UTC(), and
// InstalledBy defaults to "operator-local".
type InstallOptions struct {
	// Action selects the lifecycle transition; one of ActionInstall,
	// ActionUpgrade, ActionUninstall, ActionRollback. Empty defaults to
	// ActionInstall.
	Action string

	// DryRun produces a plan + verification without mutating state. No
	// receipt is written; the returned State is unchanged from the
	// store.
	DryRun bool

	// Secrets maps declared-secret name to value. Keys absent from this
	// map that are declared Required on the manifest produce a
	// MissingSecrets plan entry.
	Secrets map[string]string

	// InstalledBy records the operator who performed the action.
	// Defaults to "operator-local".
	InstalledBy string

	// Now is injected for deterministic testing. Defaults to
	// time.Now().UTC().
	Now func() time.Time
}

// InstallResult captures the outcome of a lifecycle call.
type InstallResult struct {
	Action        string
	Plan          contracts.PackInstallPlan
	Manifest      contracts.PackManifestV2
	Verification  *VerificationResult
	State         *State
	InstalledPack *contracts.InstalledPack
	Receipt       *Receipt
}

// Runner drives the install lifecycle for a Store.
type Runner struct {
	store Store
}

// NewRunner returns a Runner backed by store. store MUST NOT be nil.
func NewRunner(store Store) *Runner {
	return &Runner{store: store}
}

// Plan produces a dry-run install plan without mutating the store.
// Commercial callers layer additional checks (entitlement, edition
// gating) on top of the returned plan.
func (r *Runner) Plan(ctx context.Context, manifest contracts.PackManifestV2, manifestHash string, opts InstallOptions) (contracts.PackInstallPlan, error) {
	_ = ctx
	action := normalizeAction(opts.Action)
	state, err := r.loadState(manifest.PackID)
	if err != nil {
		return contracts.PackInstallPlan{}, err
	}
	return buildPlan(manifest, manifestHash, state, action, opts, true), nil
}

// Install runs an install, upgrade, uninstall, or rollback depending on
// opts.Action. A DryRun call returns a plan + verification without
// mutating state and without writing a receipt.
//
// If the plan is not Eligible, the returned error wraps ErrIneligible
// and the result still carries the plan so callers can surface missing
// secrets / ineligible reasons to the user.
func (r *Runner) Install(ctx context.Context, manifest contracts.PackManifestV2, manifestHash string, opts InstallOptions) (*InstallResult, error) {
	_ = ctx
	action := normalizeAction(opts.Action)
	now := nowFn(opts.Now)()

	verification, err := Verify(manifest, manifestHash)
	if err != nil {
		return nil, err
	}

	state, err := r.loadState(manifest.PackID)
	if err != nil {
		return nil, err
	}

	plan := buildPlan(manifest, manifestHash, state, action, opts, opts.DryRun)
	result := &InstallResult{
		Action:       action,
		Plan:         plan,
		Manifest:     manifest,
		Verification: verification,
		State:        state,
	}
	if state != nil {
		result.InstalledPack = installedPackFromState(state)
	}

	if !plan.Eligible {
		return result, ErrIneligible
	}

	if opts.DryRun {
		return result, nil
	}

	// Mutate state for the chosen action.
	if state == nil {
		state = &State{PackID: manifest.PackID}
	}
	installedBy := strings.TrimSpace(opts.InstalledBy)
	if installedBy == "" {
		installedBy = "operator-local"
	}
	state.Version = manifest.Version
	state.InstalledBy = installedBy
	state.ManifestHash = manifestHash
	state.LastAction = action
	state.LastError = ""
	state.UpdatedAt = now
	state.VerifiedAt = timePtr(now)

	switch action {
	case ActionRollback:
		state.Status = "rolled_back"
		state.InstalledAt = nil
	case ActionUninstall:
		state.Status = "uninstalled"
		state.InstalledAt = nil
	default: // install, upgrade
		state.Status = "installed"
		state.InstalledAt = timePtr(now)
		state.InstallCount++
	}

	receipt, err := issueReceipt(
		manifest.PackID,
		manifest.Name,
		manifest.Version,
		manifestHash,
		action,
		installedBy,
		now,
		state.ReceiptID,
	)
	if err != nil {
		return nil, err
	}
	state.ReceiptID = receipt.ReceiptID
	state.ReceiptHash = receipt.ContentHash

	if err := r.store.Put(state); err != nil {
		return nil, fmt.Errorf("packs/install: persist state: %w", err)
	}

	result.State = state
	result.InstalledPack = installedPackFromState(state)
	result.Receipt = receipt
	return result, nil
}

// Uninstall is shorthand for Install with Action=ActionUninstall.
func (r *Runner) Uninstall(ctx context.Context, manifest contracts.PackManifestV2, manifestHash string, opts InstallOptions) (*InstallResult, error) {
	opts.Action = ActionUninstall
	return r.Install(ctx, manifest, manifestHash, opts)
}

// Rollback is shorthand for Install with Action=ActionRollback.
func (r *Runner) Rollback(ctx context.Context, manifest contracts.PackManifestV2, manifestHash string, opts InstallOptions) (*InstallResult, error) {
	opts.Action = ActionRollback
	return r.Install(ctx, manifest, manifestHash, opts)
}

// --- Helpers ---

func (r *Runner) loadState(packID string) (*State, error) {
	state, err := r.store.Get(packID)
	if errors.Is(err, ErrStateNotFound) {
		return nil, nil
	}
	return state, err
}

func buildPlan(
	manifest contracts.PackManifestV2,
	manifestHash string,
	state *State,
	action string,
	opts InstallOptions,
	dryRun bool,
) contracts.PackInstallPlan {
	_ = manifestHash // reserved for future plan-integrity fields
	ineligible := make([]string, 0)

	if !IsKnownChannel(manifest.Channel) {
		ineligible = append(ineligible, fmt.Sprintf("unknown channel %q", manifest.Channel))
	} else if !IsInstallableByOSS(manifest.Channel) {
		ineligible = append(ineligible, fmt.Sprintf("channel %q requires commercial entitlement", manifest.Channel))
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
		PackID:            manifest.PackID,
		Version:           manifest.Version,
		Action:            action,
		DryRun:            dryRun,
		Eligible:          len(ineligible) == 0 && len(missingSecrets) == 0,
		RequiresUpgrade:   requiresUpgrade,
		MinimumEdition:    manifest.MinimumEdition,
		CurrentVersion:    currentVersion,
		Steps:             planSteps(action),
		MissingSecrets:    missingSecrets,
		IneligibleReasons: ineligible,
	}
}

func planSteps(action string) []string {
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

func normalizeAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case ActionUpgrade:
		return ActionUpgrade
	case ActionUninstall:
		return ActionUninstall
	case ActionRollback:
		return ActionRollback
	default:
		return ActionInstall
	}
}

func installedPackFromState(state *State) *contracts.InstalledPack {
	if state == nil {
		return nil
	}
	return &contracts.InstalledPack{
		PackID:      state.PackID,
		Version:     state.Version,
		Status:      state.Status,
		InstalledAt: state.InstalledAt,
	}
}

func timePtr(t time.Time) *time.Time {
	return &t
}

func nowFn(custom func() time.Time) func() time.Time {
	if custom != nil {
		return custom
	}
	return func() time.Time { return time.Now().UTC() }
}
