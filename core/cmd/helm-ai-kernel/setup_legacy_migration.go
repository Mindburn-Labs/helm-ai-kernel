package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const setupLegacyMigrationTemporaryPrefix = ".helm-setup-migrate-"

var (
	renameLegacyCodexProjectMigration     = os.Rename
	syncLegacyCodexProjectMigrationParent = syncSetupParentDirectory
	writeLegacyCodexProjectMigrationFile  = writeSetupPrivateFile
	removeLegacyCodexProjectMigrationTree = os.RemoveAll
	afterLegacyRecoveryMigrationPreflight = func() {}
	afterLegacyBindingMigrationPreflight  = func() {}
)

// runSetupMigrateCmd is intentionally explicit: normal setup and runtime
// admission must never silently treat one shared pre-v1 state directory as
// authority for an arbitrary project. Migration validates the exact current
// project before moving only owned state into its namespaced v1 location.
func runSetupMigrateCmd(args []string, stdout, stderr io.Writer) int {
	opts, code := parseSetupInspectArgs("setup migrate", args, stderr, true)
	if code != 0 {
		return code
	}
	if opts.Target != "codex" || opts.Scope != "project" {
		fmt.Fprintln(stderr, "setup migrate: migration is available only for Codex project scope")
		return 2
	}
	if !opts.Yes && !opts.DryRun {
		fmt.Fprintln(stderr, "setup migrate: pass --yes to migrate validated legacy local state, or --dry-run to inspect it")
		return 2
	}
	securedDataDir, err := requireSetupAuthorityDataDir(opts.DataDir)
	if err != nil {
		fmt.Fprintf(stderr, "setup migrate: unsafe Codex project authority state: %v\n", err)
		return 1
	}
	opts.DataDir = securedDataDir
	summary, err := buildSetupSummary(opts)
	if err != nil {
		fmt.Fprintf(stderr, "setup migrate: %v\n", err)
		return 2
	}
	if !opts.DryRun {
		lifecycleLock, lockErr := acquireSetupCodexProjectLifecycleLock(opts.DataDir)
		if lockErr != nil {
			fmt.Fprintf(stderr, "setup migrate: acquire Codex project lifecycle lock: %v\n", lockErr)
			return 1
		}
		defer func() { _ = lifecycleLock.Close() }()
	}
	migration, err := inspectLegacyCodexProjectMigration(opts, summary)
	if err != nil {
		fmt.Fprintf(stderr, "setup migrate: %v\n", err)
		return 1
	}
	if opts.DryRun {
		fmt.Fprintf(stderr, "setup migrate: validated legacy %s state; rerun with --yes to move it into the current project namespace\n", migration.kind)
		printSetupSummary(stdout, summary, opts.JSON)
		return 0
	}
	applyResult, err := applyLegacyCodexProjectMigration(opts, summary, migration)
	if err != nil {
		fmt.Fprintf(stderr, "setup migrate: %v\n", err)
		return 1
	}
	if applyResult.cleanupWarning != "" {
		fmt.Fprintf(stderr, "setup migrate: migration completed, but %s\n", applyResult.cleanupWarning)
	}
	refreshSetupConfiguration(opts, &summary)
	if migration.kind == "recovery" {
		summary.RecoveryRequired = true
	}
	printSetupSummary(stdout, summary, opts.JSON)
	return 0
}

type legacyCodexProjectMigration struct {
	kind        string
	recovery    *legacyCodexProjectRecoveryMigration
	bindingPlan *legacyCodexProjectBindingMigrationPlan
}

type legacyCodexProjectMigrationApplyResult struct {
	cleanupWarning string
}

type legacyCodexProjectRecoveryMigration struct {
	journal *setupRecoveryJournal
}

type legacyCodexProjectMigrationFile struct {
	name       string
	sourcePath string
	data       []byte
}

type legacyCodexProjectBindingMigrationPlan struct {
	dataDir             string
	binding             *setupCodexProjectBinding
	bindingData         []byte
	bindingSourcePath   string
	artifacts           []legacyCodexProjectMigrationFile
	paths               setupCodexProjectPaths
	destinationComplete bool
}

func (plan legacyCodexProjectBindingMigrationPlan) sourceFiles() []legacyCodexProjectMigrationFile {
	files := make([]legacyCodexProjectMigrationFile, 0, len(plan.artifacts)+1)
	files = append(files, legacyCodexProjectMigrationFile{
		name:       setupCodexProjectBindingFile,
		sourcePath: plan.bindingSourcePath,
		data:       plan.bindingData,
	})
	files = append(files, plan.artifacts...)
	return files
}

func inspectLegacyCodexProjectMigration(opts setupOptions, summary setupSummary) (legacyCodexProjectMigration, error) {
	legacyRoot := legacySetupRecoveryRoot(opts.DataDir)
	legacyInfo, err := os.Lstat(legacyRoot)
	if err == nil {
		if legacyInfo.Mode()&os.ModeSymlink != 0 || !legacyInfo.IsDir() {
			return legacyCodexProjectMigration{}, fmt.Errorf("legacy unscoped recovery state is not a real directory")
		}
		recovery, err := inspectLegacyCodexProjectRecoveryMigration(opts, summary)
		if err != nil {
			return legacyCodexProjectMigration{}, err
		}
		return legacyCodexProjectMigration{kind: "recovery", recovery: recovery}, nil
	}
	if !os.IsNotExist(err) {
		return legacyCodexProjectMigration{}, fmt.Errorf("inspect legacy recovery state: %w", err)
	}

	plan, err := inspectLegacyCodexProjectBindingMigration(opts, summary)
	if err != nil {
		return legacyCodexProjectMigration{}, err
	}
	return legacyCodexProjectMigration{kind: "binding", bindingPlan: plan}, nil
}

func inspectLegacyCodexProjectRecoveryMigration(opts setupOptions, summary setupSummary) (*legacyCodexProjectRecoveryMigration, error) {
	legacyRoot := legacySetupRecoveryRoot(opts.DataDir)
	if _, err := requireSetupAuthoritySubdirectory(opts.DataDir, setupRecoveryDirectory); err != nil {
		return nil, fmt.Errorf("inspect legacy recovery authority state: %w", err)
	}
	stageExists, nonTemporaryEntries, err := inspectLegacySetupRecoveryDirectory(legacyRoot)
	if err != nil {
		return nil, fmt.Errorf("inspect legacy recovery contents: %w", err)
	}
	journal, err := readSetupRecoveryJournalAtPath(filepath.Join(legacyRoot, setupRecoveryJournalFile))
	if err != nil {
		return nil, fmt.Errorf("read legacy recovery journal: %w", err)
	}
	preparing, err := readSetupRecoveryMarkerAtPath(filepath.Join(legacyRoot, setupRecoveryPreparingFile), setupRecoveryPreparingFile)
	if err != nil {
		return nil, fmt.Errorf("read legacy recovery preparing marker: %w", err)
	}
	committed, err := readSetupRecoveryMarkerAtPath(filepath.Join(legacyRoot, setupRecoveryCommittedFile), setupRecoveryCommittedFile)
	if err != nil {
		return nil, fmt.Errorf("read legacy recovery committed marker: %w", err)
	}
	if journal != nil {
		if _, err := validateCodexProjectRecoveryJournal(opts, summary, journal); err != nil {
			return nil, fmt.Errorf("validate legacy recovery journal: %w", err)
		}
		if !stageExists {
			return nil, fmt.Errorf("prepared legacy recovery journal has no staging directory")
		}
	} else if committed != nil {
		// A marker-only legacy residue cannot prove a v1 binding before migration.
		// Do not relocate it and then discover an unresumable state after writes.
		return nil, fmt.Errorf("legacy committed recovery marker has no resumable journal")
	} else if preparing == nil && !stageExists && nonTemporaryEntries != 0 {
		return nil, fmt.Errorf("unclassifiable legacy recovery state")
	}
	if err := requireLegacyRecoveryDestinationAbsent(opts.DataDir); err != nil {
		return nil, err
	}
	return &legacyCodexProjectRecoveryMigration{journal: journal}, nil
}

func inspectLegacySetupRecoveryDirectory(root string) (stageExists bool, nonTemporaryEntries int, err error) {
	if err := requireSetupAuthorityDirectory(root); err != nil {
		return false, 0, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return false, 0, err
	}
	known := map[string]bool{
		setupRecoveryJournalFile:   true,
		setupRecoveryStagingDir:    true,
		setupRecoveryPreparingFile: true,
		setupRecoveryCommittedFile: true,
	}
	for _, entry := range entries {
		entryInfo, err := entry.Info()
		if err != nil {
			return false, 0, err
		}
		entryPath := filepath.Join(root, entry.Name())
		if isSetupRecoveryTemporaryName(entry.Name()) {
			if err := validateSetupRecoveryTemporaryEntry(entryPath, entryInfo); err != nil {
				return false, 0, err
			}
			continue
		}
		if !known[entry.Name()] {
			return false, 0, fmt.Errorf("unexpected setup recovery entry %q", entry.Name())
		}
		nonTemporaryEntries++
		if entryInfo.Mode()&os.ModeSymlink != 0 {
			return false, 0, fmt.Errorf("refusing setup recovery through symlinked entry %q", entry.Name())
		}
		if entry.Name() == setupRecoveryStagingDir {
			if !entryInfo.IsDir() {
				return false, 0, fmt.Errorf("setup recovery staging entry is not a directory")
			}
			if err := requireSetupAuthorityDirectory(entryPath); err != nil {
				return false, 0, err
			}
		} else if !entryInfo.Mode().IsRegular() {
			return false, 0, fmt.Errorf("setup recovery entry %q is not a regular file", entry.Name())
		}
	}
	stageExists, err = inspectLegacySetupRecoveryStageDirectory(filepath.Join(root, setupRecoveryStagingDir))
	return stageExists, nonTemporaryEntries, err
}

func inspectLegacySetupRecoveryStageDirectory(stageDir string) (bool, error) {
	info, err := os.Lstat(stageDir)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, fmt.Errorf("invalid setup recovery staging directory %s", stageDir)
	}
	if err := requireSetupAuthorityDirectory(stageDir); err != nil {
		return false, err
	}
	entries, err := os.ReadDir(stageDir)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		entryInfo, err := entry.Info()
		if err != nil {
			return false, err
		}
		entryPath := filepath.Join(stageDir, entry.Name())
		if isSetupRecoveryTemporaryName(entry.Name()) {
			if err := validateSetupRecoveryTemporaryEntry(entryPath, entryInfo); err != nil {
				return false, err
			}
			continue
		}
		if !setupRecoveryAllowedStageFile(entry.Name()) {
			return false, fmt.Errorf("unexpected setup recovery staged entry %q", entry.Name())
		}
		if entryInfo.Mode()&os.ModeSymlink != 0 || !entryInfo.Mode().IsRegular() {
			return false, fmt.Errorf("invalid setup recovery staged entry %q", entry.Name())
		}
	}
	return true, nil
}

func inspectLegacyCodexProjectBindingMigration(opts setupOptions, summary setupSummary) (*legacyCodexProjectBindingMigrationPlan, error) {
	if _, err := requireSetupAuthoritySubdirectory(opts.DataDir, "native-client"); err != nil {
		return nil, fmt.Errorf("inspect legacy binding authority state: %w", err)
	}
	legacyBindingPath := legacyCodexProjectBindingPath(opts.DataDir)
	legacyBindingState, err := readSetupExistingPrivateFile(legacyBindingPath)
	if err != nil {
		return nil, fmt.Errorf("inspect legacy Codex binding: %w", err)
	}
	if !legacyBindingState.Exists {
		return nil, fmt.Errorf("no legacy unscoped Codex recovery or install binding exists")
	}
	var binding setupCodexProjectBinding
	if err := decodeCanonicalSetupJSON(legacyBindingState.Data, &binding); err != nil {
		return nil, fmt.Errorf("read legacy Codex binding: %w", err)
	}
	if err := validateSetupCodexProjectBinding(&binding); err != nil {
		return nil, fmt.Errorf("read legacy Codex binding: %w", err)
	}
	if err := validateLegacyCodexProjectBindingProof(opts, summary, &binding); err != nil {
		return nil, err
	}
	paths, err := newSetupCodexProjectPaths(opts)
	if err != nil {
		return nil, err
	}
	artifacts, err := inspectLegacyCodexProjectArtifacts(opts.DataDir, paths)
	if err != nil {
		return nil, err
	}
	plan := &legacyCodexProjectBindingMigrationPlan{
		dataDir:           opts.DataDir,
		binding:           &binding,
		bindingData:       append([]byte(nil), legacyBindingState.Data...),
		bindingSourcePath: legacyBindingPath,
		artifacts:         artifacts,
		paths:             paths,
	}
	if err := inspectLegacyCodexProjectBindingDestination(plan); err != nil {
		return nil, err
	}
	return plan, nil
}

func validateLegacyCodexProjectBindingProof(opts setupOptions, summary setupSummary, binding *setupCodexProjectBinding) error {
	proof, err := validateCodexProjectInstallProof(opts, binding)
	if err != nil {
		return fmt.Errorf("validate legacy Codex install proof: %w", err)
	}
	clientState, err := readSetupFileState(summary.ClientConfigPath)
	if err != nil {
		return err
	}
	hookState, err := readSetupFileState(summary.HookConfigPath)
	if err != nil {
		return err
	}
	if _, err := validateCodexProjectInstallProofForCurrentConfig(opts, proof, clientState, hookState); err != nil {
		return fmt.Errorf("legacy Codex install proof does not match current config: %w", err)
	}
	currentBinary, err := inspectSetupKernelBinary(summary.BinaryPath)
	if err != nil {
		return err
	}
	if proof.Binary.Path != currentBinary.Path || proof.Binary.ContentHash != currentBinary.ContentHash {
		return fmt.Errorf("legacy Codex install proof is pinned to a different running Kernel binary; reinstall with this binary before migration")
	}
	return nil
}

func inspectLegacyCodexProjectArtifacts(dataDir string, paths setupCodexProjectPaths) ([]legacyCodexProjectMigrationFile, error) {
	legacyDir := legacyCodexProjectArtifactsDir(dataDir)
	info, err := os.Lstat(legacyDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("legacy autoconfigure state is not a real directory")
	}
	if _, err := requireSetupAuthoritySubdirectory(dataDir, "autoconfigure"); err != nil {
		return nil, fmt.Errorf("inspect legacy autoconfigure authority state: %w", err)
	}
	entries, err := os.ReadDir(legacyDir)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{
		"inventory.json":           true,
		"policy.draft.json":        true,
		"mcp_quarantine_plan.json": true,
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] {
			return nil, fmt.Errorf("legacy autoconfigure state contains unsupported entry %q", entry.Name())
		}
	}
	artifacts := make([]legacyCodexProjectMigrationFile, 0, len(allowed))
	for _, filename := range []string{"inventory.json", "policy.draft.json", "mcp_quarantine_plan.json"} {
		sourcePath := filepath.Join(legacyDir, filename)
		state, err := readSetupExistingPrivateFile(sourcePath)
		if err != nil {
			return nil, fmt.Errorf("read legacy %s: %w", filename, err)
		}
		if !state.Exists {
			continue
		}
		artifacts = append(artifacts, legacyCodexProjectMigrationFile{
			name:       filename,
			sourcePath: sourcePath,
			data:       append([]byte(nil), state.Data...),
		})
	}
	return artifacts, nil
}

func inspectLegacyCodexProjectBindingDestination(plan *legacyCodexProjectBindingMigrationPlan) error {
	stateExists, err := inspectCodexProjectStateAuthority(plan.dataDir)
	if err != nil {
		return fmt.Errorf("inspect project migration destination authority: %w", err)
	}
	if !stateExists {
		plan.destinationComplete = false
		return nil
	}
	bindingState, err := readSetupExistingPrivateFile(plan.paths.BindingPath)
	if err != nil {
		return fmt.Errorf("read current project binding: %w", err)
	}
	if !bindingState.Exists || !bytes.Equal(bindingState.Data, plan.bindingData) {
		return fmt.Errorf("current project binding differs from the validated legacy binding")
	}
	if len(plan.artifacts) == 0 {
		plan.destinationComplete = true
		return nil
	}
	info, err := os.Lstat(plan.paths.ArtifactsDir)
	if os.IsNotExist(err) {
		return fmt.Errorf("current project is missing validated legacy autoconfigure artifacts")
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("current project autoconfigure state is not a real directory")
	}
	relativeArtifactsDir, err := filepath.Rel(plan.dataDir, plan.paths.ArtifactsDir)
	if err != nil || filepath.IsAbs(relativeArtifactsDir) || relativeArtifactsDir == ".." {
		return fmt.Errorf("resolve current project autoconfigure authority path")
	}
	if _, err := requireSetupAuthoritySubdirectory(plan.dataDir, relativeArtifactsDir); err != nil {
		return fmt.Errorf("inspect current project autoconfigure authority state: %w", err)
	}
	for _, artifact := range plan.artifacts {
		state, err := readSetupExistingPrivateFile(filepath.Join(plan.paths.ArtifactsDir, artifact.name))
		if err != nil {
			return err
		}
		if !state.Exists || !bytes.Equal(state.Data, artifact.data) {
			return fmt.Errorf("current project %s differs from the validated legacy artifact", artifact.name)
		}
	}
	plan.destinationComplete = true
	return nil
}

func validateLegacyCodexProjectBindingMigrationPlan(opts setupOptions, summary setupSummary, plan *legacyCodexProjectBindingMigrationPlan) error {
	if plan == nil || plan.binding == nil || plan.dataDir != opts.DataDir {
		return fmt.Errorf("invalid legacy Codex binding migration plan")
	}
	if err := validateLegacyCodexProjectBindingProof(opts, summary, plan.binding); err != nil {
		return err
	}
	if _, err := requireSetupAuthoritySubdirectory(opts.DataDir, "native-client"); err != nil {
		return fmt.Errorf("revalidate legacy binding authority state: %w", err)
	}
	if len(plan.artifacts) > 0 {
		if _, err := requireSetupAuthoritySubdirectory(opts.DataDir, "autoconfigure"); err != nil {
			return fmt.Errorf("revalidate legacy autoconfigure authority state: %w", err)
		}
	}
	for _, source := range plan.sourceFiles() {
		state, err := readSetupExistingPrivateFile(source.sourcePath)
		if err != nil {
			return fmt.Errorf("read legacy %s before migration: %w", source.name, err)
		}
		if !state.Exists || !bytes.Equal(state.Data, source.data) {
			return fmt.Errorf("legacy %s changed during migration", source.name)
		}
	}
	wasComplete := plan.destinationComplete
	if err := inspectLegacyCodexProjectBindingDestination(plan); err != nil {
		return err
	}
	if plan.destinationComplete != wasComplete {
		return fmt.Errorf("current project migration destination changed during preflight")
	}
	return nil
}

func applyLegacyCodexProjectMigration(opts setupOptions, summary setupSummary, migration legacyCodexProjectMigration) (legacyCodexProjectMigrationApplyResult, error) {
	switch migration.kind {
	case "recovery":
		if migration.recovery == nil {
			return legacyCodexProjectMigrationApplyResult{}, fmt.Errorf("legacy recovery migration plan is required")
		}
		return legacyCodexProjectMigrationApplyResult{}, migrateLegacyCodexProjectRecovery(opts, summary, migration.recovery.journal)
	case "binding":
		return migrateLegacyCodexProjectBinding(opts, summary, migration.bindingPlan)
	default:
		return legacyCodexProjectMigrationApplyResult{}, fmt.Errorf("unsupported legacy migration kind %q", migration.kind)
	}
}

func requireLegacyRecoveryDestinationAbsent(dataDir string) error {
	if _, err := inspectCodexProjectStateAuthority(dataDir); err != nil {
		return fmt.Errorf("inspect current project recovery authority state: %w", err)
	}
	currentRoot := setupRecoveryRoot(dataDir)
	if _, err := os.Lstat(currentRoot); err == nil {
		return fmt.Errorf("current project recovery state already exists; refusing to overwrite it")
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func migrateLegacyCodexProjectRecovery(opts setupOptions, summary setupSummary, journal *setupRecoveryJournal) error {
	// Repeat the complete read-only preflight while the caller holds the
	// lifecycle lock. This closes the window between --dry-run/initial inspect
	// and the no-overwrite rename below.
	preflight, err := inspectLegacyCodexProjectRecoveryMigration(opts, summary)
	if err != nil {
		return err
	}
	afterLegacyRecoveryMigrationPreflight()
	preflight, err = inspectLegacyCodexProjectRecoveryMigration(opts, summary)
	if err != nil {
		return err
	}
	if (preflight.journal == nil) != (journal == nil) {
		return fmt.Errorf("legacy recovery journal presence changed during migration")
	}
	if preflight.journal != nil {
		before, err := setupRecoveryJournalHash(journal)
		if err != nil {
			return err
		}
		after, err := setupRecoveryJournalHash(preflight.journal)
		if err != nil {
			return err
		}
		if before != after {
			return fmt.Errorf("legacy recovery journal changed during migration")
		}
	}
	if err := requireLegacyRecoveryDestinationAbsent(opts.DataDir); err != nil {
		return err
	}
	if err := ensureCodexProjectStateAuthority(opts.DataDir); err != nil {
		return fmt.Errorf("create project migration destination: %w", err)
	}
	if err := requireLegacyRecoveryDestinationAbsent(opts.DataDir); err != nil {
		return err
	}
	legacyRoot := legacySetupRecoveryRoot(opts.DataDir)
	currentRoot := setupRecoveryRoot(opts.DataDir)
	if err := renameLegacyCodexProjectMigration(legacyRoot, currentRoot); err != nil {
		return fmt.Errorf("move legacy recovery state into project namespace: %w", err)
	}
	if err := syncLegacyCodexProjectMigrationParent(currentRoot); err != nil {
		rollbackErr := rollbackLegacyCodexProjectRecoveryMove(currentRoot, legacyRoot)
		if rollbackErr != nil {
			return errors.Join(fmt.Errorf("sync migrated recovery state: %w", err), fmt.Errorf("rollback migrated recovery state: %w", rollbackErr))
		}
		return fmt.Errorf("sync migrated recovery state: %w", err)
	}
	inspection, inspectErr := inspectSetupRecovery(opts.DataDir)
	if inspectErr == nil && inspection.State == setupRecoveryStateAbsent {
		inspectErr = fmt.Errorf("migrated recovery state disappeared during validation")
	}
	if inspectErr != nil {
		rollbackErr := rollbackLegacyCodexProjectRecoveryMove(currentRoot, legacyRoot)
		if rollbackErr != nil {
			return errors.Join(fmt.Errorf("validate migrated recovery state: %w", inspectErr), fmt.Errorf("rollback migrated recovery state: %w", rollbackErr))
		}
		return fmt.Errorf("validate migrated recovery state: %w", inspectErr)
	}
	return nil
}

func rollbackLegacyCodexProjectRecoveryMove(currentRoot, legacyRoot string) error {
	if err := renameLegacyCodexProjectMigration(currentRoot, legacyRoot); err != nil {
		return err
	}
	return syncLegacyCodexProjectMigrationParent(legacyRoot)
}

func migrateLegacyCodexProjectBinding(opts setupOptions, summary setupSummary, plan *legacyCodexProjectBindingMigrationPlan) (legacyCodexProjectMigrationApplyResult, error) {
	afterLegacyBindingMigrationPreflight()
	if err := validateLegacyCodexProjectBindingMigrationPlan(opts, summary, plan); err != nil {
		return legacyCodexProjectMigrationApplyResult{}, err
	}
	published, err := publishLegacyCodexProjectBindingDestination(plan)
	if err != nil {
		return legacyCodexProjectMigrationApplyResult{}, err
	}
	sourceMove, err := moveLegacyCodexProjectMigrationSources(plan)
	if err != nil {
		// A failed rollback leaves a sealed source backup behind. The v1
		// destination contains the complete, durably published state, so removing
		// it would turn a recoverable cleanup condition into data loss.
		if sourceMove.preservePublishedDestination {
			return legacyCodexProjectMigrationApplyResult{cleanupWarning: sourceMove.cleanupWarning}, nil
		}
		if !published {
			return legacyCodexProjectMigrationApplyResult{}, err
		}
		rollbackErr := rollbackPublishedLegacyCodexProjectBindingDestination(plan)
		if rollbackErr != nil {
			return legacyCodexProjectMigrationApplyResult{}, errors.Join(err, fmt.Errorf("rollback project-scoped binding destination: %w", rollbackErr))
		}
		return legacyCodexProjectMigrationApplyResult{}, err
	}
	return legacyCodexProjectMigrationApplyResult{cleanupWarning: sourceMove.cleanupWarning}, nil
}

func publishLegacyCodexProjectBindingDestination(plan *legacyCodexProjectBindingMigrationPlan) (bool, error) {
	if plan.destinationComplete {
		return false, nil
	}
	stateExists, err := inspectCodexProjectStateAuthority(plan.dataDir)
	if err != nil {
		return false, err
	}
	if stateExists {
		return false, fmt.Errorf("current project migration destination appeared during publication")
	}
	parentRelativePath := filepath.Join("native-client", "codex-projects", setupCodexProjectStateLayout)
	if err := ensureSetupAuthoritySubdirectory(plan.dataDir, parentRelativePath); err != nil {
		return false, fmt.Errorf("create project migration parent: %w", err)
	}
	stateParent := filepath.Dir(plan.paths.StateRoot)
	stagingRoot, err := os.MkdirTemp(stateParent, setupLegacyMigrationTemporaryPrefix)
	if err != nil {
		return false, err
	}
	cleanupStaging := true
	defer func() {
		if cleanupStaging {
			_ = removeLegacyCodexProjectMigrationTemporaryDirectory(stagingRoot)
		}
	}()
	if err := os.Chmod(stagingRoot, 0o700); err != nil {
		return false, err
	}
	if err := requireSetupAuthorityDirectory(stagingRoot); err != nil {
		return false, err
	}
	if err := writeLegacyCodexProjectMigrationFile(filepath.Join(stagingRoot, setupCodexProjectBindingFile), plan.bindingData); err != nil {
		return false, fmt.Errorf("stage project-scoped Codex binding: %w", err)
	}
	if len(plan.artifacts) > 0 {
		artifactsDir := filepath.Join(stagingRoot, "autoconfigure")
		if err := os.Mkdir(artifactsDir, 0o700); err != nil {
			return false, err
		}
		if err := requireSetupAuthorityDirectory(artifactsDir); err != nil {
			return false, err
		}
		for _, artifact := range plan.artifacts {
			if err := writeLegacyCodexProjectMigrationFile(filepath.Join(artifactsDir, artifact.name), artifact.data); err != nil {
				return false, fmt.Errorf("stage project-scoped %s: %w", artifact.name, err)
			}
		}
	}
	stagedPlan := *plan
	stagedPlan.paths.StateRoot = stagingRoot
	stagedPlan.paths.BindingPath = filepath.Join(stagingRoot, setupCodexProjectBindingFile)
	stagedPlan.paths.ArtifactsDir = filepath.Join(stagingRoot, "autoconfigure")
	if err := validatePublishedLegacyCodexProjectBindingDestination(&stagedPlan); err != nil {
		return false, fmt.Errorf("verify staged project migration state: %w", err)
	}
	stateExists, err = inspectCodexProjectStateAuthority(plan.dataDir)
	if err != nil {
		return false, err
	}
	if stateExists {
		return false, fmt.Errorf("current project migration destination appeared during publication")
	}
	if err := renameLegacyCodexProjectMigration(stagingRoot, plan.paths.StateRoot); err != nil {
		return false, fmt.Errorf("publish project-scoped migration state: %w", err)
	}
	cleanupStaging = false
	if err := syncLegacyCodexProjectMigrationParent(plan.paths.StateRoot); err != nil {
		rollbackErr := renameLegacyCodexProjectMigration(plan.paths.StateRoot, stagingRoot)
		if rollbackErr == nil {
			rollbackErr = syncLegacyCodexProjectMigrationParent(stagingRoot)
		}
		if rollbackErr != nil {
			return false, errors.Join(fmt.Errorf("sync published project migration state: %w", err), fmt.Errorf("rollback published project migration state: %w", rollbackErr))
		}
		cleanupStaging = true
		return false, fmt.Errorf("sync published project migration state: %w", err)
	}
	return true, nil
}

func validatePublishedLegacyCodexProjectBindingDestination(plan *legacyCodexProjectBindingMigrationPlan) error {
	if err := requireSetupAuthorityDirectory(plan.paths.StateRoot); err != nil {
		return err
	}
	entries, err := os.ReadDir(plan.paths.StateRoot)
	if err != nil {
		return err
	}
	allowedRootEntries := map[string]bool{setupCodexProjectBindingFile: true}
	if len(plan.artifacts) > 0 {
		allowedRootEntries["autoconfigure"] = true
	}
	for _, entry := range entries {
		if !allowedRootEntries[entry.Name()] {
			return fmt.Errorf("unexpected project migration entry %q", entry.Name())
		}
	}
	binding, err := readSetupExistingPrivateFile(plan.paths.BindingPath)
	if err != nil {
		return err
	}
	if !binding.Exists || !bytes.Equal(binding.Data, plan.bindingData) {
		return fmt.Errorf("project-scoped binding does not match staged legacy binding")
	}
	if len(plan.artifacts) == 0 {
		return nil
	}
	if err := requireSetupAuthorityDirectory(plan.paths.ArtifactsDir); err != nil {
		return err
	}
	expected := make(map[string][]byte, len(plan.artifacts))
	for _, artifact := range plan.artifacts {
		expected[artifact.name] = artifact.data
	}
	artifactEntries, err := os.ReadDir(plan.paths.ArtifactsDir)
	if err != nil {
		return err
	}
	for _, entry := range artifactEntries {
		if _, ok := expected[entry.Name()]; !ok {
			return fmt.Errorf("unexpected project migration artifact %q", entry.Name())
		}
	}
	for name, data := range expected {
		state, err := readSetupExistingPrivateFile(filepath.Join(plan.paths.ArtifactsDir, name))
		if err != nil {
			return err
		}
		if !state.Exists || !bytes.Equal(state.Data, data) {
			return fmt.Errorf("project migration artifact %s does not match legacy state", name)
		}
	}
	return nil
}

func rollbackPublishedLegacyCodexProjectBindingDestination(plan *legacyCodexProjectBindingMigrationPlan) error {
	if err := validatePublishedLegacyCodexProjectBindingDestination(plan); err != nil {
		return err
	}
	if err := os.RemoveAll(plan.paths.StateRoot); err != nil {
		return err
	}
	return syncLegacyCodexProjectMigrationParent(plan.paths.StateRoot)
}

type legacyCodexProjectMigrationSourceMoveResult struct {
	cleanupWarning               string
	preservePublishedDestination bool
}

func moveLegacyCodexProjectMigrationSources(plan *legacyCodexProjectBindingMigrationPlan) (legacyCodexProjectMigrationSourceMoveResult, error) {
	temporaryRoot, err := os.MkdirTemp(plan.dataDir, setupLegacyMigrationTemporaryPrefix)
	if err != nil {
		return legacyCodexProjectMigrationSourceMoveResult{}, err
	}
	cleanupTemporaryRoot := true
	defer func() {
		if cleanupTemporaryRoot {
			_ = removeLegacyCodexProjectMigrationTemporaryDirectory(temporaryRoot)
		}
	}()
	if err := os.Chmod(temporaryRoot, 0o700); err != nil {
		return legacyCodexProjectMigrationSourceMoveResult{}, err
	}
	if err := requireSetupAuthorityDirectory(temporaryRoot); err != nil {
		return legacyCodexProjectMigrationSourceMoveResult{}, err
	}
	type movedSource struct {
		source legacyCodexProjectMigrationFile
		backup string
	}
	moved := make([]movedSource, 0, len(plan.sourceFiles()))
	rollback := func() error {
		var rollbackErrors []error
		for index := len(moved) - 1; index >= 0; index-- {
			item := moved[index]
			backup, err := readSetupExistingPrivateFile(item.backup)
			if err != nil {
				rollbackErrors = append(rollbackErrors, err)
				continue
			}
			if !backup.Exists || !bytes.Equal(backup.Data, item.source.data) {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("migration backup for %s changed during rollback", item.source.name))
				continue
			}
			current, err := readSetupFileState(item.source.sourcePath)
			if err != nil {
				rollbackErrors = append(rollbackErrors, err)
				continue
			}
			if current.Exists {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("legacy %s reappeared during rollback", item.source.name))
				continue
			}
			if err := renameLegacyCodexProjectMigration(item.backup, item.source.sourcePath); err != nil {
				rollbackErrors = append(rollbackErrors, err)
				continue
			}
			if err := syncLegacyCodexProjectMigrationParent(item.source.sourcePath); err != nil {
				rollbackErrors = append(rollbackErrors, err)
			}
		}
		return errors.Join(rollbackErrors...)
	}
	rollbackOrPreservePublishedDestination := func(cause error) (legacyCodexProjectMigrationSourceMoveResult, error) {
		rollbackErr := rollback()
		if rollbackErr == nil {
			return legacyCodexProjectMigrationSourceMoveResult{}, cause
		}
		// The published v1 namespace is already complete and durable. Retain it
		// and the private transaction directory rather than deleting both the
		// authoritative copy and a source backup whose rollback could not finish.
		cleanupTemporaryRoot = false
		return legacyCodexProjectMigrationSourceMoveResult{
			cleanupWarning:               fmt.Sprintf("legacy source retirement could not be completed or fully rolled back after v1 publication (%v; %v); retained sealed source state at %s and the v1 project state remains active", cause, rollbackErr, temporaryRoot),
			preservePublishedDestination: true,
		}, errors.Join(cause, fmt.Errorf("rollback legacy source moves: %w", rollbackErr))
	}
	for index, source := range plan.sourceFiles() {
		state, err := readSetupExistingPrivateFile(source.sourcePath)
		if err != nil {
			return rollbackOrPreservePublishedDestination(fmt.Errorf("read legacy %s before move: %w", source.name, err))
		}
		if !state.Exists || !bytes.Equal(state.Data, source.data) {
			return rollbackOrPreservePublishedDestination(fmt.Errorf("legacy %s changed during migration", source.name))
		}
		backupPath := filepath.Join(temporaryRoot, fmt.Sprintf("%02d-%s", index, source.name))
		if err := renameLegacyCodexProjectMigration(source.sourcePath, backupPath); err != nil {
			return rollbackOrPreservePublishedDestination(fmt.Errorf("move legacy %s into migration transaction: %w", source.name, err))
		}
		moved = append(moved, movedSource{source: source, backup: backupPath})
		if err := syncLegacyCodexProjectMigrationParent(source.sourcePath); err != nil {
			return rollbackOrPreservePublishedDestination(fmt.Errorf("sync migrated legacy %s: %w", source.name, err))
		}
	}
	// Every source now lives in a secure retired-source directory and the v1
	// destination was already durably published. That is the transaction commit
	// point. Cleanup is best effort: returning an error here would make the
	// caller roll back the only active state after the legacy names disappeared.
	if err := removeLegacyCodexProjectMigrationTree(temporaryRoot); err != nil {
		cleanupTemporaryRoot = false
		return legacyCodexProjectMigrationSourceMoveResult{cleanupWarning: fmt.Sprintf("a sealed retired-source cleanup remains at %s; it is not active project authority", temporaryRoot)}, nil
	}
	cleanupTemporaryRoot = false
	if err := syncLegacyCodexProjectMigrationParent(temporaryRoot); err != nil {
		return legacyCodexProjectMigrationSourceMoveResult{cleanupWarning: fmt.Sprintf("retired-source cleanup completed but parent-directory durability could not be confirmed for %s", filepath.Dir(temporaryRoot))}, nil
	}
	return legacyCodexProjectMigrationSourceMoveResult{}, nil
}

func removeLegacyCodexProjectMigrationTemporaryDirectory(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || filepath.Base(path) == "" || len(filepath.Base(path)) <= len(setupLegacyMigrationTemporaryPrefix) || filepath.Base(path)[:len(setupLegacyMigrationTemporaryPrefix)] != setupLegacyMigrationTemporaryPrefix {
		return fmt.Errorf("refusing to remove invalid legacy migration temporary directory %s", path)
	}
	if err := removeLegacyCodexProjectMigrationTree(path); err != nil {
		return err
	}
	return syncLegacyCodexProjectMigrationParent(path)
}
