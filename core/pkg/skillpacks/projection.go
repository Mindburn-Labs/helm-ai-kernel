package skillpacks

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const cursorInstallStatusPending = "pending_install"

func Install(pack SkillPack, req InstallRequest) (InstallResult, error) {
	if req.Scope == "" {
		req.Scope = ScopeRepo
	}
	if req.Agent == "" {
		req.Agent = "codex"
	}
	scan, err := Scan(pack)
	if err != nil {
		return InstallResult{}, err
	}
	result := InstallResult{SkillID: pack.Manifest.ID, Verdict: scan.Verdict, Scan: scan}
	if req.Scope != ScopeRepo {
		result.Status = "approval_required"
		result.Verdict = VerdictEscalate
		result.ReasonCode = "ERR_GLOBAL_SKILL_INSTALL_DENIED"
		result.Message = "repo-scoped install is the default; broader scope requires approval receipt"
		return result, nil
	}
	if scan.Verdict != VerdictAllow {
		result.Status = "blocked"
		result.ReasonCode = scan.ReasonCode
		return result, nil
	}
	root := req.RepoRoot
	if root == "" {
		var err error
		root, err = os.Getwd()
		if err != nil {
			return InstallResult{}, err
		}
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return InstallResult{}, err
	}
	root, err = canonicalRepositoryRoot(root)
	if err != nil {
		return InstallResult{}, err
	}
	projections, err := ProjectionPaths(root, pack.Manifest.ID, req.Agent)
	if err != nil {
		return InstallResult{}, err
	}
	if projections[0].Agent == "cursor" {
		req.Agent = "cursor"
		if err := installCursorProjection(root, pack.Manifest, req, projections[0], scan.SkillContentHash, []byte(pack.SkillMD)); err != nil {
			return InstallResult{}, err
		}
	} else {
		for _, projection := range projections {
			if err := os.MkdirAll(filepath.Dir(projection.Path), 0o755); err != nil {
				return InstallResult{}, err
			}
			if err := atomicWrite(projection.Path, []byte(pack.SkillMD)); err != nil {
				return InstallResult{}, err
			}
		}
	}
	installReceipt := NewReceipt("SKILL_INSTALL_RECEIPT", pack.Manifest.ID, VerdictAllow, "", scan.SkillContentHash, pack.Manifest.PolicyRef, projections)
	projectionReceipt := NewReceipt("SKILL_PROJECTION_RECEIPT", pack.Manifest.ID, VerdictAllow, "", scan.SkillContentHash, pack.Manifest.PolicyRef, projections)
	if _, err := WriteReceipt(root, installReceipt); err != nil {
		return InstallResult{}, err
	}
	if _, err := WriteReceipt(root, projectionReceipt); err != nil {
		return InstallResult{}, err
	}
	if err := updateInstallStore(root, pack.Manifest, req, projections, installReceipt.ID, projectionReceipt.ID); err != nil {
		return InstallResult{}, err
	}
	result.Status = "active"
	result.Verdict = VerdictAllow
	result.ProjectionPaths = projections
	result.InstallReceipt = installReceipt
	result.ProjectionReceipt = projectionReceipt
	return result, nil
}

func ProjectionPaths(root, skillID, agent string) ([]Projection, error) {
	projection, err := projectionRelativePath(skillID, agent)
	if err != nil {
		return nil, err
	}
	projection.Path = filepath.Join(root, projection.Path)
	return []Projection{projection}, nil
}

func projectionRelativePath(skillID, agent string) (Projection, error) {
	if !skillIDPattern.MatchString(skillID) {
		return Projection{}, fmt.Errorf("skill id must be namespaced publisher/name: %s", skillID)
	}
	safeParts := strings.Split(skillID, "/")
	switch strings.ToLower(strings.TrimSpace(agent)) {
	case "codex", "generic":
		return Projection{Agent: "codex", Path: filepath.Join(".agents", "skills", safeParts[0], safeParts[1], "SKILL.md")}, nil
	case "claude", "claude-code":
		return Projection{Agent: "claude-code", Path: filepath.Join(".claude", "skills", safeParts[0], safeParts[1], "SKILL.md")}, nil
	case "cursor":
		return Projection{Agent: "cursor", Path: filepath.Join(".cursor", "rules", safeParts[0], safeParts[1]+".md")}, nil
	case "opencode":
		return Projection{Agent: "opencode", Path: filepath.Join(".opencode", "skills", safeParts[0], safeParts[1], "SKILL.md")}, nil
	default:
		return Projection{}, fmt.Errorf("unsupported agent projection: %s", agent)
	}
}

func legacyCursorRelativePath(skillID string) (string, error) {
	if !skillIDPattern.MatchString(skillID) {
		return "", fmt.Errorf("skill id must be namespaced publisher/name: %s", skillID)
	}
	parts := strings.Split(skillID, "/")
	return filepath.Join(".cursor", "rules", parts[0]+"-"+parts[1]+".md"), nil
}

func installCursorProjection(
	root string,
	manifest Manifest,
	req InstallRequest,
	projection Projection,
	nextContentHash string,
	content []byte,
) error {
	managed, err := openManagedRoot(root)
	if err != nil {
		return err
	}
	defer managed.Close()

	canonical, err := projectionRelativePath(manifest.ID, "cursor")
	if err != nil {
		return err
	}
	legacyRel, err := legacyCursorRelativePath(manifest.ID)
	if err != nil {
		return err
	}
	canonicalRel := canonical.Path
	if !sameProjectionPath(root, projection.Path, canonicalRel) || projection.Agent != "cursor" {
		return ErrProjectionPathUnsafe
	}

	store, err := readInstallStore(root)
	if err != nil {
		return err
	}
	index, err := findCursorInstallRecord(store, manifest.ID, req.Scope)
	if err != nil {
		return err
	}
	legacyPresent, legacyHash, err := observeManagedFile(managed, legacyRel, maxProjectionArtifactBytes)
	if err != nil {
		return err
	}
	canonicalPresent, canonicalHash, err := observeManagedFile(managed, canonicalRel, maxProjectionArtifactBytes)
	if err != nil {
		return err
	}

	if index < 0 {
		if legacyPresent || canonicalPresent {
			return ErrUnmanagedProjection
		}
		store.Installs = append(store.Installs, installedSkill{
			SkillID: manifest.ID, Agent: "cursor", Scope: req.Scope, Status: cursorInstallStatusPending,
			ContentHash: nextContentHash, PendingContentHash: nextContentHash,
			ProjectionPaths: []Projection{projection}, UpdatedAt: time.Now().UTC().Format(time.RFC3339), Manifest: manifest,
		})
		index = len(store.Installs) - 1
		if err := writeInstallStore(root, store); err != nil {
			return err
		}
	}

	record := store.Installs[index]
	if err := validateCursorInstallRecordPaths(root, record, legacyRel, canonicalRel); err != nil {
		return err
	}
	if err := ensureCursorPathOwnership(store, index, root, legacyRel, canonicalRel); err != nil {
		return err
	}
	previousHash := record.ContentHash
	legacyExpectedHash := ""
	removeLegacy := false
	if record.Status != "revoked" && record.PendingContentHash != "" && record.PendingContentHash != nextContentHash {
		return ErrProjectionReplayConflict
	}
	switch record.Status {
	case cursorInstallStatusPending:
		if cursorInstallPathState(root, record, legacyRel, canonicalRel) != "canonical" ||
			record.ContentHash != nextContentHash || record.PendingContentHash != nextContentHash ||
			record.InstallReceiptID != "" || record.ProjectionReceiptID != "" ||
			hashCanonical(record.Manifest) != hashCanonical(manifest) || legacyPresent ||
			(canonicalPresent && canonicalHash != nextContentHash) {
			return fmt.Errorf("%w: pending Cursor install intent does not match disk", ErrProjectionDrift)
		}
	case "revoked":
		if legacyPresent || canonicalPresent {
			return fmt.Errorf("%w: revoked Cursor projection is still present", ErrProjectionDrift)
		}
		record.Status = cursorInstallStatusPending
		record.ContentHash = nextContentHash
		record.PendingContentHash = nextContentHash
		record.InstallReceiptID = ""
		record.ProjectionReceiptID = ""
		record.ProjectionPaths = []Projection{projection}
		record.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		record.Manifest = manifest
		store.Installs[index] = record
		if err := writeInstallStore(root, store); err != nil {
			return err
		}
	case "active", "disabled":
		switch cursorInstallPathState(root, record, legacyRel, canonicalRel) {
		case "legacy":
			if !legacyPresent || legacyHash != previousHash || canonicalPresent {
				return fmt.Errorf("%w: legacy Cursor projection does not match its store record", ErrProjectionDrift)
			}
			removeLegacy = true
			legacyExpectedHash = previousHash
			record.ProjectionPaths = cursorTransitionPaths(root, legacyRel, canonicalRel)
			record.PendingContentHash = nextContentHash
			setCursorLegacyOwnership(&record, root, legacyRel, previousHash)
			store.Installs[index] = record
			if err := writeInstallStore(root, store); err != nil {
				return err
			}
		case "transition":
			if record.PendingContentHash != nextContentHash || record.LegacyCursorProjection == nil ||
				record.LegacyCursorContentHash != previousHash ||
				(legacyPresent && legacyHash != previousHash) ||
				(canonicalPresent && canonicalHash != nextContentHash) ||
				(!legacyPresent && !canonicalPresent) {
				return fmt.Errorf("%w: Cursor migration transition does not match disk", ErrProjectionDrift)
			}
			removeLegacy = legacyPresent
			legacyExpectedHash = record.LegacyCursorContentHash
		case "canonical":
			storeChanged := false
			if legacyPresent {
				ownedHash, err := authorizeCursorLegacyProjection(managed, root, store, index, record, legacyRel, legacyHash)
				if err != nil {
					return err
				}
				setCursorLegacyOwnership(&record, root, legacyRel, ownedHash)
				removeLegacy = true
				legacyExpectedHash = ownedHash
				storeChanged = true
			}
			if record.PendingContentHash == "" {
				if !canonicalPresent || canonicalHash != previousHash {
					return fmt.Errorf("%w: canonical Cursor projection does not match its store record", ErrProjectionDrift)
				}
				record.PendingContentHash = nextContentHash
				storeChanged = true
			} else if !canonicalPresent || (canonicalHash != previousHash && canonicalHash != nextContentHash) {
				return fmt.Errorf("%w: canonical Cursor transition does not match disk", ErrProjectionDrift)
			}
			if storeChanged {
				store.Installs[index] = record
				if err := writeInstallStore(root, store); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("%w: Cursor install paths are invalid", ErrProjectionDrift)
		}
	default:
		return fmt.Errorf("%w: Cursor install status is invalid", ErrProjectionDrift)
	}

	if !canonicalPresent || canonicalHash != nextContentHash {
		if err := atomicReplaceManagedAt(managed, canonicalRel, content); err != nil {
			return err
		}
	}
	observed, err := readManagedFileAt(managed, canonicalRel, maxProjectionArtifactBytes)
	if err != nil || HashBytes(observed) != nextContentHash || !constantBytesEqual(observed, content) {
		return fmt.Errorf("%w: canonical Cursor projection readback mismatch: %v", ErrProjectionDrift, err)
	}
	if removeLegacy {
		legacyPresent, legacyHash, err = observeManagedFile(managed, legacyRel, maxProjectionArtifactBytes)
		if err != nil || (legacyPresent && legacyHash != legacyExpectedHash) {
			return fmt.Errorf("%w: legacy Cursor projection changed during migration: %v", ErrProjectionDrift, err)
		}
		if legacyPresent {
			if err := removeManagedFileAt(managed, legacyRel); err != nil {
				return err
			}
		}
	}
	return nil
}

func findCursorInstallRecord(store installStore, skillID, scope string) (int, error) {
	index := -1
	for i := range store.Installs {
		record := store.Installs[i]
		if record.SkillID != skillID || !strings.EqualFold(strings.TrimSpace(record.Agent), "cursor") || record.Scope != scope {
			continue
		}
		if index >= 0 {
			return -1, fmt.Errorf("%w: duplicate Cursor install records", ErrProjectionDrift)
		}
		index = i
	}
	return index, nil
}

func validateCursorInstallRecordPaths(root string, record installedSkill, legacyRel, canonicalRel string) error {
	state := cursorInstallPathState(root, record, legacyRel, canonicalRel)
	if state == "" || !validProjectionSHA256(record.ContentHash) ||
		(record.PendingContentHash != "" && !validProjectionSHA256(record.PendingContentHash)) ||
		(state != "transition" && record.PendingContentHash != "" && state != "canonical") {
		return fmt.Errorf("%w: Cursor install path record is invalid", ErrProjectionDrift)
	}
	if (record.LegacyCursorProjection == nil) != (record.LegacyCursorContentHash == "") {
		return fmt.Errorf("%w: Cursor legacy ownership record is incomplete", ErrProjectionDrift)
	}
	if record.LegacyCursorProjection != nil &&
		(record.LegacyCursorProjection.Agent != "cursor" ||
			!sameProjectionPath(root, record.LegacyCursorProjection.Path, legacyRel) ||
			!validProjectionSHA256(record.LegacyCursorContentHash)) {
		return fmt.Errorf("%w: Cursor legacy ownership record is invalid", ErrProjectionDrift)
	}
	return nil
}

func ensureCursorPathOwnership(store installStore, owner int, root, legacyRel, canonicalRel string) error {
	for i, record := range store.Installs {
		if i == owner {
			continue
		}
		for _, projection := range record.ProjectionPaths {
			if sameProjectionPath(root, projection.Path, legacyRel) || sameProjectionPath(root, projection.Path, canonicalRel) {
				return fmt.Errorf("%w: Cursor projection path has multiple store owners", ErrProjectionDrift)
			}
		}
		if record.LegacyCursorProjection != nil &&
			(sameProjectionPath(root, record.LegacyCursorProjection.Path, legacyRel) ||
				sameProjectionPath(root, record.LegacyCursorProjection.Path, canonicalRel)) {
			return fmt.Errorf("%w: Cursor projection path has multiple store owners", ErrProjectionDrift)
		}
	}
	return nil
}

func setCursorLegacyOwnership(record *installedSkill, root, legacyRel, contentHash string) {
	projection := Projection{Agent: "cursor", Path: filepath.Join(root, legacyRel)}
	record.LegacyCursorProjection = &projection
	record.LegacyCursorContentHash = contentHash
}

func authorizeCursorLegacyProjection(
	managed *os.Root,
	root string,
	store installStore,
	owner int,
	record installedSkill,
	legacyRel, observedHash string,
) (string, error) {
	if record.LegacyCursorProjection != nil {
		if record.LegacyCursorProjection.Agent != "cursor" ||
			!sameProjectionPath(root, record.LegacyCursorProjection.Path, legacyRel) ||
			!constantStringEqual(record.LegacyCursorContentHash, observedHash) {
			return "", fmt.Errorf("%w: retired Cursor projection differs from its ownership record", ErrProjectionDrift)
		}
		return observedHash, nil
	}
	if err := ensureCursorPathOwnership(store, owner, root, legacyRel, legacyRel); err != nil {
		return "", err
	}
	owned, err := cursorReceiptOwnsLegacyProjection(managed, root, record.SkillID, legacyRel, observedHash)
	if err != nil {
		return "", err
	}
	if !owned {
		return "", ErrUnmanagedProjection
	}
	return observedHash, nil
}

func cursorReceiptOwnsLegacyProjection(
	managed *os.Root,
	root, skillID, legacyRel, observedHash string,
) (bool, error) {
	const maxReceiptEntries = 4096
	receiptsRel := filepath.Join(".helm", "skillpacks", "receipts")
	if err := validateManagedPathAt(managed, receiptsRel, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	info, err := managed.Lstat(receiptsRel)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, ErrProjectionPathUnsafe
	}
	dir, err := managed.Open(receiptsRel)
	if err != nil {
		return false, err
	}
	defer dir.Close()
	opened, err := dir.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return false, ErrProjectionPathUnsafe
	}

	ownerMatch := false
	foreignClaim := false
	count := 0
	for {
		entries, readErr := dir.ReadDir(128)
		for _, entry := range entries {
			count++
			if count > maxReceiptEntries || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
				return false, ErrProjectionPathUnsafe
			}
			data, err := readManagedFileAt(managed, filepath.Join(receiptsRel, entry.Name()), maxProjectionArtifactBytes)
			if err != nil {
				return false, err
			}
			var receipt Receipt
			if err := json.Unmarshal(data, &receipt); err != nil || !validSkillPackReceipt(receipt) ||
				entry.Name() != sanitizePathSegment(receipt.ID)+".json" {
				return false, fmt.Errorf("%w: Cursor ownership receipt is invalid", ErrProjectionDrift)
			}
			if receipt.Type != "SKILL_INSTALL_RECEIPT" && receipt.Type != "SKILL_PROJECTION_RECEIPT" {
				continue
			}
			claimsLegacy := false
			for _, projection := range receipt.ProjectionPaths {
				if projection.Agent == "cursor" && sameProjectionPath(root, projection.Path, legacyRel) {
					claimsLegacy = true
					break
				}
			}
			if !claimsLegacy {
				continue
			}
			if receipt.SkillID != skillID {
				foreignClaim = true
				continue
			}
			if receipt.SkillContentHash == observedHash {
				ownerMatch = true
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return false, readErr
		}
	}
	if foreignClaim {
		return false, fmt.Errorf("%w: legacy Cursor receipt ownership is ambiguous", ErrProjectionDrift)
	}
	return ownerMatch, nil
}

func validSkillPackReceipt(receipt Receipt) bool {
	id := receipt.ID
	if id == "" {
		return false
	}
	receipt.ID = ""
	return constantStringEqual(id, "receipt:"+hashCanonical(receipt))
}

func cursorInstallPathState(root string, record installedSkill, legacyRel, canonicalRel string) string {
	if len(record.ProjectionPaths) == 1 && record.ProjectionPaths[0].Agent == "cursor" {
		switch {
		case sameProjectionPath(root, record.ProjectionPaths[0].Path, legacyRel):
			return "legacy"
		case sameProjectionPath(root, record.ProjectionPaths[0].Path, canonicalRel):
			return "canonical"
		}
	}
	if len(record.ProjectionPaths) == 2 && record.PendingContentHash != "" {
		legacy, canonical := false, false
		for _, projection := range record.ProjectionPaths {
			if projection.Agent != "cursor" {
				return ""
			}
			legacy = legacy || sameProjectionPath(root, projection.Path, legacyRel)
			canonical = canonical || sameProjectionPath(root, projection.Path, canonicalRel)
		}
		if legacy && canonical {
			return "transition"
		}
	}
	return ""
}

func cursorTransitionPaths(root, legacyRel, canonicalRel string) []Projection {
	return []Projection{
		{Agent: "cursor", Path: filepath.Join(root, legacyRel)},
		{Agent: "cursor", Path: filepath.Join(root, canonicalRel)},
	}
}

func sameProjectionPath(root, candidate, relative string) bool {
	if !filepath.IsAbs(candidate) {
		return false
	}
	relative = filepath.Clean(relative)
	if relative == "." || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return false
	}
	candidateRoot := filepath.Clean(candidate)
	parts := strings.Split(relative, string(os.PathSeparator))
	for i := len(parts) - 1; i >= 0; i-- {
		if filepath.Base(candidateRoot) != parts[i] {
			return false
		}
		parent := filepath.Dir(candidateRoot)
		if parent == candidateRoot {
			return false
		}
		candidateRoot = parent
	}
	expectedRoot, expectedErr := canonicalRepositoryRoot(root)
	observedRoot, observedErr := canonicalRepositoryRoot(candidateRoot)
	return expectedErr == nil && observedErr == nil && expectedRoot == observedRoot
}

func canonicalRepositoryRoot(root string) (string, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("skillpacks: resolve repository root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("skillpacks: resolve repository root symlinks: %w", err)
	}
	info, err := os.Lstat(resolved)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		if err != nil {
			return "", err
		}
		return "", ErrProjectionPathUnsafe
	}
	managed, err := openManagedRoot(resolved)
	if err != nil {
		return "", err
	}
	defer managed.Close()
	opened, err := managed.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		if err != nil {
			return "", err
		}
		return "", fmt.Errorf("%w: repository root changed during resolution", ErrProjectionPathUnsafe)
	}
	return filepath.Clean(resolved), nil
}

func Disable(repoRoot, skillID string) (Receipt, error) {
	if repoRoot == "" {
		var err error
		repoRoot, err = os.Getwd()
		if err != nil {
			return Receipt{}, err
		}
	}
	receipt := NewReceipt("SKILL_DISABLE_RECEIPT", skillID, VerdictAllow, "", "", "", nil)
	if err := markInstallStatus(repoRoot, skillID, "disabled"); err != nil {
		return Receipt{}, err
	}
	_, err := WriteReceipt(repoRoot, receipt)
	return receipt, err
}

func Revoke(repoRoot, skillID string) (Receipt, error) {
	if repoRoot == "" {
		var err error
		repoRoot, err = os.Getwd()
		if err != nil {
			return Receipt{}, err
		}
	}
	repoRoot, err := canonicalRepositoryRoot(repoRoot)
	if err != nil {
		return Receipt{}, err
	}
	store, err := readInstallStore(repoRoot)
	if err != nil {
		return Receipt{}, err
	}
	cursorPaths, cursorRoot, err := validateCursorRevoke(repoRoot, store, skillID)
	if err != nil {
		return Receipt{}, err
	}
	if cursorRoot != nil {
		defer cursorRoot.Close()
	}
	paths := []Projection{}
	for i := range store.Installs {
		if store.Installs[i].SkillID == skillID {
			paths = append(paths, store.Installs[i].ProjectionPaths...)
			store.Installs[i].Status = "revoked"
			store.Installs[i].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		}
	}
	for _, p := range paths {
		if strings.EqualFold(strings.TrimSpace(p.Agent), "cursor") {
			continue
		}
		if err := os.Remove(p.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return Receipt{}, err
		}
	}
	for rel, hashes := range cursorPaths {
		present, hash, err := observeManagedFile(cursorRoot, rel, maxProjectionArtifactBytes)
		if err != nil {
			return Receipt{}, err
		}
		if !present {
			continue
		}
		if _, ok := hashes[hash]; !ok {
			return Receipt{}, fmt.Errorf("%w: Cursor projection changed before revoke", ErrProjectionDrift)
		}
		if err := removeManagedFileAt(cursorRoot, rel); err != nil {
			return Receipt{}, err
		}
	}
	if err := writeInstallStore(repoRoot, store); err != nil {
		return Receipt{}, err
	}
	receipt := NewReceipt("SKILL_REVOKE_RECEIPT", skillID, VerdictAllow, "", "", "", paths)
	_, err = WriteReceipt(repoRoot, receipt)
	return receipt, err
}

func validateCursorRevoke(root string, store installStore, skillID string) (map[string]map[string]struct{}, *os.Root, error) {
	removals := map[string]map[string]struct{}{}
	var managed *os.Root
	for index, record := range store.Installs {
		if record.SkillID != skillID || !strings.EqualFold(strings.TrimSpace(record.Agent), "cursor") {
			continue
		}
		legacyRel, err := legacyCursorRelativePath(record.SkillID)
		if err != nil {
			return nil, nil, err
		}
		canonical, err := projectionRelativePath(record.SkillID, "cursor")
		if err != nil {
			return nil, nil, err
		}
		if err := validateCursorInstallRecordPaths(root, record, legacyRel, canonical.Path); err != nil {
			return nil, nil, err
		}
		if err := ensureCursorPathOwnership(store, index, root, legacyRel, canonical.Path); err != nil {
			if managed != nil {
				_ = managed.Close()
			}
			return nil, nil, err
		}
		if managed == nil {
			managed, err = openManagedRoot(root)
			if err != nil {
				return nil, nil, err
			}
		}
		state := cursorInstallPathState(root, record, legacyRel, canonical.Path)
		for _, projection := range record.ProjectionPaths {
			rel := canonical.Path
			hashes := map[string]struct{}{record.ContentHash: {}}
			if sameProjectionPath(root, projection.Path, legacyRel) {
				rel = legacyRel
			} else if record.PendingContentHash != "" {
				hashes[record.PendingContentHash] = struct{}{}
			}
			if state == "transition" && rel == canonical.Path {
				hashes = map[string]struct{}{record.PendingContentHash: {}}
			}
			present, hash, err := observeManagedFile(managed, rel, maxProjectionArtifactBytes)
			if err != nil {
				_ = managed.Close()
				return nil, nil, err
			}
			if present {
				if _, ok := hashes[hash]; !ok {
					_ = managed.Close()
					return nil, nil, fmt.Errorf("%w: Cursor revoke path differs from its store record", ErrProjectionDrift)
				}
			}
			if existing, ok := removals[rel]; ok {
				for allowed := range hashes {
					existing[allowed] = struct{}{}
				}
			} else {
				removals[rel] = hashes
			}
		}
		legacyAlreadyRecorded := state == "legacy" || state == "transition"
		if !legacyAlreadyRecorded {
			present, hash, err := observeManagedFile(managed, legacyRel, maxProjectionArtifactBytes)
			if err != nil {
				_ = managed.Close()
				return nil, nil, err
			}
			if present {
				ownedHash, err := authorizeCursorLegacyProjection(managed, root, store, index, record, legacyRel, hash)
				if err != nil {
					_ = managed.Close()
					return nil, nil, err
				}
				removals[legacyRel] = map[string]struct{}{ownedHash: {}}
			}
		}
	}
	return removals, managed, nil
}

func ListInstalled(repoRoot string) (any, error) {
	if repoRoot == "" {
		var err error
		repoRoot, err = os.Getwd()
		if err != nil {
			return nil, err
		}
	}
	return readInstallStore(repoRoot)
}

type installStore struct {
	SchemaVersion string           `json:"schema_version"`
	Installs      []installedSkill `json:"installs"`
}

type installedSkill struct {
	SkillID                 string       `json:"skill_id"`
	Agent                   string       `json:"agent"`
	Scope                   string       `json:"scope"`
	Status                  string       `json:"status"`
	ContentHash             string       `json:"content_hash"`
	PendingContentHash      string       `json:"pending_content_hash,omitempty"`
	LegacyCursorProjection  *Projection  `json:"legacy_cursor_projection,omitempty"`
	LegacyCursorContentHash string       `json:"legacy_cursor_content_hash,omitempty"`
	InstallReceiptID        string       `json:"install_receipt_id"`
	ProjectionReceiptID     string       `json:"projection_receipt_id"`
	ProjectionPaths         []Projection `json:"projection_paths"`
	UpdatedAt               string       `json:"updated_at"`
	Manifest                Manifest     `json:"manifest"`
}

func updateInstallStore(root string, manifest Manifest, req InstallRequest, paths []Projection, installReceipt, projectionReceipt string) error {
	store, err := readInstallStore(root)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for i := range store.Installs {
		agentMatches := store.Installs[i].Agent == req.Agent ||
			(req.Agent == "cursor" && strings.EqualFold(strings.TrimSpace(store.Installs[i].Agent), "cursor"))
		if store.Installs[i].SkillID == manifest.ID && agentMatches && store.Installs[i].Scope == req.Scope {
			store.Installs[i].Agent = req.Agent
			store.Installs[i].Status = "active"
			store.Installs[i].ContentHash = manifest.ContentHash
			store.Installs[i].PendingContentHash = ""
			store.Installs[i].InstallReceiptID = installReceipt
			store.Installs[i].ProjectionReceiptID = projectionReceipt
			store.Installs[i].ProjectionPaths = paths
			store.Installs[i].UpdatedAt = now
			store.Installs[i].Manifest = manifest
			return writeInstallStore(root, store)
		}
	}
	store.Installs = append(store.Installs, installedSkill{
		SkillID: manifest.ID, Agent: req.Agent, Scope: req.Scope, Status: "active",
		ContentHash: manifest.ContentHash, InstallReceiptID: installReceipt,
		ProjectionReceiptID: projectionReceipt, ProjectionPaths: paths, UpdatedAt: now, Manifest: manifest,
	})
	return writeInstallStore(root, store)
}

func markInstallStatus(root, skillID, status string) error {
	store, err := readInstallStore(root)
	if err != nil {
		return err
	}
	found := false
	for i := range store.Installs {
		if store.Installs[i].SkillID == skillID {
			store.Installs[i].Status = status
			store.Installs[i].UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			found = true
		}
	}
	if !found {
		return fmt.Errorf("skill %s is not managed by HELM", skillID)
	}
	return writeInstallStore(root, store)
}

func readInstallStore(root string) (installStore, error) {
	path := filepath.Join(root, ".helm", "skillpacks", "installed.json")
	store := installStore{SchemaVersion: "helm.skillpack.installs.v1", Installs: []installedSkill{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return store, err
	}
	if err := json.Unmarshal(data, &store); err != nil {
		return store, err
	}
	return store, nil
}

func writeInstallStore(root string, store installStore) error {
	path := filepath.Join(root, ".helm", "skillpacks", "installed.json")
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return atomicWrite(path, data)
}
