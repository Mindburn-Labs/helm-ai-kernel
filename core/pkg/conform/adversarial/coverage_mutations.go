package adversarial

// quantum_posture: SHA-256 is used only to detect a torn local snapshot read;
// campaign authorization remains externally rooted and makes no PQ claim.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
)

const (
	maxCoverageMutationEntries = 4096
	maxCoverageMutationBytes   = 32 << 20
)

type restoreCoverageMutation func() bool

type coverageMutation struct {
	ID             string
	ExpectedTestID string
	Apply          func(string) (restoreCoverageMutation, bool)
}

func mandatoryCoverageMutations() map[string]coverageMutation {
	return map[string]coverageMutation{
		"ADV-01": {ID: "receipt-sequence-gap/v1", ExpectedTestID: "ADV-01-T1", Apply: mutateReceiptSequenceGap},
		"ADV-02": {ID: "policy-decision-bypass/v1", ExpectedTestID: "ADV-02-T1", Apply: mutatePolicyBinding},
		"ADV-03": {ID: "proofgraph-dangling-parent/v1", ExpectedTestID: "ADV-03-T1", Apply: mutateProofGraphParent},
		"ADV-04": {ID: "budget-overdraft/v1", ExpectedTestID: "ADV-04-T1", Apply: mutateBudgetBoundary},
		"ADV-05": {ID: "envelope-binding-removal/v1", ExpectedTestID: "ADV-05-T1", Apply: mutateEnvelopeBinding},
		"ADV-06": {ID: "tape-value-hash-tamper/v1", ExpectedTestID: "ADV-06-T1", Apply: mutateTapeHash},
		"ADV-07": {ID: "cross-tenant-replay/v1", ExpectedTestID: "ADV-07-T1", Apply: mutateTenantBinding},
		"ADV-08": {ID: "unsigned-tool-manifest/v1", ExpectedTestID: "ADV-08-T1", Apply: mutateToolSignature},
		"ADV-09": {ID: "post-panic-receipt/v1", ExpectedTestID: "ADV-09-T1", Apply: mutatePanicBoundary},
		"ADV-10": {ID: "high-finality-approval-bypass/v1", ExpectedTestID: "ADV-10-T1", Apply: mutateApprovalBinding},
	}
}

func newCoverageMutationWorkspace(evidenceDir string, opts VerificationOptions) (string, func(), error) {
	expectedRoots, err := externallyVerifiedEvidenceRoots(opts)
	if err != nil {
		return "", func() {}, err
	}
	tempDir, err := os.MkdirTemp("", "helm-adversarial-mutations-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(tempDir) }
	mutationRoot := filepath.Join(tempDir, "evidence-pack")
	if err := copyCoverageMutationTree(evidenceDir, mutationRoot); err != nil {
		cleanup()
		return "", func() {}, err
	}
	var verifiedRoots evidence.EvidencePackIndexRoots
	if opts.AllowVerifiedConformanceSignature {
		verifiedRoots, err = evidence.VerifyEvidencePackIndexRootsAllowingVerifiedConformanceSignature(mutationRoot)
	} else {
		verifiedRoots, err = evidence.VerifyEvidencePackIndexRoots(mutationRoot)
	}
	if err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("verify mutation snapshot inventory: %w", err)
	}
	if verifiedRoots != expectedRoots {
		cleanup()
		return "", func() {}, fmt.Errorf(
			"mutation snapshot roots differ from externally verified EvidencePack roots: index_hash=%s merkle_root=%s entry_count=%d",
			verifiedRoots.IndexHash,
			verifiedRoots.MerkleRoot,
			verifiedRoots.EntryCount,
		)
	}
	return mutationRoot, cleanup, nil
}

func externallyVerifiedEvidenceRoots(opts VerificationOptions) (evidence.EvidencePackIndexRoots, error) {
	indexHash, err := canonicalSHA256Digest("verified EvidencePack index hash", opts.VerifiedEvidenceIndexHash)
	if err != nil {
		return evidence.EvidencePackIndexRoots{}, err
	}
	merkleRoot, err := canonicalSHA256Digest("verified EvidencePack Merkle root", opts.VerifiedEvidenceMerkleRoot)
	if err != nil {
		return evidence.EvidencePackIndexRoots{}, err
	}
	if opts.VerifiedEvidenceEntryCount < 0 {
		return evidence.EvidencePackIndexRoots{}, fmt.Errorf("verified EvidencePack entry count must be non-negative")
	}
	return evidence.EvidencePackIndexRoots{
		IndexHash:  indexHash,
		MerkleRoot: merkleRoot,
		EntryCount: opts.VerifiedEvidenceEntryCount,
	}, nil
}

func canonicalSHA256Digest(name, value string) (string, error) {
	value = strings.TrimSpace(value)
	digest, err := hex.DecodeString(value)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != value {
		return "", fmt.Errorf("%s must be a canonical lowercase %d-byte SHA-256 hex digest", name, sha256.Size)
	}
	return value, nil
}

func copyCoverageMutationTree(source, destination string) error {
	var copiedBytes int64
	entries := 0
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("mutation snapshot rejects symlink: %s", entry.Name())
		}
		entries++
		if entries > maxCoverageMutationEntries {
			return fmt.Errorf("mutation snapshot exceeds %d entries", maxCoverageMutationEntries)
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("mutation snapshot rejects non-regular file: %s", entry.Name())
		}
		copiedBytes += info.Size()
		if info.Size() > maxCoverageMutationBytes || copiedBytes > maxCoverageMutationBytes {
			return fmt.Errorf("mutation snapshot exceeds %d bytes", maxCoverageMutationBytes)
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		openedInfo, statErr := input.Stat()
		if statErr != nil || !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() {
			_ = input.Close()
			return fmt.Errorf("EvidencePack changed while snapshotting: %s", entry.Name())
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			_ = input.Close()
			return err
		}
		output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			_ = input.Close()
			return err
		}
		copiedHasher := sha256.New()
		copied, copyErr := io.Copy(io.MultiWriter(output, copiedHasher), io.LimitReader(input, info.Size()+1))
		closeOutputErr := output.Close()
		closeInputErr := input.Close()
		switch {
		case copyErr != nil:
			return copyErr
		case closeOutputErr != nil:
			return closeOutputErr
		case closeInputErr != nil:
			return closeInputErr
		case copied != info.Size():
			return fmt.Errorf("EvidencePack changed while snapshotting: %s", entry.Name())
		}
		verificationInput, err := os.Open(path)
		if err != nil {
			return err
		}
		verificationInfo, statErr := verificationInput.Stat()
		if statErr != nil || !os.SameFile(info, verificationInfo) || !verificationInfo.Mode().IsRegular() || verificationInfo.Size() != info.Size() || !verificationInfo.ModTime().Equal(info.ModTime()) {
			_ = verificationInput.Close()
			return fmt.Errorf("EvidencePack changed while snapshotting: %s", entry.Name())
		}
		verificationHasher := sha256.New()
		verified, verificationErr := io.Copy(verificationHasher, io.LimitReader(verificationInput, info.Size()+1))
		closeVerificationErr := verificationInput.Close()
		switch {
		case verificationErr != nil:
			return verificationErr
		case closeVerificationErr != nil:
			return closeVerificationErr
		case verified != info.Size():
			return fmt.Errorf("EvidencePack changed while snapshotting: %s", entry.Name())
		case !bytes.Equal(copiedHasher.Sum(nil), verificationHasher.Sum(nil)):
			return fmt.Errorf("EvidencePack changed while snapshotting: %s", entry.Name())
		}
		return nil
	})
}

func runCoverageMutation(evidenceDir string, suite *Suite, mutation coverageMutation) (bool, bool, bool) {
	if mutation.Apply == nil || mutation.ExpectedTestID == "" {
		return false, false, false
	}
	restore, applied := mutation.Apply(evidenceDir)
	if !applied || restore == nil {
		return false, false, false
	}
	restored := false
	defer func() {
		if !restored {
			_ = restore()
		}
	}()
	result := suite.Run(evidenceDir)
	rejected := false
	if result != nil && !result.Pass {
		for _, test := range result.TestResults {
			if test.TestID == mutation.ExpectedTestID && !test.Pass {
				rejected = true
				break
			}
		}
	}
	restored = restore()
	if !restored {
		return true, rejected, false
	}
	return true, rejected, true
}

func suitePassesExpectedTest(result *SuiteResult, expectedTestID string) bool {
	if result == nil || !result.Pass || expectedTestID == "" {
		return false
	}
	for _, test := range result.TestResults {
		if test.TestID == expectedTestID {
			return test.Pass
		}
	}
	return false
}

func mutateReceiptSequenceGap(evidenceDir string) (restoreCoverageMutation, bool) {
	files := receiptFiles(evidenceDir)
	var targetPath string
	var maxSequence float64 = -1
	validSequences := 0
	for _, path := range files {
		receipt := loadReceipt(path)
		sequence, ok := receiptSequence(receipt)
		if !ok {
			continue
		}
		validSequences++
		if sequence > maxSequence {
			maxSequence = sequence
			targetPath = path
		}
	}
	if validSequences < 2 || targetPath == "" {
		return nil, false
	}
	const maxExactJSONInteger = 1<<53 - 1
	return applyJSONMutation(targetPath, func(target map[string]interface{}) {
		if maxSequence < maxExactJSONInteger {
			target["seq"] = maxSequence + 1
		} else {
			target["seq"] = float64(0)
		}
	})
}

func mutatePolicyBinding(evidenceDir string) (restoreCoverageMutation, bool) {
	return mutateFirstReceipt(evidenceDir, func(receipt map[string]interface{}) bool {
		action, _ := receipt["action_type"].(string)
		return isEffectAction(action)
	}, mutateDecisionID)
}

func mutateProofGraphParent(evidenceDir string) (restoreCoverageMutation, bool) {
	return mutateFirstReceipt(evidenceDir, func(receipt map[string]interface{}) bool {
		sequence, ok := receiptSequence(receipt)
		return ok && sequence > 1
	}, func(receipt map[string]interface{}) {
		receipt["parent_receipt_hashes"] = []string{"sha256:helm-mutation-missing-parent"}
	})
}

func mutateBudgetBoundary(evidenceDir string) (restoreCoverageMutation, bool) {
	type exhaustion struct {
		scope    string
		sequence float64
	}
	files := receiptFiles(evidenceDir)
	exhaustions := make([]exhaustion, 0)
	for _, path := range files {
		receipt := loadReceipt(path)
		if receipt["action_type"] != "budget_exhausted" {
			continue
		}
		sequence, ok := receiptSequence(receipt)
		if scope := budgetScope(receipt); ok && scope != "" {
			exhaustions = append(exhaustions, exhaustion{scope: scope, sequence: sequence})
		}
	}
	for _, path := range files {
		receipt := loadReceipt(path)
		if receipt["action_type"] != "budget_decrement" {
			continue
		}
		sequence, ok := receiptSequence(receipt)
		scope := budgetScope(receipt)
		if !ok || scope == "" {
			continue
		}
		for _, boundary := range exhaustions {
			if boundary.scope == scope && sequence < boundary.sequence {
				return applyJSONMutation(path, func(target map[string]interface{}) {
					target["seq"] = boundary.sequence
				})
			}
		}
	}
	return nil, false
}

func mutateEnvelopeBinding(evidenceDir string) (restoreCoverageMutation, bool) {
	return mutateFirstReceipt(evidenceDir, func(receipt map[string]interface{}) bool {
		action, _ := receipt["action_type"].(string)
		return isEffectAction(action)
	}, func(receipt map[string]interface{}) {
		delete(receipt, "envelope_hash")
	})
}

func mutateTapeHash(evidenceDir string) (restoreCoverageMutation, bool) {
	files, _ := filepath.Glob(filepath.Join(evidenceDir, "08_TAPES", "entry_*.json"))
	for _, path := range files {
		entry := loadMutationJSON(path)
		if entry == nil || !validTapeEntry(entry) {
			continue
		}
		return applyJSONMutation(path, func(target map[string]interface{}) {
			current, _ := target["value_hash"].(string)
			target["value_hash"] = differentMutationValue(current)
		})
	}
	return nil, false
}

func mutateTenantBinding(evidenceDir string) (restoreCoverageMutation, bool) {
	seenTenant := ""
	seenReceipts := 0
	return mutateFirstReceipt(evidenceDir, func(receipt map[string]interface{}) bool {
		tenant, _ := receipt["tenant_id"].(string)
		tenant = strings.TrimSpace(tenant)
		if tenant == "" {
			return false
		}
		seenReceipts++
		if seenTenant == "" {
			seenTenant = tenant
			return false
		}
		return seenReceipts >= 2
	}, func(receipt map[string]interface{}) {
		receipt["tenant_id"] = differentMutationValue(seenTenant)
	})
}

func mutateToolSignature(evidenceDir string) (restoreCoverageMutation, bool) {
	for _, path := range toolManifestFiles(evidenceDir) {
		manifest := loadMutationJSON(path)
		if manifest == nil {
			continue
		}
		return applyJSONMutation(path, func(target map[string]interface{}) {
			delete(target, "signatures")
		})
	}
	return nil, false
}

func mutatePanicBoundary(evidenceDir string) (restoreCoverageMutation, bool) {
	maxSequence := float64(-1)
	for _, path := range receiptFiles(evidenceDir) {
		if sequence, ok := receiptSequence(loadReceipt(path)); ok && sequence > maxSequence {
			maxSequence = sequence
		}
	}
	if maxSequence < 1 {
		return nil, false
	}
	for _, path := range panicEvidenceFiles(evidenceDir) {
		panicRecord := loadMutationJSON(path)
		if panicRecord == nil {
			continue
		}
		return applyJSONMutation(path, func(target map[string]interface{}) {
			target["last_good_seq"] = maxSequence - 1
		})
	}
	return nil, false
}

func mutateApprovalBinding(evidenceDir string) (restoreCoverageMutation, bool) {
	return mutateFirstReceipt(evidenceDir, func(receipt map[string]interface{}) bool {
		action, _ := receipt["action_type"].(string)
		effectClass, _ := receipt["effect_class"].(string)
		return isHighFinality(effectClass, action)
	}, mutateDecisionID)
}

func mutateDecisionID(receipt map[string]interface{}) {
	current, _ := receipt["decision_id"].(string)
	receipt["decision_id"] = differentMutationValue(current)
}

func mutateFirstReceipt(evidenceDir string, match func(map[string]interface{}) bool, mutate func(map[string]interface{})) (restoreCoverageMutation, bool) {
	for _, path := range receiptFiles(evidenceDir) {
		receipt := loadReceipt(path)
		if receipt == nil || !match(receipt) {
			continue
		}
		return applyJSONMutation(path, mutate)
	}
	return nil, false
}

func receiptFiles(evidenceDir string) []string {
	files, _ := filepath.Glob(filepath.Join(evidenceDir, "02_PROOFGRAPH", "receipts", "*.json"))
	return files
}

func loadMutationJSON(path string) map[string]interface{} {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var value map[string]interface{}
	if json.Unmarshal(data, &value) != nil {
		return nil
	}
	return value
}

func applyJSONMutation(path string, mutate func(map[string]interface{})) (restoreCoverageMutation, bool) {
	original, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, false
	}
	var value map[string]interface{}
	if json.Unmarshal(original, &value) != nil {
		return nil, false
	}
	mutate(value)
	mutated, err := json.Marshal(value)
	if err != nil || os.WriteFile(path, mutated, info.Mode().Perm()) != nil {
		return nil, false
	}
	restore := func() bool {
		return os.WriteFile(path, original, info.Mode().Perm()) == nil
	}
	return restore, true
}

func differentMutationValue(current string) string {
	return current + ":helm-mutation"
}
