package main

// quantum_posture: evidence verification checks the pack seal and receipt
// signatures against the runtime trust configuration.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	helmotel "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/otel"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
)

// Evidence bundle checks. A check appears in a verification response only
// when it ran; its status uses the evidence verifier vocabulary (AGENTS.md R2).
const (
	evidenceCheckBundleFormat      = "bundle_format"
	evidenceCheckBundleSeal        = "bundle_seal"
	evidenceCheckManifestHashes    = "manifest_hashes"
	evidenceCheckRequiredArtifacts = "required_artifacts"
	evidenceCheckReceiptSignatures = "receipt_signatures"
	evidenceCheckReceiptChain      = "receipt_chain"
)

// evidenceChecksRequiredForVerified are the checks a VERIFIED outcome needs.
// required_artifacts runs only when a receipt declares an artifact
// requirement, so it is not in this list.
var evidenceChecksRequiredForVerified = []string{
	evidenceCheckBundleFormat,
	evidenceCheckBundleSeal,
	evidenceCheckManifestHashes,
	evidenceCheckReceiptSignatures,
	evidenceCheckReceiptChain,
}

// evidenceCheck is one check that ran. Status is VERIFIED when the property
// held, FAILED when it did not, and UNVERIFIABLE when the material is intact
// but signed by a key the runtime does not trust, or the runtime has no trust
// anchor to check it against.
type evidenceCheck struct {
	Name   string                `json:"name"`
	Status receiptverify.Verdict `json:"status"`
	Detail string                `json:"detail"`
}

type evidenceVerificationRoots struct {
	EntryCount int `json:"entry_count"`
}

// evidenceVerification is the POST /api/v1/evidence/verify response.
type evidenceVerification struct {
	Outcome   receiptverify.Verdict     `json:"outcome"`
	ChecksRun []evidenceCheck           `json:"checks_run"`
	Roots     evidenceVerificationRoots `json:"roots"`
	Errors    []string                  `json:"errors"`
}

func (v *evidenceVerification) add(name string, status receiptverify.Verdict, detail string, errs ...string) {
	v.ChecksRun = append(v.ChecksRun, evidenceCheck{Name: name, Status: status, Detail: detail})
	v.Errors = append(v.Errors, errs...)
}

// conclude derives the outcome from the checks that ran: any FAILED check
// fails the bundle; otherwise any UNVERIFIABLE check, or a required check that
// did not run, leaves it UNVERIFIABLE; only a full set of VERIFIED checks
// verifies it. No checks at all is FAILED, never a pass.
//
// The rule itself is verifier.Conclude, the same one `helm-ai-kernel verify`
// reports with, so the route and the CLI cannot drift apart on what a missing
// or unverifiable check means.
func (v *evidenceVerification) conclude() {
	outcomes := make([]verifier.CheckOutcome, 0, len(v.ChecksRun))
	for _, check := range v.ChecksRun {
		outcomes = append(outcomes, verifier.CheckOutcome{Name: check.Name, Status: verifier.CheckStatus(check.Status)})
	}
	v.Outcome = verifier.Conclude(outcomes, evidenceChecksRequiredForVerified).Outcome
}

func verifyEvidenceRequest(r *http.Request, svc *Services) evidenceVerification {
	result := evidenceVerification{ChecksRun: []evidenceCheck{}, Errors: []string{}}
	raw, parsed, receipts, err := readEvidenceVerificationInput(r)
	if err != nil {
		result.add(evidenceCheckBundleFormat, receiptverify.VerdictFailed,
			"the request is not a readable evidence bundle with a manifest and at least one receipt", err.Error())
		result.conclude()
		return result
	}
	result.add(evidenceCheckBundleFormat, receiptverify.VerdictVerified,
		fmt.Sprintf("gzip tar archive with a manifest and %d receipts", len(receipts)))
	result.Roots.EntryCount = len(receipts)

	checkEvidenceBundleSeal(&result, raw, svc)
	checkEvidenceManifestHashes(&result, parsed)
	checkEvidenceRequiredArtifacts(&result, parsed, receipts)
	checkEvidenceReceiptSignatures(&result, receipts, svc)
	checkEvidenceReceiptChain(&result, receipts)
	result.conclude()

	recordVerification(r.Context(), helmotel.VerificationEvent{
		EnvelopeID:  parsed.Manifest.SessionID,
		Verified:    result.Outcome == receiptverify.VerdictVerified,
		CheckCount:  len(receipts),
		EvidenceRef: parsed.Manifest.SessionID,
	})
	return result
}

// readEvidenceVerificationInput reads the uploaded bundle and its receipts,
// sorted by session and Lamport clock.
//
// Each receipt file is read by receiptverify.ParseReceipt, the parser
// receipt_verify uses, so one rule decides what a receipt document is. The
// signature profile is left to verifyTrustedEvidenceReceipt, which checks the
// hybrid and ML-DSA profiles that parser's own verifier does not know. A file
// that writes a member twice, or spells a receipt member in another letter
// case, says one thing to encoding/json and another to a reader that matches
// names exactly; the bundle seal cannot vouch for it, because whoever holds
// the bundle seals it. Such a file makes the bundle unreadable (bundle_format
// FAILED) before any receipt check runs.
func readEvidenceVerificationInput(r *http.Request) ([]byte, *evidenceBundle, []*contracts.Receipt, error) {
	raw, err := readEvidenceBundleRequest(r)
	if err != nil {
		return nil, nil, nil, err
	}
	parsed, err := readEvidenceBundle(raw)
	if err != nil {
		return nil, nil, nil, err
	}
	var receipts []*contracts.Receipt
	for name, data := range parsed.Files {
		if !strings.HasPrefix(name, "receipts/") || !strings.HasSuffix(name, ".json") {
			continue
		}
		receipt, err := receiptverify.ParseReceipt(data, receiptverify.AnySignatureProfile)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%s: %w", name, err)
		}
		receipts = append(receipts, receipt)
	}
	if len(receipts) == 0 {
		return nil, nil, nil, errors.New("no receipts in evidence bundle")
	}
	sort.Slice(receipts, func(i, j int) bool {
		if receipts[i].SessionID == receipts[j].SessionID {
			return receipts[i].LamportClock < receipts[j].LamportClock
		}
		return receipts[i].SessionID < receipts[j].SessionID
	})
	return raw, parsed, receipts, nil
}

func readEvidenceBundleRequest(r *http.Request) ([]byte, error) {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err := r.ParseMultipartForm(maxEvidenceBundleBytes); err != nil {
			return nil, fmt.Errorf("parse multipart evidence bundle: %w", err)
		}
		file, _, err := r.FormFile("bundle")
		if err != nil {
			return nil, fmt.Errorf("multipart field bundle is required: %w", err)
		}
		defer func() { _ = file.Close() }()
		return io.ReadAll(io.LimitReader(file, maxEvidenceBundleBytes+1))
	}
	return io.ReadAll(io.LimitReader(r.Body, maxEvidenceBundleBytes+1))
}

func readEvidenceBundle(data []byte) (*evidenceBundle, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty evidence bundle")
	}
	if len(data) > maxEvidenceBundleBytes {
		return nil, fmt.Errorf("evidence bundle exceeds %d bytes", maxEvidenceBundleBytes)
	}
	gzipReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("open evidence gzip: %w", err)
	}
	defer func() { _ = gzipReader.Close() }()
	tarReader := tar.NewReader(gzipReader)
	files := make(map[string][]byte)
	totalSize := int64(0)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read evidence tar: %w", err)
		}
		if !safeArchiveName(header.Name) {
			return nil, fmt.Errorf("unsafe archive path %q", header.Name)
		}
		if header.Size < 0 {
			return nil, fmt.Errorf("archive entry %q has invalid size", header.Name)
		}
		if header.Size > maxEvidenceBundleBytes {
			return nil, fmt.Errorf("archive entry %q too large", header.Name)
		}
		totalSize += header.Size
		if totalSize > maxEvidenceBundleBytes {
			return nil, fmt.Errorf("evidence archive exceeds %d bytes", maxEvidenceBundleBytes)
		}
		data, err := io.ReadAll(io.LimitReader(tarReader, maxEvidenceBundleBytes+1))
		if err != nil {
			return nil, fmt.Errorf("read archive entry %q: %w", header.Name, err)
		}
		files[header.Name] = data
	}
	manifestData, ok := files["manifest.json"]
	if !ok {
		return nil, fmt.Errorf("manifest.json not found")
	}
	var manifest evidenceManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("decode manifest.json: %w", err)
	}
	delete(files, "manifest.json")
	return &evidenceBundle{Manifest: manifest, Files: files}, nil
}

// checkEvidenceBundleSeal checks the EvidencePack seal against the runtime
// key only. When that does not prove it, the seal is checked once more
// against the key the seal carries, only to tell an intact pack signed by
// another key (UNVERIFIABLE) from a missing, malformed or altered one
// (FAILED); the carried key never makes the seal VERIFIED. The same applies
// when the runtime has no Ed25519 trust anchor at all.
func checkEvidenceBundleSeal(result *evidenceVerification, raw []byte, svc *Services) {
	packDir, err := os.MkdirTemp("", "helm-evidence-verify-*")
	if err != nil {
		result.add(evidenceCheckBundleSeal, receiptverify.VerdictFailed,
			"the bundle could not be unpacked to check its seal",
			"trusted evidence bundle seal verification failed: create evidence verify workspace")
		return
	}
	defer os.RemoveAll(packDir)
	// Seal errors name files inside the workspace; report them relative to
	// the pack so the public route does not leak server paths.
	relative := func(text string) string {
		return strings.ReplaceAll(strings.ReplaceAll(text, packDir+string(os.PathSeparator), ""), packDir, "evidence pack")
	}
	if err := extractEvidenceBundleToDir(raw, packDir); err != nil {
		result.add(evidenceCheckBundleSeal, receiptverify.VerdictFailed,
			"the bundle could not be unpacked to check its seal",
			"trusted evidence bundle seal verification failed: "+relative(err.Error()))
		return
	}

	trustConfig, trustErr := trustedEvidenceBundleSealTrustConfig(svc)
	var runtimeReport evidencepkg.EvidencePackSealVerification
	if trustErr == nil {
		trustedKeyID := trustConfig.Signer.KeyID
		runtimeReport = verifyEvidencePackSealWith(packDir, trustConfig)
		if evidenceSealValid(runtimeReport) && runtimeReport.SignerKeyID == trustedKeyID {
			result.add(evidenceCheckBundleSeal, receiptverify.VerdictVerified,
				fmt.Sprintf("the seal signature verifies under the runtime key %q and the pack inventory matches the seal", trustedKeyID))
			return
		}
	}

	if carried, ok := carriedEvidenceSealTrust(packDir); ok && evidenceSealValid(verifyEvidencePackSealWith(packDir, carried)) {
		if trustErr != nil {
			result.add(evidenceCheckBundleSeal, receiptverify.VerdictUnverifiable,
				"the pack matches its seal, but the runtime has no Ed25519 trust anchor to check the signer against",
				"evidence bundle seal not checked against a trust anchor: "+trustErr.Error())
			return
		}
		result.add(evidenceCheckBundleSeal, receiptverify.VerdictUnverifiable,
			fmt.Sprintf("the pack matches its seal, but the seal is signed by key %q, not the runtime key %q", carried.Signer.KeyID, trustConfig.Signer.KeyID),
			fmt.Sprintf("evidence bundle seal signer %q is not the runtime trust anchor %q", carried.Signer.KeyID, trustConfig.Signer.KeyID))
		return
	}

	detail := fmt.Sprintf("state=%s signer=%s", runtimeReport.State, runtimeReport.SignerKeyID)
	if len(runtimeReport.Errors) > 0 {
		detail = relative(strings.Join(runtimeReport.Errors, "; "))
	} else if trustErr != nil {
		detail = "the seal is missing, names no public key, or does not verify under the key it carries"
	}
	result.add(evidenceCheckBundleSeal, receiptverify.VerdictFailed,
		"the seal is missing or malformed, or does not match the pack contents",
		"trusted evidence bundle seal verification failed: "+detail)
}

func verifyEvidencePackSealWith(packDir string, trustConfig *evidencepkg.EvidencePackTrustConfig) evidencepkg.EvidencePackSealVerification {
	return evidencepkg.VerifyEvidencePackSeal(packDir, evidencepkg.VerifyEvidencePackSealOptions{
		Profile:     evidencepkg.EvidenceTrustProfileDevLocal,
		TrustConfig: trustConfig,
	})
}

func evidenceSealValid(report evidencepkg.EvidencePackSealVerification) bool {
	return report.State == "valid" && report.SignatureValid && len(report.Errors) == 0
}

// carriedEvidenceSealTrust builds a trust config from the signer the seal
// names about itself. It exists only to classify a seal that failed under the
// runtime key; it is never used to accept one.
func carriedEvidenceSealTrust(packDir string) (*evidencepkg.EvidencePackTrustConfig, bool) {
	root, err := os.OpenRoot(packDir)
	if err != nil {
		return nil, false
	}
	defer func() { _ = root.Close() }()
	data, err := root.ReadFile(filepath.FromSlash(evidencepkg.EvidencePackSealPath))
	if err != nil {
		return nil, false
	}
	var seal evidencepkg.EvidencePackSeal
	if err := json.Unmarshal(data, &seal); err != nil {
		return nil, false
	}
	keyID := strings.TrimSpace(seal.Signer.KeyID)
	publicKey := strings.TrimSpace(seal.Signer.PublicKey)
	if keyID == "" || publicKey == "" {
		return nil, false
	}
	return trustedEvidenceBundleSealConfig(keyID, publicKey, seal.Signer.Type), true
}

func extractEvidenceBundleToDir(data []byte, dstDir string) error {
	if len(data) == 0 {
		return fmt.Errorf("empty evidence bundle")
	}
	if len(data) > maxEvidenceBundleBytes {
		return fmt.Errorf("evidence bundle exceeds %d bytes", maxEvidenceBundleBytes)
	}
	root, err := os.OpenRoot(dstDir)
	if err != nil {
		return fmt.Errorf("open evidence extraction root: %w", err)
	}
	defer func() { _ = root.Close() }()
	gzipReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("open evidence gzip: %w", err)
	}
	defer func() { _ = gzipReader.Close() }()
	tarReader := tar.NewReader(gzipReader)
	totalSize := int64(0)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read evidence tar: %w", err)
		}
		if !safeArchiveName(header.Name) {
			return fmt.Errorf("unsafe archive path %q", header.Name)
		}
		if header.Size < 0 {
			return fmt.Errorf("archive entry %q has invalid size", header.Name)
		}
		if header.Size > maxEvidenceBundleBytes {
			return fmt.Errorf("archive entry %q too large", header.Name)
		}
		totalSize += header.Size
		if totalSize > maxEvidenceBundleBytes {
			return fmt.Errorf("evidence archive exceeds %d bytes", maxEvidenceBundleBytes)
		}
		entryData, err := io.ReadAll(io.LimitReader(tarReader, maxEvidenceBundleBytes+1))
		if err != nil {
			return fmt.Errorf("read archive entry %q: %w", header.Name, err)
		}
		if dir := path.Dir(header.Name); dir != "." {
			if err := root.MkdirAll(dir, 0o700); err != nil {
				return fmt.Errorf("mkdir extract path %s: %w", header.Name, err)
			}
		}
		if err := root.WriteFile(header.Name, entryData, 0o600); err != nil {
			return fmt.Errorf("write archive entry %q: %w", header.Name, err)
		}
	}
}

func checkEvidenceManifestHashes(result *evidenceVerification, bundle *evidenceBundle) {
	var errs []string
	for name, expected := range bundle.Manifest.FileHashes {
		data, ok := bundle.Files[name]
		if !ok {
			errs = append(errs, fmt.Sprintf("%s listed in manifest but missing", name))
			continue
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != expected {
			errs = append(errs, fmt.Sprintf("%s hash mismatch", name))
		}
	}
	for name := range bundle.Files {
		if isEvidenceBundleControlFile(name) {
			continue
		}
		if _, ok := bundle.Manifest.FileHashes[name]; !ok {
			errs = append(errs, fmt.Sprintf("%s present but not listed in manifest", name))
		}
	}
	sort.Strings(errs)
	if len(errs) > 0 {
		result.add(evidenceCheckManifestHashes, receiptverify.VerdictFailed,
			"files are missing, unlisted or differ from their manifest SHA-256", errs...)
		return
	}
	result.add(evidenceCheckManifestHashes, receiptverify.VerdictVerified,
		fmt.Sprintf("all %d manifest files are present with matching SHA-256 and no file is unlisted", len(bundle.Manifest.FileHashes)))
}

// checkEvidenceRequiredArtifacts runs only when a receipt declares that it
// needs a referenced artifact; with no such receipt there is nothing to check.
func checkEvidenceRequiredArtifacts(result *evidenceVerification, bundle *evidenceBundle, receipts []*contracts.Receipt) {
	requiring := 0
	for _, receipt := range receipts {
		if receiptRequiresEvidenceArtifact(receipt) {
			requiring++
		}
	}
	if requiring == 0 {
		return
	}
	if errs := verifyHarnessEvidenceRequirements(bundle, receipts); len(errs) > 0 {
		result.add(evidenceCheckRequiredArtifacts, receiptverify.VerdictFailed,
			"receipts that require a referenced artifact do not have it in the bundle", errs...)
		return
	}
	result.add(evidenceCheckRequiredArtifacts, receiptverify.VerdictVerified,
		fmt.Sprintf("all %d receipts that require referenced artifacts have them in the bundle", requiring))
}

func receiptRequiresEvidenceArtifact(receipt *contracts.Receipt) bool {
	for _, requirement := range evidenceArtifactRequirements {
		if requirement.requires(receipt) {
			return true
		}
	}
	return false
}

// checkEvidenceReceiptSignatures verifies every receipt against the runtime
// trust anchor. A receipt that fails there but verifies under the key it
// carries itself is UNVERIFIABLE: intact, but not signed by this runtime. The
// carried key never makes a receipt VERIFIED.
//
// A receipt with no signature_version is not checked, and so is UNVERIFIABLE
// too. This route does not opt in to the legacy preimage
// (helmcrypto.AllowLegacyReceiptPreimages): the signature of a receipt.v5
// receipt this runtime issued verifies under it for an unversioned receipt
// that says something else.
func checkEvidenceReceiptSignatures(result *evidenceVerification, receipts []*contracts.Receipt, svc *Services) {
	var failed, unverifiable []string
	for _, receipt := range receipts {
		switch {
		case strings.TrimSpace(receipt.Signature) == "":
			failed = append(failed, fmt.Sprintf("%s missing signature", receipt.ReceiptID))
		default:
			err := verifyTrustedEvidenceReceipt(svc, receipt)
			switch {
			case err == nil:
			case errors.Is(err, errNoTrustedReceiptVerifier), errors.Is(err, helmcrypto.ErrLegacyReceiptRefused):
				unverifiable = append(unverifiable, fmt.Sprintf("%s not checked: %v", receipt.ReceiptID, err))
			case receiptVerifiesUnderCarriedKey(receipt):
				unverifiable = append(unverifiable, fmt.Sprintf("%s is signed by a key it carries, not by the runtime trust anchor: %v", receipt.ReceiptID, err))
			default:
				failed = append(failed, fmt.Sprintf("%s signature verification failed: %v", receipt.ReceiptID, err))
			}
		}
	}
	switch {
	case len(failed) > 0:
		result.add(evidenceCheckReceiptSignatures, receiptverify.VerdictFailed,
			fmt.Sprintf("%d of %d receipts have a missing or invalid signature", len(failed), len(receipts)),
			append(failed, unverifiable...)...)
	case len(unverifiable) > 0:
		result.add(evidenceCheckReceiptSignatures, receiptverify.VerdictUnverifiable,
			fmt.Sprintf("%d of %d receipts were not checked or do not verify under the runtime trust anchor", len(unverifiable), len(receipts)),
			unverifiable...)
	default:
		result.add(evidenceCheckReceiptSignatures, receiptverify.VerdictVerified,
			fmt.Sprintf("all %d receipt signatures verify under the runtime trust anchor", len(receipts)))
	}
}

// receiptVerifiesUnderCarriedKey reports whether a receipt verifies under its
// own public_key_set. It only separates "signed by another key" from
// "tampered"; it never establishes trust.
func receiptVerifiesUnderCarriedKey(receipt *contracts.Receipt) bool {
	ed25519Key := strings.TrimSpace(receipt.PublicKeySet[helmcrypto.SigPrefixEd25519])
	mldsaKey := strings.TrimSpace(receipt.PublicKeySet[helmcrypto.SigPrefixMLDSA65])
	if ed25519Key == "" && mldsaKey == "" {
		return false
	}
	_, valid, err := helmcrypto.VerifyReceiptProfile(ed25519Key, mldsaKey, receipt)
	return err == nil && valid
}

// checkEvidenceReceiptChain checks each session's receipts form a chain: the
// first has a genesis prev_hash, each later one links to the recomputed hash
// of its predecessor, and Lamport clocks strictly increase. receipts must be
// sorted by session and Lamport clock.
func checkEvidenceReceiptChain(result *evidenceVerification, receipts []*contracts.Receipt) {
	var errs []string
	lastBySession := map[string]uint64{}
	prevBySession := map[string]*contracts.Receipt{}
	for _, receipt := range receipts {
		sessionID := receipt.SessionID
		if last := lastBySession[sessionID]; last != 0 && receipt.LamportClock <= last {
			errs = append(errs, fmt.Sprintf("%s non-monotonic lamport clock", receipt.ReceiptID))
		}
		if previous := prevBySession[sessionID]; previous == nil {
			if !isGenesisPrevHash(receipt.PrevHash) {
				errs = append(errs, fmt.Sprintf("%s invalid genesis prev_hash %q", receipt.ReceiptID, receipt.PrevHash))
			}
		} else {
			expected, err := contracts.ReceiptChainHash(previous)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s previous receipt hash failed: %v", receipt.ReceiptID, err))
			} else if receipt.PrevHash != expected {
				errs = append(errs, fmt.Sprintf("%s prev_hash mismatch: expected %s got %s", receipt.ReceiptID, expected, receipt.PrevHash))
			}
		}
		lastBySession[sessionID] = receipt.LamportClock
		prevBySession[sessionID] = receipt
	}
	if len(errs) > 0 {
		result.add(evidenceCheckReceiptChain, receiptverify.VerdictFailed,
			"the receipt chain is broken or its Lamport clocks do not increase", errs...)
		return
	}
	result.add(evidenceCheckReceiptChain, receiptverify.VerdictVerified,
		fmt.Sprintf("%d receipts across %d sessions link by prev_hash with increasing Lamport clocks", len(receipts), len(prevBySession)))
}

// errNoTrustedReceiptVerifier means the runtime has no trust anchor that can
// check a receipt, so the receipt is unverifiable rather than failed.
var errNoTrustedReceiptVerifier = errors.New("trusted receipt signer unavailable")

// verifyTrustedEvidenceReceipt verifies against the runtime trust anchor, not
// receipt-provided public keys. A self-signed uploaded bundle is consistency
// evidence only and must not become its own authority. A receipt with no
// signature_version is refused with helmcrypto.ErrLegacyReceiptRefused by
// every branch below, the KeyRing included: none passes
// AllowLegacyReceiptPreimages. A signer of another type that exposes
// VerifyReceipt answers for itself.
func verifyTrustedEvidenceReceipt(svc *Services, receipt *contracts.Receipt) error {
	if svc == nil || svc.ReceiptSigner == nil {
		return errNoTrustedReceiptVerifier
	}

	switch signer := svc.ReceiptSigner.(type) {
	case *helmcrypto.Ed25519Signer:
		if signer == nil {
			return errNoTrustedReceiptVerifier
		}
		return verifyEvidenceReceiptProfile(signer.PublicKey(), "", receipt)
	case *helmcrypto.MLDSASigner:
		if signer == nil {
			return errNoTrustedReceiptVerifier
		}
		return verifyEvidenceReceiptProfile("", signer.PublicKey(), receipt)
	case *helmcrypto.HybridSigner:
		if signer == nil || signer.Ed25519Signer() == nil || signer.MLDSASigner() == nil {
			return fmt.Errorf("%w: hybrid signer is incomplete", errNoTrustedReceiptVerifier)
		}
		return verifyEvidenceReceiptProfile(signer.Ed25519Signer().PublicKey(), signer.MLDSASigner().PublicKey(), receipt)
	}

	// KeyRing and external signers that expose VerifyReceipt remain the trusted
	// verification path for rotated or provider-owned runtime keys.
	verifier, ok := svc.ReceiptSigner.(interface {
		VerifyReceipt(*contracts.Receipt) (bool, error)
	})
	if !ok {
		return fmt.Errorf("%w: %T cannot verify receipts", errNoTrustedReceiptVerifier, svc.ReceiptSigner)
	}
	valid, err := verifier.VerifyReceipt(receipt)
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("receipt signature does not match trusted signer")
	}
	return nil
}

func verifyEvidenceReceiptProfile(ed25519PublicKey, mldsa65PublicKey string, receipt *contracts.Receipt) error {
	profile, valid, err := helmcrypto.VerifyReceiptProfile(ed25519PublicKey, mldsa65PublicKey, receipt)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("receipt signature does not match trusted %s profile", profile)
	}
	return nil
}

func isGenesisPrevHash(value string) bool {
	normalized := strings.TrimSpace(value)
	return normalized == "" || normalized == "GENESIS" || normalized == strings.Repeat("0", 64)
}
