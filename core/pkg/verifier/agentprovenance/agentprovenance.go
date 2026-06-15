// Package agentprovenance verifies HELM advisory agent provenance packs.
//
// Agent provenance is authoring evidence. It is never HELM-native execution
// proof unless separately bound to HELM verdict receipts or EvidencePacks.
package agentprovenance

import (
	"archive/tar"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

const (
	PackVersion = "agent_provenance_pack.v1"

	ClassUnverified               = "unverified"
	ClassHashConformant           = "hash_conformant"
	ClassCryptoConformantAdvisory = "crypto_conformant_advisory"
	ClassHELMBoundAdvisory        = "helm_bound_advisory"
)

type TrustedKeySet map[string]ed25519.PublicKey

type TrustedKey struct {
	KeyID        string `json:"key_id"`
	PublicKeyHex string `json:"public_key_hex"`
}

type VerifyOptions struct {
	AllowRedactionFailures  bool
	AllowBundleDisclosedKey bool
}

type AgentProvenanceReport struct {
	Verified             bool      `json:"verified"`
	PackID               string    `json:"pack_id"`
	RootHash             string    `json:"root_hash"`
	CaptureProfile       string    `json:"capture_profile"`
	SignerKeyID          string    `json:"signer_key_id,omitempty"`
	Classification       string    `json:"classification"`
	SignatureValid       bool      `json:"signature_valid"`
	TrustedSigner        bool      `json:"trusted_signer"`
	HashesValid          bool      `json:"hashes_valid"`
	RedactionValid       bool      `json:"redaction_valid"`
	AgentRunReceiptValid bool      `json:"agent_run_receipt_valid,omitempty"`
	HELMBound            bool      `json:"helm_bound"`
	Sessions             int       `json:"sessions"`
	Turns                int       `json:"turns"`
	ToolInvocations      int       `json:"tool_invocations"`
	CodeEffects          int       `json:"code_effects"`
	CommitBindings       int       `json:"commit_bindings"`
	ValidationBindings   int       `json:"validation_bindings"`
	Limitations          []string  `json:"limitations"`
	Checks               []Check   `json:"checks"`
	VerifiedAt           time.Time `json:"verified_at"`
}

type Check struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type manifestObject struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
	Hash string `json:"hash"`
	Size int64  `json:"size"`
}

type manifest struct {
	Version         string           `json:"version"`
	PackID          string           `json:"pack_id"`
	RootHash        string           `json:"root_hash"`
	CaptureProfile  string           `json:"capture_profile"`
	CreatedAt       time.Time        `json:"created_at"`
	ObjectHashAlg   string           `json:"object_hash_alg"`
	CanonicalJSON   string           `json:"canonical_json"`
	Objects         []manifestObject `json:"objects"`
	RedactionReport manifestObject   `json:"redaction_report"`
	AgentRunReceipt *manifestObject  `json:"agent_run_receipt,omitempty"`
	Signing         signingMetadata  `json:"signing"`
	Limitations     []string         `json:"limitations"`
}

type signingMetadata struct {
	SignerKeyID  string    `json:"signer_key_id"`
	PublicKeyHex string    `json:"public_key_hex,omitempty"`
	SignatureHex string    `json:"signature_hex,omitempty"`
	SignedAt     time.Time `json:"signed_at,omitempty"`
}

type redactionReport struct {
	Version  string   `json:"version"`
	Status   string   `json:"status"`
	Profile  string   `json:"profile"`
	Failures []string `json:"failures,omitempty"`
}

func ParseTrustedKeysJSON(raw []byte) (TrustedKeySet, error) {
	var keyed map[string]string
	if err := json.Unmarshal(raw, &keyed); err == nil && len(keyed) > 0 {
		return trustedKeySetFromMap(keyed)
	}
	var wrapped struct {
		Keys []TrustedKey `json:"keys"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, fmt.Errorf("parse trusted keys: %w", err)
	}
	keyed = make(map[string]string, len(wrapped.Keys))
	for _, key := range wrapped.Keys {
		keyed[key.KeyID] = key.PublicKeyHex
	}
	return trustedKeySetFromMap(keyed)
}

func VerifyPack(path string, trustedKeys TrustedKeySet, opts VerifyOptions) (AgentProvenanceReport, error) {
	root := path
	info, err := os.Stat(path)
	if err != nil {
		return AgentProvenanceReport{}, err
	}
	if !info.IsDir() {
		root, cleanup, err := unpackTar(path)
		if err != nil {
			return AgentProvenanceReport{}, err
		}
		defer cleanup()
		return verifyPackDir(root, trustedKeys, opts)
	}
	return verifyPackDir(root, trustedKeys, opts)
}

func verifyPackDir(root string, trustedKeys TrustedKeySet, opts VerifyOptions) (AgentProvenanceReport, error) {
	raw, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		return AgentProvenanceReport{}, err
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return AgentProvenanceReport{}, err
	}
	report := AgentProvenanceReport{
		PackID:         m.PackID,
		RootHash:       m.RootHash,
		CaptureProfile: m.CaptureProfile,
		SignerKeyID:    m.Signing.SignerKeyID,
		Classification: ClassUnverified,
		Limitations: append([]string{
			"agent authoring provenance; advisory unless bound to HELM verdict receipts",
			"not an authorization boundary",
			"not HELM-native execution proof",
		}, m.Limitations...),
		VerifiedAt: time.Now().UTC(),
	}
	check := func(name string, pass bool, detail, reason string) {
		if pass {
			reason = ""
		} else {
			detail = ""
		}
		report.Checks = append(report.Checks, Check{Name: name, Pass: pass, Detail: detail, Reason: reason})
	}
	check("manifest:version", m.Version == PackVersion, m.Version, "unsupported manifest version")
	check("manifest:object_hash_alg", m.ObjectHashAlg == "sha256", m.ObjectHashAlg, "unsupported object hash algorithm")
	check("manifest:canonical_json", strings.HasPrefix(strings.ToLower(m.CanonicalJSON), "jcs"), m.CanonicalJSON, "expected JCS canonical JSON")
	check("manifest:capture_profile", validCaptureProfile(m.CaptureProfile), m.CaptureProfile, "unsupported capture profile")

	hashesOK := true
	for _, obj := range m.Objects {
		if err := verifyObject(root, obj); err != nil {
			hashesOK = false
			check("object:"+obj.Kind+":"+obj.Hash, false, "", err.Error())
		} else {
			check("object:"+obj.Kind+":"+obj.Hash, true, obj.Path, "")
		}
		switch obj.Kind {
		case "agent_session":
			report.Sessions++
		case "agent_turn":
			report.Turns++
		case "tool_invocation":
			report.ToolInvocations++
		case "code_effect":
			report.CodeEffects++
		case "commit_binding":
			report.CommitBindings++
		case "validation_binding":
			report.ValidationBindings++
		}
	}
	if err := verifyObject(root, m.RedactionReport); err != nil {
		hashesOK = false
		check("redaction_report:hash", false, "", err.Error())
	} else {
		check("redaction_report:hash", true, m.RedactionReport.Hash, "")
	}
	var receiptObj *manifestObject
	if m.AgentRunReceipt != nil {
		if err := verifyObject(root, *m.AgentRunReceipt); err != nil {
			hashesOK = false
			check("agent_run_receipt:hash", false, "", err.Error())
		} else {
			check("agent_run_receipt:hash", true, m.AgentRunReceipt.Hash, "")
			receiptObj = m.AgentRunReceipt
		}
	}
	rootHash, err := manifestRootHash(m.Objects, m.RedactionReport, receiptObj)
	if err != nil {
		hashesOK = false
		check("manifest:root_hash", false, "", err.Error())
	} else if rootHash != m.RootHash {
		hashesOK = false
		check("manifest:root_hash", false, rootHash, "root_hash mismatch")
	} else {
		check("manifest:root_hash", true, rootHash, "")
	}
	report.HashesValid = hashesOK

	redactionOK, reason := verifyRedaction(root, m.RedactionReport, opts)
	report.RedactionValid = redactionOK
	check("redaction_report:status", redactionOK, "", reason)

	key, trusted, keyReason := resolveKey(m, trustedKeys, opts)
	report.TrustedSigner = trusted
	if keyReason != "" {
		check("signature:key", false, "", keyReason)
	} else {
		check("signature:key", true, m.Signing.SignerKeyID, "")
	}
	if key != nil {
		payload, err := canonicalize.JCS(map[string]any{
			"pack_id":         m.PackID,
			"root_hash":       m.RootHash,
			"version":         PackVersion,
			"capture_profile": m.CaptureProfile,
		})
		if err != nil {
			check("signature:payload", false, "", err.Error())
		} else {
			sig, err := hex.DecodeString(m.Signing.SignatureHex)
			if err != nil {
				check("signature:ed25519", false, "", "signature must be hex")
			} else if !ed25519.Verify(key, payload, sig) {
				check("signature:ed25519", false, "", "signature verification failed")
			} else {
				report.SignatureValid = true
				check("signature:ed25519", true, "verified", "")
			}
		}
	}
	if m.AgentRunReceipt != nil {
		valid, bound, reason := verifyAgentRunReceipt(root, *m.AgentRunReceipt, trustedKeys)
		report.AgentRunReceiptValid = valid
		report.HELMBound = bound
		check("agent_run_receipt:signature", valid, "", reason)
	}
	report.Verified = report.HashesValid && report.RedactionValid && report.SignatureValid
	switch {
	case report.Verified && report.HELMBound:
		report.Classification = ClassHELMBoundAdvisory
	case report.Verified && report.TrustedSigner:
		report.Classification = ClassCryptoConformantAdvisory
	case report.HashesValid:
		report.Classification = ClassHashConformant
	default:
		report.Classification = ClassUnverified
	}
	return report, nil
}

func verifyObject(root string, obj manifestObject) error {
	if obj.Kind == "" || obj.Path == "" || obj.Hash == "" {
		return errors.New("object kind/path/hash required")
	}
	if !isSHA256(obj.Hash) {
		return fmt.Errorf("invalid sha256 hash %q", obj.Hash)
	}
	if strings.Contains(obj.Path, "..") || filepath.IsAbs(obj.Path) {
		return fmt.Errorf("unsafe object path %q", obj.Path)
	}
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(obj.Path)))
	if err != nil {
		return err
	}
	if int64(len(raw)) != obj.Size {
		return fmt.Errorf("size mismatch for %s", obj.Hash)
	}
	if hashBytes(raw) != obj.Hash {
		return fmt.Errorf("hash mismatch for %s", obj.Hash)
	}
	return nil
}

func verifyRedaction(root string, obj manifestObject, opts VerifyOptions) (bool, string) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(obj.Path)))
	if err != nil {
		return false, err.Error()
	}
	var report redactionReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return false, err.Error()
	}
	if report.Status == "redaction_failed" && !opts.AllowRedactionFailures {
		return false, "redaction failed"
	}
	if report.Version == "" {
		return false, "missing redaction report version"
	}
	return true, ""
}

func verifyAgentRunReceipt(root string, obj manifestObject, trustedKeys TrustedKeySet) (bool, bool, string) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(obj.Path)))
	if err != nil {
		return false, false, err.Error()
	}
	var receipt map[string]any
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return false, false, err.Error()
	}
	hashValue, _ := receipt["receipt_hash"].(string)
	signatureValue, _ := receipt["signature"].(string)
	keyID, _ := receipt["signer_key_id"].(string)
	if hashValue == "" || signatureValue == "" || keyID == "" {
		return false, false, "missing receipt_hash, signature, or signer_key_id"
	}
	unsigned := cloneMap(receipt)
	unsigned["receipt_hash"] = ""
	unsigned["signature"] = ""
	canonical, err := canonicalize.JCS(unsigned)
	if err != nil {
		return false, false, err.Error()
	}
	if hashBytes(canonical) != hashValue {
		return false, false, "receipt_hash mismatch"
	}
	key := trustedKeys[keyID]
	if key == nil {
		return false, false, "receipt signer is not trusted"
	}
	sig, err := hex.DecodeString(signatureValue)
	if err != nil || !ed25519.Verify(key, canonical, sig) {
		return false, false, "receipt signature verification failed"
	}
	bound := false
	if refs, ok := receipt["evidence_pack_refs"].([]any); ok {
		for _, ref := range refs {
			refString, _ := ref.(string)
			if isHELMBindingRef(refString) {
				bound = true
				break
			}
		}
	}
	return true, bound, ""
}

func resolveKey(m manifest, trustedKeys TrustedKeySet, opts VerifyOptions) (ed25519.PublicKey, bool, string) {
	if strings.TrimSpace(m.Signing.SignerKeyID) == "" {
		return nil, false, "missing signer_key_id"
	}
	if key := trustedKeys[m.Signing.SignerKeyID]; key != nil {
		return key, true, ""
	}
	if opts.AllowBundleDisclosedKey && m.Signing.PublicKeyHex != "" {
		raw, err := hex.DecodeString(m.Signing.PublicKeyHex)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, false, "invalid bundle-disclosed public key"
		}
		return ed25519.PublicKey(raw), false, ""
	}
	return nil, false, "signer key is not trusted"
}

func manifestRootHash(objects []manifestObject, redaction manifestObject, receipt *manifestObject) (string, error) {
	copied := append([]manifestObject{}, objects...)
	copied = append(copied, redaction)
	if receipt != nil {
		copied = append(copied, *receipt)
	}
	sort.Slice(copied, func(i, j int) bool {
		if copied[i].Kind != copied[j].Kind {
			return copied[i].Kind < copied[j].Kind
		}
		return copied[i].Hash < copied[j].Hash
	})
	root := struct {
		Version string           `json:"version"`
		Objects []manifestObject `json:"objects"`
	}{Version: PackVersion, Objects: copied}
	raw, err := canonicalize.JCS(root)
	if err != nil {
		return "", err
	}
	return hashBytes(raw), nil
}

func trustedKeySetFromMap(values map[string]string) (TrustedKeySet, error) {
	out := make(TrustedKeySet, len(values))
	for keyID, publicKeyHex := range values {
		keyID = strings.TrimSpace(keyID)
		if keyID == "" {
			return nil, errors.New("trusted key_id is required")
		}
		keyBytes, err := hex.DecodeString(strings.TrimSpace(publicKeyHex))
		if err != nil {
			return nil, fmt.Errorf("decode trusted key %s: %w", keyID, err)
		}
		if len(keyBytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("trusted key %s must be %d bytes", keyID, ed25519.PublicKeySize)
		}
		out[keyID] = ed25519.PublicKey(keyBytes)
	}
	if len(out) == 0 {
		return nil, errors.New("trusted keys are required")
	}
	return out, nil
}

func unpackTar(path string) (string, func(), error) {
	f, err := os.Open(path)
	if err != nil {
		return "", func() {}, err
	}
	defer f.Close()
	tmp, err := os.MkdirTemp("", "agent-provenance-pack-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }
	tr := tar.NewReader(f)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			cleanup()
			return "", func() {}, err
		}
		if header.FileInfo().IsDir() {
			continue
		}
		if strings.Contains(header.Name, "..") || filepath.IsAbs(header.Name) {
			cleanup()
			return "", func() {}, fmt.Errorf("unsafe tar path %q", header.Name)
		}
		dest := filepath.Join(tmp, filepath.FromSlash(header.Name))
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			cleanup()
			return "", func() {}, err
		}
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644)
		if err != nil {
			cleanup()
			return "", func() {}, err
		}
		if _, err := io.Copy(out, tr); err != nil {
			_ = out.Close()
			cleanup()
			return "", func() {}, err
		}
		_ = out.Close()
	}
	return tmp, cleanup, nil
}

func validCaptureProfile(profile string) bool {
	switch profile {
	case "hash_only", "local_minimized", "dev_raw":
		return true
	default:
		return false
	}
}

func isHELMBindingRef(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "agent-provenance://") {
		return false
	}
	return strings.HasPrefix(ref, "evidence://") ||
		strings.HasPrefix(ref, "evidence-pack://") ||
		strings.HasPrefix(ref, "helm-receipt://") ||
		strings.HasPrefix(ref, "proofgraph://")
}

func isSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func hashBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
