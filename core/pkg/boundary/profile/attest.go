package profile

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

const (
	// PostureAttestationSchemaVersion identifies the posture attestation
	// record format.
	PostureAttestationSchemaVersion = "posture_attestation.v1"

	// VerdictMatch means every live posture check passed against the
	// compiled expectations. Anything else is VerdictDrift.
	VerdictMatch = "MATCH"
	VerdictDrift = "DRIFT"

	CheckPass = "PASS"
	CheckFail = "FAIL"
)

// PostureCheck is one live-vs-expected comparison. FAIL rows ARE the drift
// diff: expected and observed carry both sides. Target and Property are
// deliberately free-form strings so the record family stays substrate-neutral.
type PostureCheck struct {
	Target   string `json:"target"`
	Property string `json:"property"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
	Result   string `json:"result"`
}

// PostureAttestation is the proof object of one live posture read: at
// ObservedAt, the OS posture either matched the compiled artifact set bound
// by ReceiptHash (MATCH) or diverged (DRIFT, with the diff in Checks). It is
// always hash-sealed; a signature is attached when a signer is configured.
type PostureAttestation struct {
	SchemaVersion string         `json:"schema_version"`
	AttestationID string         `json:"attestation_id"`
	ReceiptID     string         `json:"receipt_id"`
	ReceiptHash   string         `json:"receipt_hash"`
	ProfileID     string         `json:"profile_id"`
	ModeTier      string         `json:"mode_tier"`
	Verdict       string         `json:"verdict"`
	Checks        []PostureCheck `json:"checks"`
	ObservedAt    string         `json:"observed_at"`
	SignerKeyID   string         `json:"signer_key_id,omitempty"`
	RecordHash    string         `json:"record_hash"`
	Signature     string         `json:"signature,omitempty"`
}

// AttestOptions carries the non-posture inputs of an attest run. ObservedAt
// is injected so canonical bytes never depend on wall clock in this package.
type AttestOptions struct {
	ObservedAt    time.Time
	AttestationID string
}

// Attest reads the live OS posture through the prober and compares it against
// the compile receipt's artifact set. Fail-closed properties:
//
//   - Artifacts on disk that do not hash to the receipt's artifact set are a
//     hard error (tamper), not a DRIFT verdict.
//   - A probe error yields a DRIFT-verdict attestation with the failure
//     recorded AND a non-nil error — an unreadable OS never attests MATCH.
//   - The verdict is MATCH only when every check passes.
func Attest(receipt CompileReceipt, files map[string][]byte, prober Prober, signer crypto.Signer, opts AttestOptions) (PostureAttestation, error) {
	if err := validateCompileReceiptShape(receipt, true); err != nil {
		return PostureAttestation{}, err
	}
	if opts.ObservedAt.IsZero() {
		return PostureAttestation{}, errors.New("attest requires an explicit observed-at time")
	}
	if prober.SystemdProps == nil || prober.NftRuleset == nil || prober.CgroupLimits == nil {
		return PostureAttestation{}, errors.New("attest requires a fully wired prober")
	}
	_, setHash, err := ArtifactSetHash(files)
	if err != nil {
		return PostureAttestation{}, err
	}
	if !constantEqual(setHash, receipt.ArtifactSetHash) {
		return PostureAttestation{}, fmt.Errorf("artifact set on disk (%s) does not match the compile receipt (%s): artifacts were modified after compile", setHash, receipt.ArtifactSetHash)
	}
	postureBytes, ok := files[posturePath]
	if !ok {
		return PostureAttestation{}, fmt.Errorf("artifact set is missing %s", posturePath)
	}
	var expected ExpectedPosture
	if err := json.Unmarshal(postureBytes, &expected); err != nil {
		return PostureAttestation{}, fmt.Errorf("parse expected posture: %w", err)
	}
	if expected.SchemaVersion != ExpectedPostureSchemaVersion {
		return PostureAttestation{}, fmt.Errorf("expected posture schema_version must be %q", ExpectedPostureSchemaVersion)
	}

	var checks []PostureCheck
	var probeErrs []error

	for _, unit := range sortedKeys(expected.Systemd) {
		props := expected.Systemd[unit]
		names := sortedKeys(props)
		observed, err := prober.SystemdProps(unit, names)
		if err != nil {
			probeErrs = append(probeErrs, err)
			checks = append(checks, probeFailure("systemd:"+unit, err))
			continue
		}
		for _, name := range names {
			checks = append(checks, compareCheck("systemd:"+unit, name, props[name], normalizeObservedSystemdValue(name, observed[name])))
		}
	}

	observedRuleset, err := prober.NftRuleset(expected.Nftables.Table)
	if err != nil {
		probeErrs = append(probeErrs, err)
		checks = append(checks, probeFailure("nftables", err))
	} else {
		observedHash := canonicalize.ComputeArtifactHash([]byte(NormalizeNftRuleset(observedRuleset)))
		checks = append(checks, compareCheck("nftables", "ruleset_sha256", expected.Nftables.RulesetSHA256, observedHash))
	}

	for _, unit := range sortedKeys(expected.Cgroup) {
		limits := expected.Cgroup[unit]
		names := sortedKeys(limits)
		observed, err := prober.CgroupLimits(unit, names)
		if err != nil {
			probeErrs = append(probeErrs, err)
			checks = append(checks, probeFailure("cgroup:"+unit, err))
			continue
		}
		for _, name := range names {
			checks = append(checks, compareCheck("cgroup:"+unit, name, limits[name], observed[name]))
		}
	}

	verdict := VerdictMatch
	for _, check := range checks {
		if check.Result != CheckPass {
			verdict = VerdictDrift
			break
		}
	}

	attestationID := opts.AttestationID
	if attestationID == "" {
		seed := canonicalize.ComputeArtifactHash([]byte(receipt.RecordHash + "|" + opts.ObservedAt.UTC().Format(time.RFC3339Nano)))
		attestationID = "pa-" + strings.TrimPrefix(seed, "sha256:")[:12]
	}
	attestation := PostureAttestation{
		SchemaVersion: PostureAttestationSchemaVersion,
		AttestationID: attestationID,
		ReceiptID:     receipt.ReceiptID,
		ReceiptHash:   receipt.RecordHash,
		ProfileID:     receipt.ProfileID,
		ModeTier:      receipt.ModeTier,
		Verdict:       verdict,
		Checks:        checks,
		ObservedAt:    opts.ObservedAt.UTC().Format(time.RFC3339Nano),
	}
	sealed, err := SealPostureAttestation(attestation, signer)
	if err != nil {
		return PostureAttestation{}, err
	}
	if len(probeErrs) > 0 {
		return sealed, fmt.Errorf("posture probe failed (attestation records DRIFT): %w", errors.Join(probeErrs...))
	}
	return sealed, nil
}

// GateDispatch is the single fail-closed predicate over live posture:
// anything that is not a hash-sealed MATCH gates closed. Slice A wires no
// server-side call site — on the reference appliance the OS itself refuses
// (the gateway unit hard-requires a successful attest oneshot) — so this
// function exists for tests and for future gateway integration only. It must
// never be bypassed with a default-open wrapper.
//
// Integration contract for that future wiring: a record hash is integrity,
// NOT authenticity. A caller gating on a DESERIALIZED attestation (rather
// than one computed in-process from a Prober) must first require a signature
// and VerifyPostureAttestation against a trusted public key — an
// unauthenticated hash-sealed record is forgeable by whoever supplies it.
func GateDispatch(attestation PostureAttestation) bool {
	return attestation.RecordHash != "" && attestation.Verdict == VerdictMatch
}

// PostureAttestationSigningBytes is the RFC 8785 payload sealed (and, when a
// signer is configured, signed). RecordHash and Signature are excluded to
// avoid self-reference.
func PostureAttestationSigningBytes(attestation PostureAttestation) ([]byte, error) {
	attestation.RecordHash = ""
	attestation.Signature = ""
	if err := validatePostureAttestationShape(attestation, false); err != nil {
		return nil, err
	}
	return canonicalize.JCS(attestation)
}

// SealPostureAttestation hash-seals the record and, when signer is non-nil,
// signs it. DRIFT attestations are sealed exactly like MATCH ones — drift is
// evidence, and evidence gets receipts.
func SealPostureAttestation(attestation PostureAttestation, signer crypto.Signer) (PostureAttestation, error) {
	if signer != nil && attestation.SignerKeyID == "" {
		attestation.SignerKeyID = signerKeyID(signer)
	}
	payload, err := PostureAttestationSigningBytes(attestation)
	if err != nil {
		return PostureAttestation{}, err
	}
	attestation.RecordHash = canonicalize.ComputeArtifactHash(payload)
	if signer != nil {
		sigHex, err := signer.Sign(payload)
		if err != nil {
			return PostureAttestation{}, fmt.Errorf("sign posture attestation: %w", err)
		}
		attestation.Signature = "ed25519:" + sigHex
	}
	if err := validatePostureAttestationShape(attestation, true); err != nil {
		return PostureAttestation{}, err
	}
	return attestation, nil
}

// VerifyPostureAttestation proves content integrity offline: the record hash
// always, and the Ed25519 signature whenever one is attached (publicKey is
// then required). An unsigned record verifies as hash-sealed only.
func VerifyPostureAttestation(attestation PostureAttestation, publicKey ed25519.PublicKey) error {
	if err := validatePostureAttestationShape(attestation, true); err != nil {
		return err
	}
	payload, err := PostureAttestationSigningBytes(attestation)
	if err != nil {
		return err
	}
	if !constantEqual(attestation.RecordHash, canonicalize.ComputeArtifactHash(payload)) {
		return errors.New("posture attestation record hash mismatch")
	}
	if attestation.Signature == "" {
		return nil
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("posture attestation public key has invalid size")
	}
	signature, err := parseRecordSignature(attestation.Signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("posture attestation signature verification failed")
	}
	return nil
}

func validatePostureAttestationShape(attestation PostureAttestation, sealed bool) error {
	if attestation.SchemaVersion != PostureAttestationSchemaVersion {
		return fmt.Errorf("posture attestation schema_version must be %q", PostureAttestationSchemaVersion)
	}
	if attestation.AttestationID == "" || attestation.ReceiptID == "" {
		return errors.New("posture attestation identity is incomplete")
	}
	if !validSHA256.MatchString(attestation.ReceiptHash) {
		return errors.New("posture attestation receipt_hash is invalid")
	}
	if !validProfileID.MatchString(attestation.ProfileID) {
		return errors.New("posture attestation profile_id is invalid")
	}
	switch attestation.ModeTier {
	case TierObserve, TierEnforce:
	default:
		return errors.New("posture attestation mode_tier is invalid")
	}
	if len(attestation.Checks) == 0 {
		return errors.New("posture attestation must carry at least one check")
	}
	failCount := 0
	for _, check := range attestation.Checks {
		if check.Target == "" || check.Property == "" {
			return errors.New("posture attestation check target/property must be set")
		}
		switch check.Result {
		case CheckPass:
		case CheckFail:
			failCount++
		default:
			return fmt.Errorf("posture attestation check result %q is invalid", check.Result)
		}
	}
	switch attestation.Verdict {
	case VerdictMatch:
		if failCount != 0 {
			return errors.New("MATCH attestation cannot carry failed checks")
		}
	case VerdictDrift:
		if failCount == 0 {
			return errors.New("DRIFT attestation must carry at least one failed check")
		}
	default:
		return fmt.Errorf("posture attestation verdict %q is invalid", attestation.Verdict)
	}
	if _, err := time.Parse(time.RFC3339Nano, attestation.ObservedAt); err != nil {
		return errors.New("posture attestation observed_at must be RFC3339")
	}
	if sealed {
		if !validSHA256.MatchString(attestation.RecordHash) {
			return errors.New("posture attestation record hash is invalid")
		}
		if attestation.Signature != "" {
			if attestation.SignerKeyID == "" {
				return errors.New("signed posture attestation must carry signer_key_id")
			}
			if _, err := parseRecordSignature(attestation.Signature); err != nil {
				return err
			}
		}
	} else if attestation.RecordHash != "" || attestation.Signature != "" {
		return errors.New("unsealed posture attestation cannot carry hash or signature")
	}
	return nil
}

// normalizeObservedSystemdValue reconciles systemd's reported forms with the
// compiled expectations. Single-address IPAddressAllow/Deny values come back
// with explicit /32 (v4) or /128 (v6) prefixes on some systemd versions.
// ponytail: suffix-strip normalization; extend from recorded fixtures if a
// target systemd renders differently.
func normalizeObservedSystemdValue(property, value string) string {
	value = strings.TrimSpace(value)
	if property != "IPAddressAllow" && property != "IPAddressDeny" {
		return value
	}
	tokens := strings.Fields(value)
	for i, token := range tokens {
		tokens[i] = strings.TrimSuffix(strings.TrimSuffix(token, "/32"), "/128")
	}
	return strings.Join(tokens, " ")
}

func compareCheck(target, property, expected, observed string) PostureCheck {
	result := CheckFail
	if expected == observed {
		result = CheckPass
	}
	return PostureCheck{Target: target, Property: property, Expected: expected, Observed: observed, Result: result}
}

func probeFailure(target string, err error) PostureCheck {
	return PostureCheck{Target: target, Property: "probe", Expected: "readable", Observed: err.Error(), Result: CheckFail}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
