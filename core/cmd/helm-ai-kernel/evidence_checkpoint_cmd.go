package main

// quantum_posture: offline contract tooling for classical Ed25519 DSSE only;
// no private keys, signing, trust discovery or provider operations.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
)

const checkpointCLIUsage = "Usage: helm-ai-kernel evidence checkpoint <prepare|assemble|verify> [flags]"

func runEvidenceCheckpoint(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, checkpointCLIUsage)
		return 2
	}
	switch args[0] {
	case "prepare":
		return runEvidenceCheckpointPrepare(args[1:], stdout, stderr)
	case "assemble":
		return runEvidenceCheckpointAssemble(args[1:], stdout, stderr)
	case "verify":
		return runEvidenceCheckpointVerify(args[1:], stdout, stderr)
	case "help", "--help", "-h":
		fmt.Fprintln(stdout, checkpointCLIUsage)
		fmt.Fprintln(stdout, "Offline contract tooling only. No capture, signing, custody or restore authority.")
		return 0
	default:
		return checkpointCLIError(stderr, 2, "unknown checkpoint subcommand")
	}
}

func runEvidenceCheckpointPrepare(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("evidence checkpoint prepare", flag.ContinueOnError)
	descriptor := cmd.String("descriptor", "", "Bounded local descriptor JSON file")
	format := cmd.String("emit", "bundle", "Output: bundle (JSON), payload (exact bytes), or pae (exact signing bytes)")
	if code := checkpointCLIParse(cmd, args, stdout, stderr); code >= 0 {
		return code
	}
	if *descriptor == "" || *format != "bundle" && *format != "payload" && *format != "pae" {
		return checkpointCLIError(stderr, 2, "--descriptor and a supported --emit are required")
	}
	raw, err := checkpointCLIRead(*descriptor, contracts.RecoveryCheckpointMaxPayloadBytes)
	if err != nil {
		return checkpointCLIError(stderr, 1, "cannot read bounded local descriptor")
	}
	d, err := contracts.DecodeRecoveryCheckpoint(raw)
	if err != nil {
		return checkpointCLIError(stderr, 1, "descriptor refused")
	}
	payload, err := contracts.EncodeRecoveryCheckpoint(d)
	if err != nil {
		return checkpointCLIError(stderr, 1, "descriptor construction refused")
	}
	pae, err := evidencepkg.RecoveryCheckpointPAE(payload)
	if err != nil {
		return checkpointCLIError(stderr, 1, "signing preimage refused")
	}
	switch *format {
	case "payload":
		_, err = stdout.Write(payload)
	case "pae":
		_, err = stdout.Write(pae)
	default:
		err = json.NewEncoder(stdout).Encode(struct {
			PayloadType      string `json:"payload_type"`
			Purpose          string `json:"purpose"`
			PayloadBase64    string `json:"payload_base64"`
			PAEBase64        string `json:"pae_base64"`
			DescriptorDigest string `json:"descriptor_digest"`
		}{contracts.RecoveryCheckpointPayloadType, contracts.RecoveryCheckpointPurpose,
			base64.StdEncoding.EncodeToString(payload), base64.StdEncoding.EncodeToString(pae), contracts.RecoveryCheckpointHash(payload)})
	}
	if err != nil {
		return checkpointCLIError(stderr, 1, "cannot write prepared public material")
	}
	return 0
}

func runEvidenceCheckpointAssemble(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("evidence checkpoint assemble", flag.ContinueOnError)
	payloadPath := cmd.String("payload", "", "Local exact payload JSON bytes signed by the external signer")
	keyID := cmd.String("key-id", "", "Explicit public external signer key ID")
	signatureHex := cmd.String("signature-hex", "", "External 64-byte Ed25519 signature as lowercase hex; no private key")
	if code := checkpointCLIParse(cmd, args, stdout, stderr); code >= 0 {
		return code
	}
	if *payloadPath == "" || *keyID == "" || *signatureHex == "" {
		return checkpointCLIError(stderr, 2, "--payload, --key-id and --signature-hex are required")
	}
	payload, err := checkpointCLIRead(*payloadPath, contracts.RecoveryCheckpointMaxPayloadBytes)
	if err != nil {
		return checkpointCLIError(stderr, 1, "cannot read bounded local payload")
	}
	signature, err := checkpointCLIHex(*signatureHex, ed25519.SignatureSize)
	if err != nil {
		return checkpointCLIError(stderr, 1, "signature encoding refused")
	}
	envelope, err := evidencepkg.NewRecoveryCheckpointEnvelope(payload, *keyID, signature)
	if err != nil {
		return checkpointCLIError(stderr, 1, "envelope assembly refused")
	}
	// Assembly preserves supplied bytes. It makes no signature-validity claim.
	if _, err := stdout.Write(envelope); err != nil {
		return checkpointCLIError(stderr, 1, "cannot write assembled envelope")
	}
	return 0
}

func runEvidenceCheckpointVerify(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("evidence checkpoint verify", flag.ContinueOnError)
	envelopePath := cmd.String("envelope", "", "Bounded local DSSE envelope JSON file")
	expectedPath := cmd.String("expected", "", "Independent trusted descriptor context; never copied from the envelope")
	publicKeyHex := cmd.String("public-key-hex", "", "Independently pinned 32-byte Ed25519 public key as lowercase hex")
	keyID := cmd.String("key-id", "", "Independently pinned key ID")
	purpose := cmd.String("purpose", "", "Independently pinned purpose")
	payloadType := cmd.String("payload-type", "", "Independently pinned DSSE payload type")
	validFrom := cmd.String("valid-from-unix", "", "Trusted key validity start; unsigned decimal seconds")
	validUntil := cmd.String("valid-until-unix", "", "Trusted key validity end; unsigned decimal seconds")
	verifyAt := cmd.String("verify-at-unix", "", "Independent historical verification instant; no clock read")
	revoked := cmd.Bool("revoked", false, "Explicit trusted revocation decision; --revoked=false is required for a usable key")
	frozen := cmd.String("frozen-envelope-digest", "", "Previously frozen exact envelope digest for replay verification")
	contentPath := cmd.String("content", "", "Optional bounded local private snapshot bytes; only hash/length are checked")
	if code := checkpointCLIParse(cmd, args, stdout, stderr); code >= 0 {
		return code
	}
	provided := make(map[string]bool)
	cmd.Visit(func(f *flag.Flag) { provided[f.Name] = true })
	for _, name := range []string{"envelope", "expected", "public-key-hex", "key-id", "purpose", "payload-type", "valid-from-unix", "valid-until-unix", "verify-at-unix", "revoked"} {
		if !provided[name] || cmd.Lookup(name).Value.String() == "" {
			return checkpointCLIError(stderr, 2, "all independent trust, expected-context and validity/revocation flags are required")
		}
	}
	pub, err := checkpointCLIHex(*publicKeyHex, ed25519.PublicKeySize)
	if err != nil {
		return checkpointCLIError(stderr, 2, "pinned public key encoding refused")
	}
	from, errFrom := checkpointCLIUint(*validFrom)
	until, errUntil := checkpointCLIUint(*validUntil)
	at, errAt := checkpointCLIUint(*verifyAt)
	if errFrom != nil || errUntil != nil || errAt != nil {
		return checkpointCLIError(stderr, 2, "validity context requires bounded canonical unsigned decimal integers")
	}
	expectedRaw, err := checkpointCLIRead(*expectedPath, contracts.RecoveryCheckpointMaxPayloadBytes)
	if err != nil {
		return checkpointCLIError(stderr, 1, "cannot read bounded independent expected context")
	}
	expected, err := contracts.DecodeRecoveryCheckpoint(expectedRaw)
	if err != nil {
		return checkpointCLIError(stderr, 1, "independent expected context refused")
	}
	envelope, err := checkpointCLIRead(*envelopePath, contracts.RecoveryCheckpointMaxEnvelopeBytes)
	if err != nil {
		return checkpointCLIError(stderr, 1, "cannot read bounded local envelope")
	}
	verified, err := evidencepkg.VerifyRecoveryCheckpointEnvelope(envelope, evidencepkg.RecoveryCheckpointVerificationPolicy{
		KeyID: *keyID, PublicKey: ed25519.PublicKey(pub), Purpose: *purpose, PayloadType: *payloadType,
		Expected: expected, ValidFromUnix: from, ValidUntilUnix: until, VerifyAtUnix: at,
		Revoked: *revoked, FrozenEnvelopeDigest: *frozen,
	})
	if err != nil {
		return checkpointCLIError(stderr, 1, "signature or independently pinned context refused")
	}
	scope := "signed_descriptor_only"
	if provided["content"] {
		content, err := checkpointCLIRead(*contentPath, contracts.RecoveryCheckpointMaxContentBytes)
		if err != nil || contracts.VerifyRecoveryCheckpointContent(verified.Descriptor, content) != nil {
			return checkpointCLIError(stderr, 1, "supplied private content refused")
		}
		scope = "signed_descriptor_and_supplied_content"
	}
	// Do not export private bytes, local paths, keys or inferred trust claims.
	if err := json.NewEncoder(stdout).Encode(struct {
		Scope                  string `json:"verification_scope"`
		DescriptorDigest       string `json:"descriptor_digest"`
		EnvelopeDigest         string `json:"envelope_digest"`
		DeclaredSnapshotDigest string `json:"declared_snapshot_digest"`
	}{scope, verified.DescriptorDigest, verified.EnvelopeDigest, verified.SnapshotDigest}); err != nil {
		return checkpointCLIError(stderr, 1, "cannot write verification result")
	}
	return 0
}

// Reject duplicate/unknown flags and positional input; errors never echo caller
// values, paths or file contents. JSON inputs use the closed contract codecs.
func checkpointCLIParse(cmd *flag.FlagSet, args []string, stdout, stderr io.Writer) int {
	cmd.SetOutput(io.Discard)
	seen := make(map[string]bool)
	for i := 0; i < len(args); i++ {
		name, hasValue := strings.CutPrefix(args[i], "-")
		if !hasValue {
			return checkpointCLIError(stderr, 2, "positional checkpoint input is not supported")
		}
		name = strings.TrimPrefix(name, "-")
		name, _, inline := strings.Cut(name, "=")
		if name == "h" || name == "help" {
			fmt.Fprintf(stdout, "Usage: helm-ai-kernel %s [flags]\n", cmd.Name())
			cmd.SetOutput(stdout)
			cmd.PrintDefaults()
			return 0
		}
		f := cmd.Lookup(name)
		if f == nil || seen[name] {
			return checkpointCLIError(stderr, 2, "unknown or duplicate checkpoint flag")
		}
		seen[name] = true
		boolean, isBool := f.Value.(interface{ IsBoolFlag() bool })
		if !inline && (!isBool || !boolean.IsBoolFlag()) {
			i++
		}
	}
	if err := cmd.Parse(args); err != nil || cmd.NArg() != 0 {
		return checkpointCLIError(stderr, 2, "invalid checkpoint flags")
	}
	return -1
}

func checkpointCLIRead(path string, limit int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > int64(limit) {
		return nil, errors.New("bounded local file required")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("local file unavailable")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil || len(raw) > limit {
		return nil, errors.New("local input exceeds bound or cannot be read")
	}
	return raw, nil
}

func checkpointCLIHex(value string, size int) ([]byte, error) {
	if len(value) != size*2 {
		return nil, errors.New("wrong hex length")
	}
	raw, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(raw) != value {
		return nil, errors.New("noncanonical hex")
	}
	return raw, nil
}

func checkpointCLIUint(value string) (uint64, error) {
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != value || n > contracts.RecoveryCheckpointMaxInteger {
		return 0, errors.New("noncanonical or out-of-range integer")
	}
	return n, nil
}

func checkpointCLIError(stderr io.Writer, code int, message string) int {
	fmt.Fprintf(stderr, "Error: %s\n", message)
	return code
}
