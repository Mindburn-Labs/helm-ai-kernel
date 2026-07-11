// quantum_posture: catalog vectors cover raw Ed25519 FENCE commands and
// profile-bound acknowledgement identities; hybrid claims fail closed.
package kernel

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const emergencyStopCatalogVectorSHA256 = "78be0742665e8ec38b73c449f96d00ade9e2b86a52c8cdd4684703ba6912b51c"
const emergencyStopCatalogSourceCommit = "41fe649f336fe62067ad72663acef885762d5f7c"

type emergencyStopCatalogReferencePack struct {
	SchemaVersion    string `json:"schema_version"`
	Canonicalization struct {
		SafeIntegerMax uint64 `json:"safe_integer_max"`
	} `json:"canonicalization"`
	DeploymentKeyring struct {
		Keys map[string]struct {
			SignerProfile string `json:"kernel_signer_profile"`
			PublicKey     string `json:"kernel_public_key"`
		} `json:"keys"`
	} `json:"deployment_pinned_kernel_keyring"`
	Vectors []struct {
		ID              string       `json:"id"`
		Command         FenceCommand `json:"command"`
		CommandEnvelope struct {
			Signature string `json:"signature"`
		} `json:"command_envelope"`
		CommandCanonicalPayload string `json:"command_canonical_payload"`
		CommandSHA256           string `json:"command_sha256"`
		CommandPublicKey        string `json:"command_public_key"`
		Acknowledgement         struct {
			State           FenceState `json:"state"`
			KernelSignature string     `json:"kernel_signature"`
		} `json:"acknowledgement"`
		AcknowledgementCanonicalPayload string `json:"acknowledgement_canonical_payload"`
		AcknowledgementSHA256           string `json:"acknowledgement_sha256"`
	} `json:"vectors"`
	NegativeCases []struct {
		ID              string       `json:"id"`
		Kind            string       `json:"kind"`
		Command         FenceCommand `json:"command"`
		Signature       string       `json:"signature"`
		Acknowledgement struct {
			State FenceState `json:"state"`
		} `json:"acknowledgement"`
	} `json:"negative_cases"`
}

type emergencyStopCatalogSourceManifest struct {
	SourceRepository string `json:"source_repository"`
	SourceCommit     string `json:"source_commit"`
	SourcePath       string `json:"source_path"`
	SHA256           string `json:"sha256"`
}

func TestScopedStopCatalogReferencePack(t *testing.T) {
	packData, manifest := readEmergencyStopCatalogReferencePack(t)
	if manifest.SourceRepository != "Mindburn-Labs/contracts-catalog" || manifest.SourceCommit != emergencyStopCatalogSourceCommit || manifest.SourcePath != "schema/test-vectors/emergency_stop_fence.v1.json" || manifest.SHA256 != emergencyStopCatalogVectorSHA256 {
		t.Fatalf("unexpected emergency-stop reference source manifest: %+v", manifest)
	}
	sum := sha256.Sum256(packData)
	if actual := hex.EncodeToString(sum[:]); actual != manifest.SHA256 {
		t.Fatalf("reference vector SHA-256 = %s, manifest = %s", actual, manifest.SHA256)
	}

	var pack emergencyStopCatalogReferencePack
	if err := json.Unmarshal(packData, &pack); err != nil {
		t.Fatal(err)
	}
	if pack.SchemaVersion != "emergency-stop-fence.v1.test-vectors.v2" || pack.Canonicalization.SafeIntegerMax != EmergencyStopMaxEpoch {
		t.Fatalf("unexpected reference vector contract metadata: schema=%q safe_integer_max=%d", pack.SchemaVersion, pack.Canonicalization.SafeIntegerMax)
	}
	if len(pack.Vectors) < 3 {
		t.Fatalf("reference pack has %d positive vectors, want at least three", len(pack.Vectors))
	}

	for _, vector := range pack.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			commandPayload, err := vector.Command.CanonicalPayload()
			if err != nil {
				t.Fatalf("canonicalize FENCE command: %v", err)
			}
			if !bytes.Equal(commandPayload, []byte(vector.CommandCanonicalPayload)) {
				t.Fatalf("FENCE canonical payload drift:\n got: %s\nwant: %s", commandPayload, vector.CommandCanonicalPayload)
			}
			assertReferenceSHA256(t, commandPayload, vector.CommandSHA256)
			verifyReferenceEd25519(t, vector.CommandPublicKey, vector.CommandEnvelope.Signature, commandPayload)

			acknowledgementPayload, err := vector.Acknowledgement.State.AcknowledgementPayload()
			if err != nil {
				t.Fatalf("canonicalize FENCE_ACK: %v", err)
			}
			if !bytes.Equal(acknowledgementPayload, []byte(vector.AcknowledgementCanonicalPayload)) {
				t.Fatalf("FENCE_ACK canonical payload drift:\n got: %s\nwant: %s", acknowledgementPayload, vector.AcknowledgementCanonicalPayload)
			}
			assertReferenceSHA256(t, acknowledgementPayload, vector.AcknowledgementSHA256)
			if vector.Acknowledgement.State.ReceiptHash != vector.AcknowledgementSHA256 {
				t.Fatalf("receipt_hash = %q, want %q", vector.Acknowledgement.State.ReceiptHash, vector.AcknowledgementSHA256)
			}
			pinned, ok := pack.DeploymentKeyring.Keys[vector.Acknowledgement.State.AcknowledgementIdentity.KeyID]
			if !ok || pinned.SignerProfile != vector.Acknowledgement.State.AcknowledgementIdentity.SignerProfile || pinned.PublicKey != vector.Acknowledgement.State.AcknowledgementIdentity.PublicKey {
				t.Fatalf("FENCE_ACK signer identity is not an exact deployment-pinned keyring entry: state=%+v keyring=%+v", vector.Acknowledgement.State.AcknowledgementIdentity, pinned)
			}
			if vector.Acknowledgement.State.AcknowledgementIdentity.SignerProfile != EmergencyStopSignerClassical {
				t.Fatalf("reference pack positive vector %q needs a profile-aware verifier, got %q", vector.ID, vector.Acknowledgement.State.AcknowledgementIdentity.SignerProfile)
			}
			verifyReferenceEd25519(t, vector.Acknowledgement.State.AcknowledgementIdentity.PublicKey, vector.Acknowledgement.KernelSignature, acknowledgementPayload)
		})
	}

	for _, negative := range pack.NegativeCases {
		t.Run("negative/"+negative.ID, func(t *testing.T) {
			switch negative.Kind {
			case "command_semantics":
				if _, err := negative.Command.CanonicalPayload(); err == nil {
					t.Fatal("invalid command unexpectedly canonicalized")
				}
			case "envelope_lexical":
				if isLowerHex(negative.Signature, ed25519.SignatureSize*2) {
					t.Fatal("lexically invalid signature unexpectedly matched lowercase raw-hex profile")
				}
			case "ack_trust":
				identity := negative.Acknowledgement.State.AcknowledgementIdentity
				if negative.ID == "reject-unknown-kernel-signer-profile" {
					if _, err := identity.normalize(); err == nil {
						t.Fatal("unknown acknowledgement signer profile unexpectedly normalized")
					}
					return
				}
				if _, ok := pack.DeploymentKeyring.Keys[identity.KeyID]; ok {
					t.Fatalf("unbound acknowledgement key %q unexpectedly exists in pinned keyring", identity.KeyID)
				}
			default:
				t.Fatalf("unsupported negative vector kind %q", negative.Kind)
			}
		})
	}
}

func readEmergencyStopCatalogReferencePack(t *testing.T) ([]byte, emergencyStopCatalogSourceManifest) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate emergency-stop reference pack test")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	packData, err := os.ReadFile(filepath.Join(root, "reference_packs", "emergency_stop", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifestData, err := os.ReadFile(filepath.Join(root, "reference_packs", "emergency_stop", "SOURCE-MANIFEST.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest emergencyStopCatalogSourceManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	return packData, manifest
}

func assertReferenceSHA256(t *testing.T, payload []byte, expected string) {
	t.Helper()
	sum := sha256.Sum256(payload)
	if actual := "sha256:" + hex.EncodeToString(sum[:]); actual != expected {
		t.Fatalf("SHA-256 = %s, want %s", actual, expected)
	}
}

func verifyReferenceEd25519(t *testing.T, publicKeyHex, signatureHex string, payload []byte) {
	t.Helper()
	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		t.Fatalf("invalid reference Ed25519 public key %q: %v", publicKeyHex, err)
	}
	signature, err := hex.DecodeString(signatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize {
		t.Fatalf("invalid reference Ed25519 signature %q: %v", signatureHex, err)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), payload, signature) {
		t.Fatal("reference Ed25519 signature did not verify")
	}
}

func isLowerHex(value string, expectedLength int) bool {
	if len(value) != expectedLength {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
