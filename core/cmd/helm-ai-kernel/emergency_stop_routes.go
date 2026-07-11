package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/api"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
)

const (
	emergencyStopFencePath            = "/internal/emergency-stop/fence"
	emergencyStopFenceEnabledEnv      = "HELM_EMERGENCY_STOP_FENCE_ENABLED"
	emergencyStopCommandAudienceEnv   = "HELM_EMERGENCY_STOP_COMMAND_AUDIENCE"
	emergencyStopCommandPublicKeysEnv = "HELM_EMERGENCY_STOP_COMMAND_PUBLIC_KEYS"
	emergencyStopFenceRequestMaxBytes = 64 << 10
	emergencyStopCommandMaxFutureSkew = time.Minute
)

type emergencyStopCommandVerifier struct {
	audience   string
	publicKeys map[string]ed25519.PublicKey
}

func emergencyStopFenceEnabled() bool {
	return envBool(emergencyStopFenceEnabledEnv)
}

// emergencyStopFenceEnvelope deliberately separates the control-plane command
// from its signature. The Kernel verifies the exact canonical command payload;
// no caller-controlled transport field is part of the authority proof.
type emergencyStopFenceEnvelope struct {
	Command   kernel.FenceCommand `json:"command"`
	Signature string              `json:"signature"`
}

// emergencyStopFenceResponse is a durable acknowledgement, not a promise of
// cancellation. The scope fence denies newly governed dispatches only; an
// in-flight cancellation/reconciliation protocol remains a separate contract.
type emergencyStopFenceResponse struct {
	ContractVersion string            `json:"contract_version"`
	Coverage        string            `json:"coverage"`
	State           kernel.FenceState `json:"state"`
	Replayed        bool              `json:"replayed"`
	KernelSignature string            `json:"kernel_signature"`
}

func registerEmergencyStopFenceRoutes(mux *http.ServeMux, svc *Services) {
	mux.HandleFunc("/internal/emergency-stop/fence", protectRuntimeHandler(RouteAuthService, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			api.WriteMethodNotAllowed(w)
			return
		}
		if svc == nil || svc.EmergencyStops == nil {
			api.WriteError(w, http.StatusServiceUnavailable, "Emergency stop unavailable", "scoped emergency-stop fence store is not initialized")
			return
		}
		if svc.ReceiptSigner == nil {
			api.WriteError(w, http.StatusServiceUnavailable, "Emergency stop unavailable", "kernel receipt signer is not initialized")
			return
		}
		acknowledgementIdentity, err := emergencyStopAcknowledgementIdentity(svc.ReceiptSigner)
		if err != nil {
			api.WriteError(w, http.StatusServiceUnavailable, "Emergency stop unavailable", "kernel acknowledgement signer is not an approved profile")
			return
		}

		commandVerifier, err := configuredEmergencyStopCommandVerifier()
		if err != nil {
			api.WriteError(w, http.StatusServiceUnavailable, "Emergency stop authority unavailable", "control-plane command verification is not configured")
			return
		}

		var envelope emergencyStopFenceEnvelope
		r.Body = http.MaxBytesReader(w, r.Body, emergencyStopFenceRequestMaxBytes)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&envelope); err != nil {
			api.WriteBadRequest(w, "Invalid emergency-stop command")
			return
		}
		if err := rejectTrailingJSON(decoder); err != nil {
			api.WriteBadRequest(w, "Invalid emergency-stop command")
			return
		}

		if err := verifyEmergencyStopFenceEnvelope(envelope, commandVerifier, time.Now().UTC()); err != nil {
			api.WriteForbidden(w, "Emergency-stop command verification failed")
			return
		}

		state, replayed, err := svc.EmergencyStops.Fence(r.Context(), envelope.Command, acknowledgementIdentity)
		if err != nil {
			switch {
			case errors.Is(err, kernel.ErrScopedStopInvalid):
				api.WriteBadRequest(w, "Invalid emergency-stop command")
			case errors.Is(err, kernel.ErrScopedStopStaleEpoch), errors.Is(err, kernel.ErrScopedStopConflict):
				api.WriteConflict(w, "Emergency-stop command conflicts with the active fence")
			default:
				api.WriteInternal(w, err)
			}
			return
		}

		acknowledgementPayload, err := state.AcknowledgementPayload()
		if err != nil {
			api.WriteInternal(w, fmt.Errorf("canonicalize emergency-stop acknowledgement: %w", err))
			return
		}
		kernelSignature, err := svc.ReceiptSigner.Sign(acknowledgementPayload)
		if err != nil {
			api.WriteInternal(w, fmt.Errorf("sign emergency-stop acknowledgement: %w", err))
			return
		}

		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Helm-Contract-Status", string(RouteContractInternal))
		if !replayed {
			w.WriteHeader(http.StatusCreated)
		}
		_ = json.NewEncoder(w).Encode(emergencyStopFenceResponse{
			ContractVersion: kernel.EmergencyStopFenceContractVersion,
			Coverage:        "new_governed_dispatches_only",
			State:           state,
			Replayed:        replayed,
			KernelSignature: kernelSignature,
		})
	}))
}

func emergencyStopAcknowledgementIdentity(signer helmcrypto.Signer) (kernel.AcknowledgementIdentity, error) {
	keyIDer, ok := signer.(interface{ GetKeyID() string })
	if !ok {
		return kernel.AcknowledgementIdentity{}, errors.New("kernel acknowledgement signer has no key id")
	}
	identity := kernel.AcknowledgementIdentity{
		KeyID:     keyIDer.GetKeyID(),
		PublicKey: signer.PublicKey(),
	}
	switch signer.(type) {
	case *helmcrypto.Ed25519Signer:
		identity.SignerProfile = kernel.EmergencyStopSignerClassical
	case *helmcrypto.HybridSigner:
		identity.SignerProfile = kernel.EmergencyStopSignerHybrid
	default:
		return kernel.AcknowledgementIdentity{}, errors.New("unsupported kernel acknowledgement signer profile")
	}
	return identity, nil
}

// configuredEmergencyStopCommandVerifier accepts a comma-separated keyring of
// key_id=hex-ed25519-public-key entries. Multiple entries are intentionally
// supported for an explicit overlap during CP signing-key rotation.
func configuredEmergencyStopCommandVerifier() (emergencyStopCommandVerifier, error) {
	audience := strings.TrimSpace(os.Getenv(emergencyStopCommandAudienceEnv))
	if audience == "" || len(audience) > 255 {
		return emergencyStopCommandVerifier{}, errors.New("emergency-stop command audience not configured")
	}
	raw := strings.TrimSpace(os.Getenv(emergencyStopCommandPublicKeysEnv))
	if raw == "" {
		return emergencyStopCommandVerifier{}, errors.New("emergency-stop command public keys not configured")
	}
	publicKeys := make(map[string]ed25519.PublicKey)
	for _, entry := range strings.Split(raw, ",") {
		parts := strings.SplitN(strings.TrimSpace(entry), "=", 2)
		if len(parts) != 2 {
			return emergencyStopCommandVerifier{}, errors.New("emergency-stop command keyring entry is invalid")
		}
		keyID := strings.TrimSpace(parts[0])
		if !validEmergencyStopCommandKeyID(keyID) {
			return emergencyStopCommandVerifier{}, errors.New("emergency-stop command key id is invalid")
		}
		decoded, err := hex.DecodeString(strings.TrimSpace(parts[1]))
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return emergencyStopCommandVerifier{}, errors.New("emergency-stop command public key is invalid")
		}
		if _, exists := publicKeys[keyID]; exists {
			return emergencyStopCommandVerifier{}, errors.New("emergency-stop command key id is duplicated")
		}
		publicKeys[keyID] = ed25519.PublicKey(decoded)
	}
	return emergencyStopCommandVerifier{audience: audience, publicKeys: publicKeys}, nil
}

func validEmergencyStopCommandKeyID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '.' && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

func verifyEmergencyStopFenceEnvelope(envelope emergencyStopFenceEnvelope, verifier emergencyStopCommandVerifier, now time.Time) error {
	payload, err := envelope.Command.CanonicalPayload()
	if err != nil {
		return err
	}
	if envelope.Command.Audience != verifier.audience {
		return errors.New("emergency-stop command audience does not match this Kernel")
	}
	commandPublicKey, ok := verifier.publicKeys[envelope.Command.KeyID]
	if !ok {
		return errors.New("emergency-stop command key is not trusted")
	}
	if !now.Before(envelope.Command.ExpiresAt.UTC()) {
		return errors.New("emergency-stop command expired")
	}
	if envelope.Command.IssuedAt.UTC().After(now.Add(emergencyStopCommandMaxFutureSkew)) {
		return errors.New("emergency-stop command issued too far in the future")
	}
	if !isLowerHex(envelope.Signature, ed25519.SignatureSize*2) {
		return errors.New("emergency-stop command signature must be lowercase hexadecimal")
	}
	signature, err := hex.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("emergency-stop command signature is invalid")
	}
	if !ed25519.Verify(commandPublicKey, payload, signature) {
		return errors.New("emergency-stop command signature does not verify")
	}
	return nil
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

func rejectTrailingJSON(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}
