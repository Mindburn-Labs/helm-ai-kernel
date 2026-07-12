// quantum_posture: tests cover raw Ed25519 command verification and
// fail-closed acknowledgement profile binding; they make no PQ guarantee.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"

	_ "modernc.org/sqlite"
)

func newEmergencyStopFenceRouteForTest(t *testing.T) (*http.ServeMux, *kernel.ScopedStopStore, ed25519.PrivateKey) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "emergency-stop.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := kernel.NewScopedStopStore(db, time.Now)
	if err := store.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	commandPublicKey, commandPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	receiptSigner, err := helmcrypto.NewEd25519Signer("kernel-stop-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(serviceAPIKeyEnv, "service-stop-test")
	t.Setenv(emergencyStopCommandAudienceEnv, "kernel-test")
	t.Setenv(emergencyStopCommandPublicKeysEnv, "cp-stop-test="+hex.EncodeToString(commandPublicKey))

	mux := http.NewServeMux()
	registerEmergencyStopFenceRoutes(mux, &Services{EmergencyStops: store, ReceiptSigner: receiptSigner})
	return mux, store, commandPrivateKey
}

func newEmergencyStopFenceCommand(now time.Time) kernel.FenceCommand {
	return kernel.FenceCommand{
		ContractVersion: kernel.EmergencyStopFenceContractVersion,
		Audience:        "kernel-test",
		KeyID:           "cp-stop-test",
		CommandID:       "stop-command-route-1",
		TenantID:        "tenant-a",
		WorkspaceID:     "workspace-a",
		Epoch:           1,
		ActorID:         "operator-a",
		Reason:          "containment",
		IssuedAt:        now.Add(-time.Second),
		ExpiresAt:       now.Add(5 * time.Minute),
	}
}

func emergencyStopAcknowledgementIdentityForTest() kernel.AcknowledgementIdentity {
	return kernel.AcknowledgementIdentity{
		KeyID:         "kernel-stop-test",
		SignerProfile: kernel.EmergencyStopSignerClassical,
		PublicKey:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
}

func signedEmergencyStopFenceEnvelope(t *testing.T, command kernel.FenceCommand, privateKey ed25519.PrivateKey) emergencyStopFenceEnvelope {
	t.Helper()
	payload, err := command.CanonicalPayload()
	if err != nil {
		t.Fatal(err)
	}
	return emergencyStopFenceEnvelope{
		Command:   command,
		Signature: hex.EncodeToString(ed25519.Sign(privateKey, payload)),
	}
}

func postEmergencyStopFence(t *testing.T, mux *http.ServeMux, payload any, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, emergencyStopFencePath, bytes.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestEmergencyStopFenceRoutePersistsSignedFenceAndReplays(t *testing.T) {
	mux, store, commandPrivateKey := newEmergencyStopFenceRouteForTest(t)
	command := newEmergencyStopFenceCommand(time.Now().UTC())
	envelope := signedEmergencyStopFenceEnvelope(t, command, commandPrivateKey)

	first := postEmergencyStopFence(t, mux, envelope, "service-stop-test")
	if first.Code != http.StatusCreated {
		t.Fatalf("first fence status = %d body=%s", first.Code, first.Body.String())
	}
	if first.Header().Get("X-Helm-Contract-Status") != string(RouteContractInternal) {
		t.Fatalf("contract status = %q", first.Header().Get("X-Helm-Contract-Status"))
	}
	if first.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache control = %q", first.Header().Get("Cache-Control"))
	}
	var created emergencyStopFenceResponse
	if err := json.Unmarshal(first.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ContractVersion != kernel.EmergencyStopFenceContractVersion || created.Coverage != "new_governed_dispatches_only" || created.Replayed {
		t.Fatalf("created acknowledgement = %+v", created)
	}
	if created.State.CommandID != command.CommandID || created.State.CommandHash == "" || created.State.ReceiptHash == "" || created.State.Audience != command.Audience || created.State.KeyID != command.KeyID || created.State.AcknowledgementIdentity.KeyID != "kernel-stop-test" || created.State.AcknowledgementIdentity.SignerProfile != kernel.EmergencyStopSignerClassical || created.State.AcknowledgementIdentity.PublicKey == "" {
		t.Fatalf("created state = %+v", created.State)
	}
	acknowledgementPayload, err := created.State.AcknowledgementPayload()
	if err != nil {
		t.Fatal(err)
	}
	valid, err := helmcrypto.Verify(created.State.AcknowledgementIdentity.PublicKey, created.KernelSignature, acknowledgementPayload)
	if err != nil || !valid {
		t.Fatalf("kernel acknowledgement signature valid=%t err=%v", valid, err)
	}
	active, fenced, err := store.IsFenced(context.Background(), command.Scope())
	if err != nil || !fenced || active.ReceiptHash != created.State.ReceiptHash {
		t.Fatalf("durable active fence=%t state=%+v err=%v", fenced, active, err)
	}

	replay := postEmergencyStopFence(t, mux, envelope, "service-stop-test")
	if replay.Code != http.StatusOK {
		t.Fatalf("replay fence status = %d body=%s", replay.Code, replay.Body.String())
	}
	var replayed emergencyStopFenceResponse
	if err := json.Unmarshal(replay.Body.Bytes(), &replayed); err != nil {
		t.Fatal(err)
	}
	if !replayed.Replayed || replayed.State.ReceiptHash != created.State.ReceiptHash || replayed.KernelSignature == "" {
		t.Fatalf("replay acknowledgement = %+v", replayed)
	}
}

func TestEmergencyStopFenceRouteFailsClosed(t *testing.T) {
	t.Run("missing service authentication", func(t *testing.T) {
		mux, store, commandPrivateKey := newEmergencyStopFenceRouteForTest(t)
		command := newEmergencyStopFenceCommand(time.Now().UTC())
		rec := postEmergencyStopFence(t, mux, signedEmergencyStopFenceEnvelope(t, command, commandPrivateKey), "")
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
		}
		if _, fenced, err := store.IsFenced(context.Background(), command.Scope()); err != nil || fenced {
			t.Fatalf("unauthenticated request mutated fence=%t err=%v", fenced, err)
		}
	})

	t.Run("missing command authority", func(t *testing.T) {
		mux, store, commandPrivateKey := newEmergencyStopFenceRouteForTest(t)
		t.Setenv(emergencyStopCommandPublicKeysEnv, "")
		command := newEmergencyStopFenceCommand(time.Now().UTC())
		rec := postEmergencyStopFence(t, mux, signedEmergencyStopFenceEnvelope(t, command, commandPrivateKey), "service-stop-test")
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
		}
		if _, fenced, err := store.IsFenced(context.Background(), command.Scope()); err != nil || fenced {
			t.Fatalf("unconfigured authority mutated fence=%t err=%v", fenced, err)
		}
	})

	t.Run("invalid signature and audience do not mutate state", func(t *testing.T) {
		mux, store, commandPrivateKey := newEmergencyStopFenceRouteForTest(t)
		command := newEmergencyStopFenceCommand(time.Now().UTC())
		invalid := signedEmergencyStopFenceEnvelope(t, command, commandPrivateKey)
		invalid.Signature = "00"
		if rec := postEmergencyStopFence(t, mux, invalid, "service-stop-test"); rec.Code != http.StatusForbidden {
			t.Fatalf("invalid signature status = %d body=%s", rec.Code, rec.Body.String())
		}
		uppercase := signedEmergencyStopFenceEnvelope(t, command, commandPrivateKey)
		uppercase.Signature = strings.ToUpper(uppercase.Signature)
		if rec := postEmergencyStopFence(t, mux, uppercase, "service-stop-test"); rec.Code != http.StatusForbidden {
			t.Fatalf("uppercase signature status = %d body=%s", rec.Code, rec.Body.String())
		}
		whitespace := signedEmergencyStopFenceEnvelope(t, command, commandPrivateKey)
		whitespace.Signature = " " + whitespace.Signature
		if rec := postEmergencyStopFence(t, mux, whitespace, "service-stop-test"); rec.Code != http.StatusForbidden {
			t.Fatalf("whitespace signature status = %d body=%s", rec.Code, rec.Body.String())
		}
		wrongAudience := command
		wrongAudience.Audience = "kernel-other"
		if rec := postEmergencyStopFence(t, mux, signedEmergencyStopFenceEnvelope(t, wrongAudience, commandPrivateKey), "service-stop-test"); rec.Code != http.StatusForbidden {
			t.Fatalf("wrong audience status = %d body=%s", rec.Code, rec.Body.String())
		}
		if _, fenced, err := store.IsFenced(context.Background(), command.Scope()); err != nil || fenced {
			t.Fatalf("invalid command mutated fence=%t err=%v", fenced, err)
		}
	})

	t.Run("same command id with a changed signed payload conflicts", func(t *testing.T) {
		mux, _, commandPrivateKey := newEmergencyStopFenceRouteForTest(t)
		command := newEmergencyStopFenceCommand(time.Now().UTC())
		if rec := postEmergencyStopFence(t, mux, signedEmergencyStopFenceEnvelope(t, command, commandPrivateKey), "service-stop-test"); rec.Code != http.StatusCreated {
			t.Fatalf("initial status = %d body=%s", rec.Code, rec.Body.String())
		}
		mutated := command
		mutated.Reason = "different reason"
		if rec := postEmergencyStopFence(t, mux, signedEmergencyStopFenceEnvelope(t, mutated, commandPrivateKey), "service-stop-test"); rec.Code != http.StatusConflict {
			t.Fatalf("mutated replay status = %d body=%s", rec.Code, rec.Body.String())
		}
	})

	t.Run("strict json rejects unknown fields", func(t *testing.T) {
		mux, _, commandPrivateKey := newEmergencyStopFenceRouteForTest(t)
		command := newEmergencyStopFenceCommand(time.Now().UTC())
		envelope := signedEmergencyStopFenceEnvelope(t, command, commandPrivateKey)
		body, err := json.Marshal(struct {
			Command   kernel.FenceCommand `json:"command"`
			Signature string              `json:"signature"`
			Extra     string              `json:"extra"`
		}{Command: envelope.Command, Signature: envelope.Signature, Extra: "rejected"})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, emergencyStopFencePath, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer service-stop-test")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("unknown-field status = %d body=%s", rec.Code, rec.Body.String())
		}
	})
}

func TestEmergencyStopFenceRouteAcceptsExplicitOverlappingKeyRotation(t *testing.T) {
	mux, _, _ := newEmergencyStopFenceRouteForTest(t)
	rotatedPublicKey, rotatedPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Replace the initial test keyring with a valid two-key overlap. The
	// original key does not need to be used in this test; the parser must retain
	// both configured identities and select the command's key_id exactly.
	initialPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	firstKey := "cp-stop-old=" + hex.EncodeToString(initialPublicKey)
	t.Setenv(emergencyStopCommandPublicKeysEnv, firstKey+",cp-stop-next="+hex.EncodeToString(rotatedPublicKey))
	command := newEmergencyStopFenceCommand(time.Now().UTC())
	command.KeyID = "cp-stop-next"
	command.CommandID = "stop-command-route-rotated"
	rec := postEmergencyStopFence(t, mux, signedEmergencyStopFenceEnvelope(t, command, rotatedPrivateKey), "service-stop-test")
	if rec.Code != http.StatusCreated {
		t.Fatalf("rotated key status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestEmergencyStopFenceRouteAcceptsExactPriorAudienceReplayAuthority(t *testing.T) {
	mux, _, currentPrivateKey := newEmergencyStopFenceRouteForTest(t)
	priorPublicKey, priorPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(emergencyStopCommandAudienceEnv, "kernel-current")
	t.Setenv(emergencyStopCommandPublicKeysEnv, "cp-current="+hex.EncodeToString(currentPrivateKey.Public().(ed25519.PublicKey)))
	t.Setenv(emergencyStopCommandReplayKeyringEnv, emergencyStopCommandReplayKeyringJSON(t, emergencyStopCommandReplayAuthority{
		CommandKeyID:     "cp-before-rotation",
		CommandAudience:  "kernel-before-rotation",
		CommandPublicKey: hex.EncodeToString(priorPublicKey),
	}))

	command := newEmergencyStopFenceCommand(time.Now().UTC())
	command.Audience = "kernel-before-rotation"
	command.KeyID = "cp-before-rotation"
	command.CommandID = "stop-command-prior-audience"
	rec := postEmergencyStopFence(t, mux, signedEmergencyStopFenceEnvelope(t, command, priorPrivateKey), "service-stop-test")
	if rec.Code != http.StatusCreated {
		t.Fatalf("prior-audience replay status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestEmergencyStopFenceRouteRejectsCurrentSignerForPriorAudience(t *testing.T) {
	mux, store, currentPrivateKey := newEmergencyStopFenceRouteForTest(t)
	priorPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(emergencyStopCommandAudienceEnv, "kernel-current")
	t.Setenv(emergencyStopCommandPublicKeysEnv, "cp-current="+hex.EncodeToString(currentPrivateKey.Public().(ed25519.PublicKey)))
	t.Setenv(emergencyStopCommandReplayKeyringEnv, emergencyStopCommandReplayKeyringJSON(t, emergencyStopCommandReplayAuthority{
		CommandKeyID:     "cp-before-rotation",
		CommandAudience:  "kernel-before-rotation",
		CommandPublicKey: hex.EncodeToString(priorPublicKey),
	}))

	command := newEmergencyStopFenceCommand(time.Now().UTC())
	command.Audience = "kernel-before-rotation"
	command.KeyID = "cp-current"
	command.CommandID = "stop-command-prior-audience-current-signer"
	rec := postEmergencyStopFence(t, mux, signedEmergencyStopFenceEnvelope(t, command, currentPrivateKey), "service-stop-test")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("current signer for prior audience status = %d body=%s", rec.Code, rec.Body.String())
	}
	if _, fenced, err := store.IsFenced(context.Background(), command.Scope()); err != nil || fenced {
		t.Fatalf("current signer for prior audience mutated fence=%t err=%v", fenced, err)
	}
}

func TestEmergencyStopFenceRouteRejectsUnconfiguredPriorAudience(t *testing.T) {
	mux, store, currentPrivateKey := newEmergencyStopFenceRouteForTest(t)
	_, priorPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(emergencyStopCommandAudienceEnv, "kernel-current")
	t.Setenv(emergencyStopCommandPublicKeysEnv, "cp-current="+hex.EncodeToString(currentPrivateKey.Public().(ed25519.PublicKey)))
	t.Setenv(emergencyStopCommandReplayKeyringEnv, "")

	command := newEmergencyStopFenceCommand(time.Now().UTC())
	command.Audience = "kernel-before-rotation"
	command.KeyID = "cp-before-rotation"
	command.CommandID = "stop-command-unconfigured-prior-audience"
	rec := postEmergencyStopFence(t, mux, signedEmergencyStopFenceEnvelope(t, command, priorPrivateKey), "service-stop-test")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unconfigured prior audience status = %d body=%s", rec.Code, rec.Body.String())
	}
	if _, fenced, err := store.IsFenced(context.Background(), command.Scope()); err != nil || fenced {
		t.Fatalf("unconfigured prior audience mutated fence=%t err=%v", fenced, err)
	}
}

func TestConfiguredEmergencyStopCommandVerifierRejectsMalformedOrConflictingReplayKeyring(t *testing.T) {
	currentPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	priorPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	currentPublicKeyHex := hex.EncodeToString(currentPublicKey)
	priorPublicKeyHex := hex.EncodeToString(priorPublicKey)
	t.Setenv(emergencyStopCommandAudienceEnv, "kernel-current")
	t.Setenv(emergencyStopCommandPublicKeysEnv, "cp-current="+currentPublicKeyHex)

	validPrior := emergencyStopCommandReplayKeyringJSON(t, emergencyStopCommandReplayAuthority{
		CommandKeyID:     "cp-before-rotation",
		CommandAudience:  "kernel-before-rotation",
		CommandPublicKey: priorPublicKeyHex,
	})
	duplicatePrior := emergencyStopCommandReplayKeyringJSON(t,
		emergencyStopCommandReplayAuthority{CommandKeyID: "cp-before-rotation", CommandAudience: "kernel-before-rotation", CommandPublicKey: priorPublicKeyHex},
		emergencyStopCommandReplayAuthority{CommandKeyID: "cp-before-rotation", CommandAudience: "kernel-before-rotation", CommandPublicKey: priorPublicKeyHex},
	)
	conflictingActive := emergencyStopCommandReplayKeyringJSON(t, emergencyStopCommandReplayAuthority{
		CommandKeyID:     "cp-current",
		CommandAudience:  "kernel-before-rotation",
		CommandPublicKey: currentPublicKeyHex,
	})
	tests := []struct {
		name    string
		keyring string
	}{
		{name: "malformed JSON", keyring: "{"},
		{name: "unknown field", keyring: strings.TrimSuffix(validPrior, "}") + `,"unexpected":true}`},
		{name: "unsupported version", keyring: strings.Replace(validPrior, emergencyStopCommandReplayKeyringVersion, "unsupported", 1)},
		{name: "uppercase public key", keyring: emergencyStopCommandReplayKeyringJSON(t, emergencyStopCommandReplayAuthority{CommandKeyID: "cp-before-rotation", CommandAudience: "kernel-before-rotation", CommandPublicKey: strings.Repeat("A", ed25519.PublicKeySize*2)})},
		{name: "duplicate key id", keyring: duplicatePrior},
		{name: "conflicting active authority", keyring: conflictingActive},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(emergencyStopCommandReplayKeyringEnv, tt.keyring)
			if _, err := configuredEmergencyStopCommandVerifier(); err == nil {
				t.Fatal("configured verifier unexpectedly accepted invalid replay keyring")
			}
		})
	}
}

func TestConfiguredEmergencyStopCommandVerifierAcceptsExactRedundantActiveReplayAuthority(t *testing.T) {
	currentPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	currentPublicKeyHex := hex.EncodeToString(currentPublicKey)
	t.Setenv(emergencyStopCommandAudienceEnv, "kernel-current")
	t.Setenv(emergencyStopCommandPublicKeysEnv, "cp-current="+currentPublicKeyHex)
	t.Setenv(emergencyStopCommandReplayKeyringEnv, emergencyStopCommandReplayKeyringJSON(t, emergencyStopCommandReplayAuthority{
		CommandKeyID:     "cp-current",
		CommandAudience:  "kernel-current",
		CommandPublicKey: currentPublicKeyHex,
	}))

	verifier, err := configuredEmergencyStopCommandVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if len(verifier.authorities) != 1 || !sameEmergencyStopCommandAuthority(verifier.authorities["cp-current"], emergencyStopCommandAuthority{keyID: "cp-current", audience: "kernel-current", publicKey: currentPublicKey}) {
		t.Fatalf("verifier authorities = %+v", verifier.authorities)
	}
}

func emergencyStopCommandReplayKeyringJSON(t *testing.T, keys ...emergencyStopCommandReplayAuthority) string {
	t.Helper()
	raw, err := json.Marshal(emergencyStopCommandReplayKeyring{
		KeyringVersion: emergencyStopCommandReplayKeyringVersion,
		Keys:           keys,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestEmergencyStopAcknowledgementIdentityUsesClosedSignerProfiles(t *testing.T) {
	classicalSigner, err := helmcrypto.NewEd25519Signer("kernel-classical")
	if err != nil {
		t.Fatal(err)
	}
	classical, err := emergencyStopAcknowledgementIdentity(classicalSigner)
	if err != nil {
		t.Fatal(err)
	}
	if classical.KeyID != "kernel-classical" || classical.SignerProfile != kernel.EmergencyStopSignerClassical || classical.PublicKey != classicalSigner.PublicKey() {
		t.Fatalf("classical acknowledgement identity = %+v", classical)
	}

	hybridSigner, err := helmcrypto.NewHybridSigner("kernel-hybrid")
	if err != nil {
		t.Fatal(err)
	}
	hybrid, err := emergencyStopAcknowledgementIdentity(hybridSigner)
	if err != nil {
		t.Fatal(err)
	}
	if hybrid.KeyID != "kernel-hybrid" || hybrid.SignerProfile != kernel.EmergencyStopSignerHybrid || hybrid.PublicKey != hybridSigner.PublicKey() || !strings.HasPrefix(hybrid.PublicKey, "hybrid:") {
		t.Fatalf("hybrid acknowledgement identity = %+v", hybrid)
	}
}

func TestEmergencyStopHybridAcknowledgementVerifiesWithoutClassicalDowngrade(t *testing.T) {
	_, store, commandPrivateKey := newEmergencyStopFenceRouteForTest(t)
	hybridSigner, err := helmcrypto.NewHybridSigner("kernel-hybrid")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerEmergencyStopFenceRoutes(mux, &Services{EmergencyStops: store, ReceiptSigner: hybridSigner})
	command := newEmergencyStopFenceCommand(time.Now().UTC())
	command.CommandID = "stop-command-hybrid-ack"
	rec := postEmergencyStopFence(t, mux, signedEmergencyStopFenceEnvelope(t, command, commandPrivateKey), "service-stop-test")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var acknowledgement emergencyStopFenceResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &acknowledgement); err != nil {
		t.Fatal(err)
	}
	if acknowledgement.State.AcknowledgementIdentity.SignerProfile != kernel.EmergencyStopSignerHybrid || acknowledgement.State.AcknowledgementIdentity.KeyID != "kernel-hybrid" {
		t.Fatalf("hybrid acknowledgement identity = %+v", acknowledgement.State.AcknowledgementIdentity)
	}
	payload, err := acknowledgement.State.AcknowledgementPayload()
	if err != nil {
		t.Fatal(err)
	}
	hybridVerifier := newEmergencyStopHybridVerifier(t, acknowledgement.State.AcknowledgementIdentity.PublicKey)
	if !hybridVerifier.Verify(payload, []byte(acknowledgement.KernelSignature)) {
		t.Fatal("valid hybrid acknowledgement did not verify")
	}
	tampered := acknowledgement.KernelSignature[:len(acknowledgement.KernelSignature)-1] + "0"
	if strings.HasSuffix(acknowledgement.KernelSignature, "0") {
		tampered = acknowledgement.KernelSignature[:len(acknowledgement.KernelSignature)-1] + "1"
	}
	if hybridVerifier.Verify(payload, []byte(tampered)) {
		t.Fatal("tampered hybrid acknowledgement unexpectedly verified")
	}
}

func newEmergencyStopHybridVerifier(t *testing.T, publicKey string) *helmcrypto.HybridVerifier {
	t.Helper()
	parts := strings.Split(publicKey, ":")
	if len(parts) != 3 || parts[0] != "hybrid" {
		t.Fatalf("invalid hybrid public-key envelope %q", publicKey)
	}
	ed25519PublicKey, err := hex.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	mldsaPublicKey, err := hex.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := helmcrypto.NewHybridVerifier(ed25519PublicKey, mldsaPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}
