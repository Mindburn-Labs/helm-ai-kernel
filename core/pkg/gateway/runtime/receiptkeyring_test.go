package runtime

// quantum_posture: checks that the published classical Ed25519 receipt key
// verifies receipts the gateway's signer makes; no post-quantum claim.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptkeyring"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/receiptverify"
)

// TestServePublishesTheReceiptKeyringOnTheMainListener: serve answers GET
// /api/v1/receipt-keyring on its API listener, without a token, with the
// Kernel's keyring shape, under the gateway's own label, for the key it signs
// decision receipts with; the published key verifies a receipt that signer makes, the way receipt_verify
// --key "<key_id>=<hex>" will. The route is read-only and is not served on
// the worker listener.
func TestServePublishesTheReceiptKeyringOnTheMainListener(t *testing.T) {
	identity, _ := jwksServer(t)
	api, worker := freeAddress(t), freeAddress(t)
	values := with(identity, map[string]string{
		"HELM_GATEWAY_DATABASE_URL":      "postgres://127.0.0.1:1/none?sslmode=disable",
		"HELM_GATEWAY_MODEL_ROUTES_FILE": routesFile(t), "HELM_GATEWAY_WORKER_AUDIENCE": "helm-gateway-worker:test",
	})
	startServe(t, []string{"--dev-insecure-listen", api, "--worker-listen", worker}, values)

	resp, err := http.Get("http://" + api + receiptkeyring.Path)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/json" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("GET %s = %d %v: %s", receiptkeyring.Path, resp.StatusCode, resp.Header, body)
	}
	public := hex.EncodeToString(ed25519.NewKeyFromSeed(testReceiptSeed).Public().(ed25519.PublicKey))
	want := `{"keyring_version":"gateway-receipt-keyring.v1","keys":[{"key_id":"` + testReceiptKeyID +
		`","profile":"classical","ed25519_public_key_hex":"` + public + `"}]}`
	if string(body) != want {
		t.Fatalf("keyring\n got %s\nwant %s", body, want)
	}
	for name, secret := range map[string]string{"seed": hex.EncodeToString(testReceiptSeed), "private key": hex.EncodeToString(ed25519.NewKeyFromSeed(testReceiptSeed))} {
		if strings.Contains(strings.ToLower(string(body)), secret) {
			t.Fatalf("the keyring leaks the %s", name)
		}
	}

	// Strict decode, as the Control Plane reads the Kernel's, then verify a
	// receipt signed by the same signer with the published key alone.
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var keyring receiptkeyring.Keyring
	if err := decoder.Decode(&keyring); err != nil || len(keyring.Keys) != 1 {
		t.Fatalf("strict decode: %v %+v", err, keyring)
	}
	signer, err := crypto.NewEd25519SignerFromSeed(testReceiptSeed, testReceiptKeyID)
	if err != nil {
		t.Fatal(err)
	}
	receipt := &contracts.Receipt{ReceiptID: "keyring-probe", DecisionID: "a:1", EffectID: "a", Status: "DENIED",
		Verdict: "DENY", LamportClock: 1, SessionID: receiptverify.GatewayChainID("t", "w")}
	if err := signer.SignReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	trust := receiptverify.TrustRoot{Keys: map[string]string{keyring.Keys[0].KeyID: keyring.Keys[0].Ed25519PublicKeyHex}}
	if res := receiptverify.Verify([]*contracts.Receipt{receipt}, trust); !res.Valid || receipt.KeyID != keyring.Keys[0].KeyID {
		t.Fatalf("the published key does not verify the signer's receipt: %+v", res)
	}

	// Read-only, and only on the API listener.
	post, err := http.Post("http://"+api+receiptkeyring.Path, "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = post.Body.Close()
	if post.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST %s = %d, want 405", receiptkeyring.Path, post.StatusCode)
	}
	other, err := http.Get("http://" + worker + receiptkeyring.Path)
	if err != nil {
		t.Fatal(err)
	}
	_ = other.Body.Close()
	if other.StatusCode != http.StatusNotFound {
		t.Fatalf("the worker listener answered %s with %d, want 404", receiptkeyring.Path, other.StatusCode)
	}
}

// The public route is bounded like the Kernel's public route class: a burst
// past it is refused with 429 and a Retry-After, and nothing is served.
func TestReceiptKeyringRouteIsRateLimited(t *testing.T) {
	signer, err := crypto.NewEd25519SignerFromSeed(testReceiptSeed, testReceiptKeyID)
	if err != nil {
		t.Fatal(err)
	}
	pattern, handler, err := receiptKeyringHandler(signer)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle(pattern, handler)
	served, refused := 0, 0
	for i := 0; i < 4*receiptKeyringBurst && refused == 0; i++ {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, receiptkeyring.Path, nil))
		switch rec.Code {
		case http.StatusOK:
			served++
		case http.StatusTooManyRequests:
			refused++
			if rec.Header().Get("Retry-After") == "" || strings.Contains(rec.Body.String(), "keyring_version") {
				t.Fatalf("refusal = %v %s", rec.Header(), rec.Body.String())
			}
		default:
			t.Fatalf("status %d", rec.Code)
		}
	}
	if refused == 0 || served < receiptKeyringBurst {
		t.Fatalf("served %d, refused %d; want the burst of %d served, then a refusal", served, refused, receiptKeyringBurst)
	}
}

// A signer the keyring cannot describe stops serve: the gateway never signs
// receipts under a key it does not publish.
func TestReceiptKeyringRefusesASignerItCannotPublish(t *testing.T) {
	if _, _, err := receiptKeyringHandler(unpublishableSigner{}); err == nil {
		t.Fatal("an unpublishable signer was accepted")
	}
	if _, _, err := receiptKeyringHandler(nil); err == nil {
		t.Fatal("a nil signer was accepted")
	}
}

type unpublishableSigner struct{}

func (unpublishableSigner) SignReceipt(*contracts.Receipt) error { return nil }
func (unpublishableSigner) PublicKey() string                    { return strings.Repeat("00", 32) }
func (unpublishableSigner) GetKeyID() string                     { return "opaque" }
