package contracts

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
)

func TestClientObservationValidate(t *testing.T) {
	cases := []struct {
		name string
		obs  *ClientObservation
		ok   bool
	}{
		{
			name: "nil is valid — absence is a legitimate state",
			obs:  nil,
			ok:   true,
		},
		{
			name: "parented process may claim the load observed",
			obs:  &ClientObservation{ClientLoadObserved: true, ObservationBasis: ClientObservationBasisParentedProcess, HarnessID: "claude", ProcessOwned: true},
			ok:   true,
		},
		{
			name: "hook basis, not observed — the honest hook state",
			obs:  &ClientObservation{ClientLoadObserved: false, ObservationBasis: ClientObservationBasisHookReported, HarnessID: "codex"},
			ok:   true,
		},
		{
			name: "unobserved default",
			obs:  &ClientObservation{ObservationBasis: ClientObservationBasisUnobserved},
			ok:   true,
		},
		{
			name: "hook basis CANNOT claim the load observed",
			obs:  &ClientObservation{ClientLoadObserved: true, ObservationBasis: ClientObservationBasisHookReported, HarnessID: "claude"},
			ok:   false,
		},
		{
			name: "unobserved basis cannot claim the load observed",
			obs:  &ClientObservation{ClientLoadObserved: true, ObservationBasis: ClientObservationBasisUnobserved, HarnessID: "claude"},
			ok:   false,
		},
		{
			name: "process owned cannot pair with a non-parented basis",
			obs:  &ClientObservation{ObservationBasis: ClientObservationBasisHookReported, ProcessOwned: true},
			ok:   false,
		},
		{
			name: "observed load must name a harness",
			obs:  &ClientObservation{ClientLoadObserved: true, ObservationBasis: ClientObservationBasisParentedProcess, ProcessOwned: true},
			ok:   false,
		},
		{
			name: "unknown basis is rejected",
			obs:  &ClientObservation{ObservationBasis: "made_up"},
			ok:   false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.obs.Validate()
			if tc.ok && err != nil {
				t.Fatalf("expected valid, got %v", err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatal("expected a validation error, got nil")
				}
				var want *InvalidClientObservationError
				if !errors.As(err, &want) {
					t.Fatalf("expected *InvalidClientObservationError, got %T", err)
				}
			}
		})
	}
}

// The claim is only worth making if it is inside the signature. Mutating the
// ClientObservation must change the canonical hash of the receipt.
func TestClientObservationIsInsideTheReceiptHash(t *testing.T) {
	base := AgentRunReceipt{
		ReceiptVersion: AgentRunReceiptVersion,
		ReceiptID:      "arr-1",
		RunID:          "run-1",
		AgentSurface:   "claude",
		ClientObservation: &ClientObservation{
			ClientLoadObserved: true,
			ObservationBasis:   ClientObservationBasisParentedProcess,
			HarnessID:          "claude",
			ProcessOwned:       true,
		},
	}
	h1 := canonicalHash(t, base)

	// Flip a single sub-field: same run, weaker claim.
	mutated := base
	obs := *base.ClientObservation
	obs.ClientLoadObserved = false
	obs.ObservationBasis = ClientObservationBasisHookReported
	mutated.ClientObservation = &obs

	h2 := canonicalHash(t, mutated)
	if h1 == h2 {
		t.Fatal("mutating ClientObservation did not change the receipt hash — the claim is outside the signature")
	}
}

// A receipt written before this field existed omits the key entirely. Adding the
// field must not change its canonical hash, or every historical receipt would
// fail verification the day the field lands.
func TestReceiptWithoutClientObservationVerifiesUnchanged(t *testing.T) {
	// Marshal a legacy receipt shape (no client_observation key) and unmarshal
	// into the current struct — the field is nil.
	legacyJSON := `{"receipt_version":"agent_run_receipt.v1","receipt_id":"arr-legacy","run_id":"run-legacy","agent_surface":"codex"}`
	var r AgentRunReceipt
	if err := json.Unmarshal([]byte(legacyJSON), &r); err != nil {
		t.Fatalf("unmarshal legacy receipt: %v", err)
	}
	if r.ClientObservation != nil {
		t.Fatal("legacy receipt should decode to a nil ClientObservation")
	}

	// The canonical bytes must not contain the new key when the pointer is nil.
	canonical, err := canonicalize.JCS(&r)
	if err != nil {
		t.Fatalf("JCS: %v", err)
	}
	if strings.Contains(string(canonical), `"client_observation"`) {
		t.Fatalf("nil ClientObservation leaked a key into the canonical form: %s", canonical)
	}
}

func canonicalHash(t *testing.T, r AgentRunReceipt) string {
	t.Helper()
	h, err := canonicalize.CanonicalHash(r)
	if err != nil {
		t.Fatalf("CanonicalHash: %v", err)
	}
	return h
}
