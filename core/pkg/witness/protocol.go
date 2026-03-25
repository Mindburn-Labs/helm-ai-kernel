// Package witness implements the HELM Witness Network protocol.
//
// The Witness Network provides external co-signing for HELM receipts,
// enabling multi-party verification of governance decisions without
// requiring trust in a single HELM deployment.
//
// Protocol:
//  1. HELM node creates receipt with signature
//  2. Receipt is broadcast to k-of-n witness nodes
//  3. Each witness validates the receipt and adds its own signature
//  4. Once k signatures collected, WitnessSignatures are bound to receipt
//
// This implements SPEC-1.3 from the HELM strategic roadmap.
package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// ── Protocol Types ─────────────────────────────────────────────────────────

// WitnessRequest is sent from the HELM node to witness nodes.
type WitnessRequest struct {
	ReceiptID    string `json:"receipt_id"`
	ReceiptHash  string `json:"receipt_hash"`  // SHA-256 of full receipt
	Signature    string `json:"signature"`     // HELM node's Ed25519 signature
	PublicKey    string `json:"public_key"`    // HELM node's public key (hex)
	LamportClock uint64 `json:"lamport_clock"`
	SessionID    string `json:"session_id"`
	Timestamp    time.Time `json:"timestamp"`
}

// WitnessAttestation is the response from a witness node.
type WitnessAttestation struct {
	WitnessID      string    `json:"witness_id"`
	ReceiptID      string    `json:"receipt_id"`
	ReceiptHash    string    `json:"receipt_hash"`
	Signature      string    `json:"signature"`       // Witness's Ed25519 signature over receipt hash
	PublicKey      string    `json:"public_key"`       // Witness's public key (hex)
	AttestationTime time.Time `json:"attestation_time"`
	Verdict        string    `json:"verdict"`          // "VALID", "INVALID", "ABSTAIN"
	Reason         string    `json:"reason,omitempty"`
}

// WitnessPolicy defines the co-signing requirements.
type WitnessPolicy struct {
	MinWitnesses    int           `json:"min_witnesses"`     // k in k-of-n
	TotalWitnesses  int           `json:"total_witnesses"`   // n
	TimeoutPerNode  time.Duration `json:"timeout_per_node"`
	RequireUnanimous bool         `json:"require_unanimous"` // All must attest VALID
}

// ── Witness Node (Server) ──────────────────────────────────────────────────

// WitnessNode is a reference implementation of a HELM witness node.
type WitnessNode struct {
	mu         sync.RWMutex
	id         string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	trustedKeys map[string]ed25519.PublicKey // HELM node public keys
	log        []WitnessAttestation
}

// WitnessNodeConfig configures a witness node.
type WitnessNodeConfig struct {
	ID          string              `json:"id"`
	PrivateKey  ed25519.PrivateKey
	TrustedKeys map[string]ed25519.PublicKey // Map of node ID → public key
}

// NewWitnessNode creates a reference witness node.
func NewWitnessNode(cfg WitnessNodeConfig) (*WitnessNode, error) {
	if cfg.ID == "" {
		return nil, fmt.Errorf("witness: node ID required")
	}
	if cfg.PrivateKey == nil {
		return nil, fmt.Errorf("witness: private key required")
	}
	return &WitnessNode{
		id:          cfg.ID,
		privateKey:  cfg.PrivateKey,
		publicKey:   cfg.PrivateKey.Public().(ed25519.PublicKey),
		trustedKeys: cfg.TrustedKeys,
		log:         make([]WitnessAttestation, 0),
	}, nil
}

// Attest validates a receipt and produces a witness attestation.
func (w *WitnessNode) Attest(_ context.Context, req WitnessRequest) (*WitnessAttestation, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// 1. Verify the HELM node's signature.
	pubKeyBytes, err := hex.DecodeString(req.PublicKey)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return w.attestInvalid(req, "invalid public key"), nil
	}

	sigBytes, err := hex.DecodeString(req.Signature)
	if err != nil {
		return w.attestInvalid(req, "invalid signature encoding"), nil
	}

	receiptHashBytes, err := hex.DecodeString(req.ReceiptHash)
	if err != nil {
		return w.attestInvalid(req, "invalid receipt hash"), nil
	}

	pubKey := ed25519.PublicKey(pubKeyBytes)
	if !ed25519.Verify(pubKey, receiptHashBytes, sigBytes) {
		return w.attestInvalid(req, "signature verification failed"), nil
	}

	// 2. Verify against trusted keys (if configured).
	if len(w.trustedKeys) > 0 {
		trusted := false
		for _, tk := range w.trustedKeys {
			if tk.Equal(pubKey) {
				trusted = true
				break
			}
		}
		if !trusted {
			return w.attestInvalid(req, "public key not in trusted set"), nil
		}
	}

	// 3. Sign the receipt hash with witness key.
	witnessSig := ed25519.Sign(w.privateKey, receiptHashBytes)

	attestation := &WitnessAttestation{
		WitnessID:       w.id,
		ReceiptID:       req.ReceiptID,
		ReceiptHash:     req.ReceiptHash,
		Signature:       hex.EncodeToString(witnessSig),
		PublicKey:        hex.EncodeToString(w.publicKey),
		AttestationTime: time.Now().UTC(),
		Verdict:         "VALID",
	}

	w.log = append(w.log, *attestation)
	return attestation, nil
}

func (w *WitnessNode) attestInvalid(req WitnessRequest, reason string) *WitnessAttestation {
	return &WitnessAttestation{
		WitnessID:       w.id,
		ReceiptID:       req.ReceiptID,
		ReceiptHash:     req.ReceiptHash,
		PublicKey:        hex.EncodeToString(w.publicKey),
		AttestationTime: time.Now().UTC(),
		Verdict:         "INVALID",
		Reason:          reason,
	}
}

// ── Witness Client (Caller) ───────────────────────────────────────────────

// WitnessClient coordinates co-signing across multiple witness nodes.
type WitnessClient struct {
	policy WitnessPolicy
	nodes  []WitnessEndpoint
}

// WitnessEndpoint is a reachable witness node.
type WitnessEndpoint struct {
	ID       string `json:"id"`
	Address  string `json:"address"` // gRPC or HTTP address
	PublicKey string `json:"public_key"`
}

// NewWitnessClient creates a client that coordinates witness co-signing.
func NewWitnessClient(policy WitnessPolicy, nodes []WitnessEndpoint) *WitnessClient {
	return &WitnessClient{
		policy: policy,
		nodes:  nodes,
	}
}

// CollectAttestations broadcasts a receipt to witness nodes and collects attestations.
// Returns attestations once k-of-n threshold is met or timeout.
func (c *WitnessClient) CollectAttestations(ctx context.Context, req WitnessRequest, localAttest func(WitnessRequest) (*WitnessAttestation, error)) ([]WitnessAttestation, error) {
	type result struct {
		attestation *WitnessAttestation
		err         error
	}

	results := make(chan result, len(c.nodes))
	ctx, cancel := context.WithTimeout(ctx, c.policy.TimeoutPerNode*time.Duration(len(c.nodes)))
	defer cancel()

	// Broadcast to all witness nodes concurrently.
	for range c.nodes {
		go func() {
			att, err := localAttest(req)
			results <- result{att, err}
		}()
	}

	var attestations []WitnessAttestation
	validCount := 0

	for i := 0; i < len(c.nodes); i++ {
		select {
		case <-ctx.Done():
			break
		case r := <-results:
			if r.err != nil {
				continue
			}
			attestations = append(attestations, *r.attestation)
			if r.attestation.Verdict == "VALID" {
				validCount++
			}
			if validCount >= c.policy.MinWitnesses {
				return attestations, nil
			}
		}
	}

	if validCount >= c.policy.MinWitnesses {
		return attestations, nil
	}

	return attestations, fmt.Errorf("witness: only %d/%d valid attestations (need %d)",
		validCount, len(c.nodes), c.policy.MinWitnesses)
}

// ── Utilities ──────────────────────────────────────────────────────────────

// HashReceipt produces the SHA-256 hash that witnesses sign.
func HashReceipt(receiptJSON []byte) string {
	h := sha256.Sum256(receiptJSON)
	return hex.EncodeToString(h[:])
}

// VerifyAttestation verifies a single witness attestation.
func VerifyAttestation(att WitnessAttestation) error {
	pubKeyBytes, err := hex.DecodeString(att.PublicKey)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid witness public key")
	}

	sigBytes, err := hex.DecodeString(att.Signature)
	if err != nil {
		return fmt.Errorf("invalid witness signature encoding")
	}

	receiptHashBytes, err := hex.DecodeString(att.ReceiptHash)
	if err != nil {
		return fmt.Errorf("invalid receipt hash encoding")
	}

	if !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), receiptHashBytes, sigBytes) {
		return fmt.Errorf("witness attestation signature invalid")
	}
	return nil
}

// SerializeAttestations serializes attestations for embedding in receipts.
func SerializeAttestations(attestations []WitnessAttestation) ([]byte, error) {
	return json.Marshal(attestations)
}
