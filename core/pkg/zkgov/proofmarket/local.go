package proofmarket

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/zkgov"
)

// LocalProver wraps the existing zkgov.Prover as a ProverNetwork.
// It serves as the fallback when no external decentralized network is
// available — proof generation happens locally in the HELM kernel.
//
// Thread-safe: all public methods are safe for concurrent use.
type LocalProver struct {
	prover  *zkgov.Prover
	results map[string]*ProofResult
	clock   func() time.Time
	mu      sync.RWMutex
}

// NewLocalProver creates a LocalProver that delegates to the built-in zkgov.Prover.
// proverID identifies the local HELM node (typically the Guardian node ID).
func NewLocalProver(proverID string) *LocalProver {
	return &LocalProver{
		prover:  zkgov.NewProver(proverID),
		results: make(map[string]*ProofResult),
		clock:   time.Now,
	}
}

// WithClock overrides the clock for deterministic testing.
func (l *LocalProver) WithClock(clock func() time.Time) *LocalProver {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.clock = clock
	l.prover = l.prover.WithClock(clock)
	return l
}

// Submit generates a ZK governance proof locally using the built-in prover.
// Since this is a local prover, proof generation is synchronous — the result
// is available immediately via Poll after Submit returns.
func (l *LocalProver) Submit(ctx context.Context, task *ProofTask) error {
	if task == nil {
		return fmt.Errorf("proofmarket/local: nil task")
	}
	if task.TaskID == "" {
		return fmt.Errorf("proofmarket/local: task_id is required")
	}

	// Reconstruct the ProofRequest from the task's public commitment data.
	req, err := taskToProofRequest(task)
	if err != nil {
		return fmt.Errorf("proofmarket/local: invalid proof request: %w", err)
	}

	// Generate the proof locally.
	proof, err := l.prover.Prove(req)
	if err != nil {
		return fmt.Errorf("proofmarket/local: proof generation failed: %w", err)
	}

	// Serialize the proof for the result.
	proofBytes, err := canonicalize.JCS(proof)
	if err != nil {
		return fmt.Errorf("proofmarket/local: proof serialization failed: %w", err)
	}

	l.mu.Lock()
	now := l.clock()
	result := &ProofResult{
		TaskID:      task.TaskID,
		ProverID:    proof.ProverID,
		NetworkID:   string(NetworkLocal),
		Proof:       string(proofBytes),
		Attestation: proof.ContentHash,
		GeneratedAt: now,
		ContentHash: proof.ContentHash,
	}
	if proof.RekorEntryID != "" {
		result.AnchorID = proof.RekorEntryID
	}
	l.results[task.TaskID] = result
	l.mu.Unlock()

	task.Status = TaskCompleted
	return nil
}

// Poll returns the result for a previously submitted task.
// For the local prover, results are available immediately after Submit.
func (l *LocalProver) Poll(_ context.Context, taskID string) (*ProofResult, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result, ok := l.results[taskID]
	if !ok {
		return nil, nil
	}
	return result, nil
}

// Network returns NetworkLocal, identifying this as the built-in fallback prover.
func (l *LocalProver) Network() Network {
	return NetworkLocal
}

// taskToProofRequest reconstructs a zkgov.ProofRequest from a ProofTask.
// The task's ProofRequest map must contain the standard fields.
func taskToProofRequest(task *ProofTask) (zkgov.ProofRequest, error) {
	data := task.ProofRequest
	if data == nil {
		return zkgov.ProofRequest{}, fmt.Errorf("proof_request is nil")
	}

	req := zkgov.ProofRequest{}

	if v, ok := data["decision_id"]; ok {
		if s, ok := v.(string); ok {
			req.DecisionID = s
		}
	}
	if v, ok := data["policy_hash"]; ok {
		if s, ok := v.(string); ok {
			req.PolicyHash = s
		}
	}
	if v, ok := data["verdict"]; ok {
		if s, ok := v.(string); ok {
			req.Verdict = s
		}
	}
	if v, ok := data["decision_hash"]; ok {
		if s, ok := v.(string); ok {
			req.DecisionHash = s
		}
	}
	if v, ok := data["input_data"]; ok {
		// input_data may be a map or need re-marshaling.
		if m, ok := v.(map[string]interface{}); ok {
			req.InputData = m
		} else {
			// Try via JSON round-trip for typed maps.
			b, err := json.Marshal(v)
			if err != nil {
				return req, fmt.Errorf("input_data marshal failed: %w", err)
			}
			var m map[string]interface{}
			if err := json.Unmarshal(b, &m); err != nil {
				return req, fmt.Errorf("input_data unmarshal failed: %w", err)
			}
			req.InputData = m
		}
	}

	if req.DecisionID == "" {
		return req, fmt.Errorf("decision_id is required")
	}
	if req.PolicyHash == "" {
		return req, fmt.Errorf("policy_hash is required")
	}
	if req.Verdict == "" {
		return req, fmt.Errorf("verdict is required")
	}
	if req.DecisionHash == "" {
		return req, fmt.Errorf("decision_hash is required")
	}

	return req, nil
}
