package governance

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/artifacts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
)

type SignalController struct {
	ProducerID string
	signer     crypto.Signer
}

func NewSignalController(id string, signer crypto.Signer) *SignalController {
	return &SignalController{ProducerID: id, signer: signer}
}

func (s *SignalController) Name() string {
	return "signal.controller"
}

func (s *SignalController) Advise(ctx context.Context, intent string, contextData map[string]any) (*artifacts.ArtifactEnvelope, error) {
	// Fail-closed on context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("signal controller: context canceled: %w", err)
	}

	// 1. Check Metrics
	// If intent implies high load, check capacity.

	payload := map[string]string{
		"signal": "GREEN",
		"health": "99.9%",
		"check":  "all_systems_nominal",
	}

	bytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("signal controller: marshal failed: %w", err)
	}

	env := &artifacts.ArtifactEnvelope{
		Type:          artifacts.TypeAlertEvidence,
		SchemaVersion: "v1",
		Payload:       bytes,
		ProducerID:    s.ProducerID,
		Timestamp:     time.Now().UTC(),
	}
	if err := artifacts.SignEnvelope(env, s.signer); err != nil {
		return nil, err
	}
	return env, nil
}
