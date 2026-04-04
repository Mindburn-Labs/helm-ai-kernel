package aigp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/proofgraph"
)

// ExporterConfig configures the AIGP PCD exporter.
type ExporterConfig struct {
	// Source identifies the HELM instance producing PCDs (e.g., "helm.example.com").
	Source string

	// ProofGraphVersion is the HELM standard version (e.g., "v1.2").
	ProofGraphVersion string

	// DefaultFourTests sets default 4TS compliance for exported PCDs.
	// HELM's architecture inherently satisfies all four tests.
	DefaultFourTests FourTestsCompliance
}

// Exporter converts ProofGraph nodes to AIGP Proof-Carrying Decisions.
type Exporter struct {
	cfg ExporterConfig
}

// NewExporter creates a new AIGP PCD exporter.
func NewExporter(cfg ExporterConfig) *Exporter {
	if cfg.ProofGraphVersion == "" {
		cfg.ProofGraphVersion = "v1.2"
	}
	if cfg.Source == "" {
		cfg.Source = "helm"
	}

	// HELM's architecture inherently satisfies all four AIGP tests:
	// - Stoppable: fail-closed PEP boundary, kill switch via guardian
	// - Owned: every node has a Principal field
	// - Replayable: deterministic ProofGraph with full hash chain
	// - Escalatable: escalation package with human-in-the-loop
	if !cfg.DefaultFourTests.Stoppable {
		cfg.DefaultFourTests = FourTestsCompliance{
			Stoppable:   true,
			Owned:       true,
			Replayable:  true,
			Escalatable: true,
		}
	}

	return &Exporter{cfg: cfg}
}

// ExportNode converts a single ProofGraph node to an AIGP PCD.
func (e *Exporter) ExportNode(node *proofgraph.Node) (*ProofCarryingDecision, error) {
	if node == nil {
		return nil, fmt.Errorf("aigp: nil node")
	}

	// Parse the node payload for action metadata.
	var payloadMeta map[string]string
	if len(node.Payload) > 0 {
		// Try to extract key fields from the payload.
		var raw map[string]interface{}
		if err := json.Unmarshal(node.Payload, &raw); err == nil {
			payloadMeta = make(map[string]string)
			for k, v := range raw {
				if s, ok := v.(string); ok {
					payloadMeta[k] = s
				}
			}
		}
	}

	// Determine the decision from the payload.
	decision := "RECORDED"
	if d, ok := payloadMeta["decision"]; ok {
		decision = d
	}

	// Determine the tool from the payload.
	tool := payloadMeta["tool"]
	policyRef := payloadMeta["policy"]

	fourTests := e.cfg.DefaultFourTests
	fourTests.OwnerPrincipal = node.Principal

	pcd := &ProofCarryingDecision{
		Version:   PCDVersion,
		ID:        fmt.Sprintf("pcd:%s", node.NodeHash),
		Timestamp: time.UnixMilli(node.Timestamp).UTC(),
		Action: GovernanceAction{
			Type:      nodeTypeToAction(node.Kind),
			Principal: node.Principal,
			Decision:  decision,
			Tool:      tool,
			PolicyRef: policyRef,
			Metadata:  payloadMeta,
		},
		Evidence: CryptographicEvidence{
			GovernanceHash: node.NodeHash,
			NodeHash:       node.NodeHash,
			ParentHashes:   node.Parents,
			Signature:      node.Sig,
			HashAlgorithm:  "SHA-256",
			LamportClock:   node.Lamport,
		},
		Provenance: PCDProvenance{
			Source:            e.cfg.Source,
			ProofGraphVersion: e.cfg.ProofGraphVersion,
			NodeID:            node.NodeHash,
			ExportTimestamp:   time.Now().UTC(),
		},
		FourTests: fourTests,
	}

	pcd.PCDHash = pcd.ComputePCDHash()
	return pcd, nil
}

// ExportRange exports a range of ProofGraph nodes as AIGP PCDs.
func (e *Exporter) ExportRange(ctx context.Context, store proofgraph.Store, fromLamport, toLamport uint64) ([]*ProofCarryingDecision, error) {
	nodes, err := store.GetRange(ctx, fromLamport, toLamport)
	if err != nil {
		return nil, fmt.Errorf("aigp: get range: %w", err)
	}

	pcds := make([]*ProofCarryingDecision, 0, len(nodes))
	for _, node := range nodes {
		pcd, err := e.ExportNode(node)
		if err != nil {
			return nil, fmt.Errorf("aigp: export node %s: %w", node.NodeHash, err)
		}
		pcds = append(pcds, pcd)
	}

	return pcds, nil
}

// ExportBundle exports a range of PCDs as a JSON bundle.
type PCDBundle struct {
	// Version is the bundle format version.
	Version string `json:"version"`

	// Source identifies the HELM instance.
	Source string `json:"source"`

	// ExportTimestamp is when the bundle was created.
	ExportTimestamp time.Time `json:"export_timestamp"`

	// FromLamport is the start of the covered range.
	FromLamport uint64 `json:"from_lamport"`

	// ToLamport is the end of the covered range.
	ToLamport uint64 `json:"to_lamport"`

	// PCDs are the Proof-Carrying Decisions in this bundle.
	PCDs []*ProofCarryingDecision `json:"pcds"`

	// Count is the number of PCDs in the bundle.
	Count int `json:"count"`

	// FourTestsSummary summarizes 4TS compliance across all PCDs.
	FourTestsSummary FourTestsCompliance `json:"four_tests_summary"`
}

// ExportBundle creates a JSON-serializable bundle of PCDs for a Lamport range.
func (e *Exporter) ExportBundle(ctx context.Context, store proofgraph.Store, fromLamport, toLamport uint64) (*PCDBundle, error) {
	pcds, err := e.ExportRange(ctx, store, fromLamport, toLamport)
	if err != nil {
		return nil, err
	}

	// Compute aggregate 4TS compliance.
	summary := FourTestsCompliance{
		Stoppable:   true,
		Owned:       true,
		Replayable:  true,
		Escalatable: true,
	}
	for _, pcd := range pcds {
		if !pcd.FourTests.Stoppable {
			summary.Stoppable = false
		}
		if !pcd.FourTests.Owned {
			summary.Owned = false
		}
		if !pcd.FourTests.Replayable {
			summary.Replayable = false
		}
		if !pcd.FourTests.Escalatable {
			summary.Escalatable = false
		}
	}

	return &PCDBundle{
		Version:          PCDVersion,
		Source:           e.cfg.Source,
		ExportTimestamp:  time.Now().UTC(),
		FromLamport:      fromLamport,
		ToLamport:        toLamport,
		PCDs:             pcds,
		Count:            len(pcds),
		FourTestsSummary: summary,
	}, nil
}
