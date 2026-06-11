package aigp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
)

// ExporterConfig configures the AIGP PCD exporter.
type ExporterConfig struct {
	// Source identifies the HELM instance producing PCDs (e.g., "helm.example.com").
	Source string

	// ProofGraphVersion is the HELM standard version (e.g., "v1.2").
	ProofGraphVersion string

	// DefaultFourTests is retained for API compatibility only. AIGP 4TS
	// compliance is derived from each node's explicit evidence at export time.
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

	return &Exporter{cfg: cfg}
}

// ExportNode converts a single ProofGraph node to an AIGP PCD.
func (e *Exporter) ExportNode(node *proofgraph.Node) (*ProofCarryingDecision, error) {
	if node == nil {
		return nil, fmt.Errorf("aigp: nil node")
	}

	payloadMeta := extractPayloadMeta(node.Payload)

	// Determine the decision from the payload.
	decision := "RECORDED"
	if d, ok := payloadMeta["decision"]; ok {
		decision = d
	}

	// Determine the tool from the payload.
	tool := payloadMeta["tool"]
	policyRef := payloadMeta["policy"]

	fourTests := deriveFourTests(node, payloadMeta)

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

	summary := summarizeFourTests(pcds)

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

func extractPayloadMeta(payload json.RawMessage) map[string]string {
	meta := map[string]string{}
	if len(payload) == 0 {
		return meta
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return meta
	}
	for k, v := range raw {
		switch value := v.(type) {
		case string:
			meta[k] = strings.TrimSpace(value)
		case bool:
			meta[k] = fmt.Sprintf("%t", value)
		case float64:
			meta[k] = fmt.Sprintf("%g", value)
		}
	}
	return meta
}

func deriveFourTests(node *proofgraph.Node, payloadMeta map[string]string) FourTestsCompliance {
	return FourTestsCompliance{
		Stoppable:      hasAnyMeta(payloadMeta, "stop_ref", "kill_switch_ref", "guardian_stop_ref", "stoppable_ref") || truthyMeta(payloadMeta, "stoppable"),
		Owned:          strings.TrimSpace(node.Principal) != "",
		Replayable:     hasReplayEvidence(node, payloadMeta),
		Escalatable:    hasAnyMeta(payloadMeta, "escalation_ref", "human_approval_ref", "approval_ref", "escalation_policy", "escalation_queue") || truthyMeta(payloadMeta, "escalatable"),
		OwnerPrincipal: node.Principal,
	}
}

func hasReplayEvidence(node *proofgraph.Node, payloadMeta map[string]string) bool {
	if node == nil || node.Lamport == 0 || strings.TrimSpace(node.Sig) == "" || node.SigPurpose == "" {
		return false
	}
	if err := node.Validate(); err != nil {
		return false
	}
	if len(node.Parents) > 0 {
		return allValidSHA256(node.Parents)
	}
	if validAIGPSHA256(payloadMeta["replay_hash"]) {
		return true
	}
	return hasAnyMeta(payloadMeta, "replay_ref", "replay_script_ref", "tape_ref", "parent_chain_ref")
}

func summarizeFourTests(pcds []*ProofCarryingDecision) FourTestsCompliance {
	if len(pcds) == 0 {
		return FourTestsCompliance{}
	}

	summary := FourTestsCompliance{
		Stoppable:   true,
		Owned:       true,
		Replayable:  true,
		Escalatable: true,
	}
	for _, pcd := range pcds {
		if pcd == nil {
			summary.Stoppable = false
			summary.Owned = false
			summary.Replayable = false
			summary.Escalatable = false
			continue
		}
		summary.Stoppable = summary.Stoppable && pcd.FourTests.Stoppable
		summary.Owned = summary.Owned && pcd.FourTests.Owned
		summary.Replayable = summary.Replayable && pcd.FourTests.Replayable
		summary.Escalatable = summary.Escalatable && pcd.FourTests.Escalatable
	}
	return summary
}

func hasAnyMeta(meta map[string]string, keys ...string) bool {
	for _, key := range keys {
		if strings.TrimSpace(meta[key]) != "" {
			return true
		}
	}
	return false
}

func truthyMeta(meta map[string]string, key string) bool {
	switch strings.ToLower(strings.TrimSpace(meta[key])) {
	case "true", "1", "yes", "y":
		return true
	default:
		return false
	}
}

func allValidSHA256(values []string) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		if !validAIGPSHA256(value) {
			return false
		}
	}
	return true
}

func validAIGPSHA256(value string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	trimmed = strings.TrimPrefix(trimmed, "sha256:")
	if len(trimmed) != 64 {
		return false
	}
	for _, r := range trimmed {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
