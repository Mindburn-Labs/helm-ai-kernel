package acton

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
)

var _ effects.Connector = (*Connector)(nil)

type Connector struct {
	runner       Runner
	defaultP0    P0Ceilings
	defaultGrant *contracts.SandboxGrant
	graph        *proofgraph.Graph
	seq          atomic.Uint64
}

type Config struct {
	Runner       Runner
	DefaultP0    P0Ceilings
	SandboxGrant *contracts.SandboxGrant
}

func NewConnector(cfg Config) *Connector {
	p0 := cfg.DefaultP0
	if p0.AllowedActonVersions == nil && p0.AllowedTolkCompilerVersions == nil {
		p0 = DefaultP0Ceilings()
	}
	return &Connector{
		runner:       cfg.Runner,
		defaultP0:    p0,
		defaultGrant: cfg.SandboxGrant,
		graph:        proofgraph.NewGraph(),
	}
}

func (c *Connector) ID() string {
	return ConnectorID
}

func (c *Connector) Graph() *proofgraph.Graph {
	return c.graph
}

func (c *Connector) Execute(ctx context.Context, permit *effects.EffectPermit, toolName string, params map[string]any) (any, error) {
	if permit == nil {
		return nil, fmt.Errorf("ton.acton: permit is required")
	}
	if permit.ConnectorID != ConnectorID {
		return nil, fmt.Errorf("ton.acton: permit connector_id %q does not match %q", permit.ConnectorID, ConnectorID)
	}
	action, ok := ResolveAction(toolName, params)
	if !ok {
		env := fallbackEnvelopeForUnknown(toolName, params, permit)
		receipt, err := NewPreDispatchReceipt(env, deny(ReasonUnknownCommand, "unknown Acton action"))
		if err == nil {
			_ = c.appendProofNode(proofgraph.NodeTypeIntent, receipt)
		}
		return receipt, err
	}
	effectIndex := int(uint64Param(params, "effect_index", 0))
	env, err := NewEnvelope(params, action, permit.IntentHash, effectIndex)
	if err != nil {
		env = fallbackEnvelopeForAction(action, params, permit)
		receipt, receiptErr := NewPreDispatchReceipt(env, deny(reasonFromError(err, ReasonArgvRejected), err.Error()))
		if receiptErr == nil {
			_ = c.appendProofNode(proofgraph.NodeTypeIntent, receipt)
		}
		return receipt, receiptErr
	}
	env.PolicyHash = firstNonEmpty(env.PolicyHash, permit.PolicyHash)
	if env.P0CeilingsHash == "" {
		p0 := policyFromParams(params)
		env.P0CeilingsHash = p0.Hash()
	}
	grant := c.defaultGrant
	if parsed := sandboxGrantFromParams(params); parsed != nil {
		grant = parsed
	}
	if grant != nil && env.SandboxGrantHash == "" {
		sealed, sealErr := grant.Seal()
		if sealErr == nil {
			env.SandboxGrantHash = sealed.GrantHash
		}
	}
	manifest := scriptManifestFromParams(params)
	ceilings := c.defaultP0
	if _, ok := params["p0_ceilings"]; ok {
		ceilings = policyFromParams(params)
	}
	decision := EvaluatePolicy(env, ceilings, grant, manifest)
	_ = c.appendProofNode(proofgraph.NodeTypeIntent, env)
	if !decision.Dispatch {
		receipt, err := NewPreDispatchReceipt(env, decision)
		if err == nil {
			_ = c.appendProofNode(proofgraph.NodeTypeAttestation, receipt)
		}
		return receipt, err
	}
	expectedShapeHash, _ := stringParam(params, "expected_output_shape_hash")
	receipt, err := c.runner.Run(ctx, env, grant, expectedShapeHash)
	if err != nil {
		return nil, err
	}
	_ = c.appendProofNode(proofgraph.NodeTypeEffect, receipt)
	return receipt, nil
}

func (c *Connector) appendProofNode(t proofgraph.NodeType, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	seq := c.seq.Add(1)
	_, err = c.graph.Append(t, data, ConnectorID, seq)
	return err
}

func sandboxGrantFromParams(params map[string]any) *contracts.SandboxGrant {
	raw, ok := params["sandbox_grant"]
	if !ok || raw == nil {
		return nil
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var grant contracts.SandboxGrant
	if err := json.Unmarshal(data, &grant); err != nil {
		return nil
	}
	return &grant
}

func scriptManifestFromParams(params map[string]any) *ScriptManifest {
	if raw, ok := params["script_manifest"]; ok && raw != nil {
		data, err := json.Marshal(raw)
		if err == nil {
			var manifest ScriptManifest
			if json.Unmarshal(data, &manifest) == nil {
				return &manifest
			}
		}
	}
	if path, ok := stringParam(params, "script_manifest_path"); ok && path != "" {
		manifest, err := LoadScriptManifest(path)
		if err == nil {
			return manifest
		}
	}
	return nil
}

func fallbackEnvelopeForUnknown(toolName string, params map[string]any, permit *effects.EffectPermit) *ActonCommandEnvelope {
	env := fallbackEnvelopeForAction(ActionVersion, params, permit)
	env.ActionURN = ActionURN(toolName)
	env.RiskClass = RiskT3
	env.Argv = []string{"acton"}
	return env
}

func fallbackEnvelopeForAction(action ActionURN, params map[string]any, permit *effects.EffectPermit) *ActonCommandEnvelope {
	spec, ok := commandSpecs[action]
	if !ok {
		spec = CommandSpec{URN: action, RiskClass: RiskT3, ExecutorKind: ExecutorDigital}
	}
	commandID, _ := stringParam(params, "command_id")
	if commandID == "" {
		commandID = deterministicID(permit.IntentHash, string(action), 0)
	}
	return &ActonCommandEnvelope{
		SchemaVersion:    CommandSchemaVersion,
		ConnectorID:      ConnectorID,
		CommandID:        commandID,
		TenantID:         fallbackString(params, "tenant_id", "local"),
		WorkspaceID:      fallbackString(params, "workspace_id", "local"),
		Principal:        fallbackString(params, "principal", permit.IssuerID),
		ActionURN:        action,
		RiskClass:        spec.RiskClass,
		EffectClass:      spec.EffectClass,
		ExecutorKind:     ExecutorDigital,
		ProjectRoot:      fallbackString(params, "project_root", "."),
		ManifestPath:     fallbackString(params, "manifest_path", "Acton.toml"),
		Network:          spec.Network,
		Argv:             []string{"acton", spec.ActonSubcommand},
		PolicyHash:       permit.PolicyHash,
		IdempotencyKey:   DeriveIdempotencyKey(permit.IntentHash, string(action), 0),
		CreatedAtLamport: uint64Param(params, "created_at_lamport", 1),
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
