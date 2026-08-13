// quantum_posture: this wiring consumes a classical Ed25519 seed only to key
// the bridge's permit signer; it implements no cryptography itself and claims
// no hybrid or post-quantum protection. Signing and verification are delegated
// to the bridge and core/pkg/crypto, whose posture governs.

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/github"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/runtimeadapters"
	rtmcp "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/runtimeadapters/mcp"
)

// Environment contract for governed GitHub dispatch on the local MCP runtime.
//
// HELM_GITHUB_TOKEN arms the github.* connector wiring: the runtime constructs
// the real GitHub connector and hands it to a GovernedBridge whose permit
// signer is keyed from the same root seed that signs receipts (data-dir
// root.key). The bridge also requires a shared full-gate Guardian; this local
// caller does not yet inject that authority, so configured calls fail closed
// with a structured no-dispatch reason until the wiring is completed. Unset,
// the tools are not registered.
const (
	githubEffectsTokenEnv   = "HELM_GITHUB_TOKEN"
	githubEffectsBaseURLEnv = "HELM_GITHUB_API_URL"
	githubEffectsServerID   = "helm-github-effects"
)

// githubEffectsRuntime is the shipped wiring of the governed effects stack:
// a real connector bound to a GovernedBridge that signs permits and verifies
// them at dispatch. Dispatch is intentionally fail-closed here because this
// caller has no shared Guardian with active threat, freeze, and delegation
// gates; the bridge refuses before permit minting or connector execution.
type githubEffectsRuntime struct {
	bridge *rtmcp.GovernedBridge
}

// newGitHubEffectsRuntimeFromEnv builds the governed GitHub dispatch runtime,
// or returns (nil, nil) when HELM_GITHUB_TOKEN is unset. A set token with an
// unusable permit signing seed is a hard error, never a silent downgrade to
// unsigned permits: the bridge's dispatch gate is deliberately a no-op without
// a signer, so arming dispatch without one would make the tamper check
// vacuously pass.
func newGitHubEffectsRuntimeFromEnv(dataDir string) (*githubEffectsRuntime, error) {
	token := strings.TrimSpace(os.Getenv(githubEffectsTokenEnv))
	if token == "" {
		return nil, nil
	}
	seed, err := localPermitSigningSeed(dataDir)
	if err != nil {
		return nil, fmt.Errorf("github effects: %w", err)
	}
	return newGitHubEffectsRuntime(token, strings.TrimSpace(os.Getenv(githubEffectsBaseURLEnv)), seed)
}

// newGitHubEffectsRuntime constructs the governed runtime from explicit inputs.
// It refuses a seed that yields no permit signer. It deliberately does not
// synthesize a Guardian: freeze/delegation authority must come from the shared
// runtime owner, and the bridge fails closed until that authority is supplied.
func newGitHubEffectsRuntime(token, baseURL string, seed []byte) (*githubEffectsRuntime, error) {
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("github effects: token is required")
	}
	connector := github.NewConnector(github.Config{Token: token, BaseURL: baseURL})
	bridge := rtmcp.NewGovernedBridge(rtmcp.BridgeConfig{
		ServerID:    githubEffectsServerID,
		Profile:     githubEffectsProfile(),
		SigningSeed: seed,
		Connector:   connector,
	})
	if bridge.PermitSigningPublicKey() == "" {
		return nil, fmt.Errorf("github effects: permit signer unavailable; a valid Ed25519 signing seed is required")
	}
	return &githubEffectsRuntime{bridge: bridge}, nil
}

// localPermitSigningSeed reads the Ed25519 seed the local runtime already uses
// for receipt signing (data-dir root.key, hex-encoded). The bridge reuses it
// so a permit and the decision receipt that authorized it trace to one key.
func localPermitSigningSeed(dataDir string) ([]byte, error) {
	if dataDir == "" {
		dataDir = "data"
	}
	keyPath := filepath.Join(dataDir, "root.key")
	keyHex, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read permit signing seed: %w", err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(keyHex)))
	if err != nil {
		return nil, fmt.Errorf("permit signing seed at %s is not hex: %w", keyPath, err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("permit signing seed at %s has %d bytes, need %d", keyPath, len(seed), ed25519.SeedSize)
	}
	return seed, nil
}

// githubEffectsProfile authorizes operate-class MCP tool calls for this bridge
// once the shared Guardian and connector permit contract are present. The
// profile alone never authorizes a configured connector dispatch.
func githubEffectsProfile() contracts.WorkstationPolicyProfile {
	return contracts.WorkstationPolicyProfile{
		ID:      "workstation.github.effects.v1",
		Mode:    "operate",
		Operate: contracts.WorkstationOperatePolicy{Permissions: []string{contracts.WorkstationPermissionMCPMutate}},
	}
}

// toolRefs returns the catalog entries for the governed GitHub tools. Schemas
// mirror the connector's declared permit scope exactly; the connector refuses
// unknown params by name, so the schemas refuse them too.
func (r *githubEffectsRuntime) toolRefs() []mcppkg.ToolRef {
	repoProp := map[string]any{"type": "string", "description": "owner/name"}
	return []mcppkg.ToolRef{
		{
			Name:        "github.list_prs",
			Title:       "List GitHub pull requests",
			Description: "Configured but unavailable until shared Guardian wiring exists; calls fail closed in the current runtime.",
			ServerID:    githubEffectsServerID,
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"repo":  repoProp,
					"state": map[string]any{"type": "string", "enum": []string{"open", "closed", "all"}},
				},
				"required":             []string{"repo"},
				"additionalProperties": false,
			},
		},
		{
			Name:        "github.read_pr",
			Title:       "Read a GitHub pull request",
			Description: "Configured but unavailable until shared Guardian wiring exists; calls fail closed in the current runtime.",
			ServerID:    githubEffectsServerID,
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"repo":   repoProp,
					"number": map[string]any{"type": "integer"},
				},
				"required":             []string{"repo", "number"},
				"additionalProperties": false,
			},
		},
		{
			Name:        "github.create_issue",
			Title:       "Create a GitHub issue",
			Description: "Configured but unavailable until shared Guardian wiring exists; calls fail closed in the current runtime.",
			ServerID:    githubEffectsServerID,
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"repo":      repoProp,
					"title":     map[string]any{"type": "string"},
					"body":      map[string]any{"type": "string"},
					"labels":    map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"assignees": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				},
				"required":             []string{"repo", "title"},
				"additionalProperties": false,
			},
		},
		{
			Name:        "github.add_comment",
			Title:       "Comment on a GitHub issue",
			Description: "Configured but unavailable until shared Guardian wiring exists; calls fail closed in the current runtime.",
			ServerID:    githubEffectsServerID,
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"repo":         repoProp,
					"issue_number": map[string]any{"type": "integer"},
					"body":         map[string]any{"type": "string"},
				},
				"required":             []string{"repo", "issue_number", "body"},
				"additionalProperties": false,
			},
		},
	}
}

// execute routes a github.* tool call through the governed bridge and returns
// the outcome as a machine document. A denied call carries the gate or scope
// reason and a not-dispatched state; an allowed call also carries the signed
// permit and its offline verification key.
func (r *githubEffectsRuntime) execute(ctx context.Context, req mcppkg.ToolExecutionRequest) (mcppkg.ToolExecutionResponse, error) {
	adapted := &runtimeadapters.AdaptedRequest{
		RuntimeType:         "mcp",
		ToolName:            req.ToolName,
		Arguments:           req.Arguments,
		PrincipalID:         firstNonEmpty(req.SessionID, "workstation-local"),
		SessionID:           req.SessionID,
		DelegationSessionID: req.DelegationSessionID,
	}
	inputHash, err := canonicalize.CanonicalHash(adapted)
	if err != nil {
		return mcppkg.ToolExecutionResponse{}, fmt.Errorf("github effects: input hash: %w", err)
	}
	outcome := r.bridge.Govern(ctx, adapted, inputHash)

	doc := map[string]any{
		"verdict":           string(outcome.Verdict),
		"dispatch_state":    outcome.DispatchState,
		"decision_id":       outcome.DecisionID,
		"receipt_hash":      outcome.ReceiptHash,
		"input_hash":        inputHash,
		"permit":            outcome.Permit,
		"permit_public_key": r.bridge.PermitSigningPublicKey(),
	}
	if outcome.Verdict == contracts.VerdictAllow {
		doc["result"] = outcome.Output
		doc["output_hash"] = outcome.OutputHash
		doc["next_steps"] = []string{
			"verify the permit offline: wrap it as {\"receipts\":[],\"permits\":[<permit>]} and run receipt_verify --receipt bundle.json --key " + r.bridge.PermitSigningPublicKey(),
		}
		return structuredLocalMCPResponse(doc)
	}

	doc["reason_code"] = outcome.ReasonCode
	doc["reason"] = outcome.Reason
	doc["denied_by"] = "governed-bridge"
	if outcome.Verdict == contracts.VerdictEscalate {
		doc["next_steps"] = []string{"obtain human approval evidence for this exact request, then retry"}
	} else {
		doc["next_steps"] = []string{"do not retry the same call; modify scope or fix the configuration named in reason"}
	}
	resp, err := structuredLocalMCPResponse(doc)
	if err != nil {
		return resp, err
	}
	resp.IsError = true
	return resp, nil
}
