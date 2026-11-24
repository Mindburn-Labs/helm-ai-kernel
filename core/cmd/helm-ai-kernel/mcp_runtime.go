package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/a2a"
	helmauth "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/auth"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/events"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	mcppkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/mcp"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
)

const maxLocalMCPFileSize = 1 << 20

func newLocalMCPRuntime() (*mcppkg.ToolCatalog, mcppkg.GovernedExecutor, error) {
	return newLocalMCPRuntimeWithDataDir("data")
}

func newLocalMCPRuntimeWithDataDir(dataDir string) (*mcppkg.ToolCatalog, mcppkg.GovernedExecutor, error) {
	return newLocalMCPRuntimeWithDataDirAndPolicy(dataDir, nil)
}

func newLocalMCPRuntimeWithDataDirAndPolicy(dataDir string, policyGraph *prg.Graph) (*mcppkg.ToolCatalog, mcppkg.GovernedExecutor, error) {
	signer, err := loadOrGenerateSignerWithDataDir(dataDir)
	if err != nil {
		return nil, mcppkg.GovernedExecutor{}, err
	}
	// Governed GitHub dispatch arms only from the environment (see
	// mcp_effects.go); a misconfigured signer seed fails loudly here instead of
	// degrading to unsigned permits.
	githubEffects, err := newGitHubEffectsRuntimeFromEnv(dataDir)
	if err != nil {
		return nil, mcppkg.GovernedExecutor{}, err
	}
	// The fence database stays open for the life of the mcp serve process.
	fence, err := openStandaloneEmergencyStopFence(context.Background(), dataDir)
	if err != nil {
		return nil, mcppkg.GovernedExecutor{}, err
	}
	return newLocalMCPRuntimeWithSignerPolicyAndEffects(signer, policyGraph, githubEffects, fence.guardianState(dataDir))
}

func newLocalMCPRuntimeWithSigner(signer helmcrypto.Signer) (*mcppkg.ToolCatalog, mcppkg.GovernedExecutor, error) {
	return newLocalMCPRuntimeWithSignerAndPolicy(signer, nil)
}

// newLocalMCPRuntimeWithSignerAndPolicy builds the local MCP runtime whose
// Guardian enforces policyGraph. A nil policyGraph keeps the historical
// fail-closed default: the catalog stays discoverable but every execution is
// denied, because an empty graph carries no allow rule. Pass a compiled graph
// (see `mcp serve --policy`) to authorize the actions it declares.
func newLocalMCPRuntimeWithSignerAndPolicy(signer helmcrypto.Signer, policyGraph *prg.Graph) (*mcppkg.ToolCatalog, mcppkg.GovernedExecutor, error) {
	return newLocalMCPRuntimeWithSignerPolicyAndEffects(signer, policyGraph, nil, productionGuardianState{})
}

func newLocalMCPRuntimeWithSignerPolicyAndEffects(signer helmcrypto.Signer, policyGraph *prg.Graph, githubEffects *githubEffectsRuntime, state productionGuardianState) (*mcppkg.ToolCatalog, mcppkg.GovernedExecutor, error) {
	if signer == nil {
		return nil, mcppkg.GovernedExecutor{}, fmt.Errorf("mcp signer is required")
	}
	if policyGraph == nil {
		policyGraph = prg.NewGraph()
	}
	guard, err := newProductionGuardian(signer, policyGraph, nil, utcRuntimeClock{}, state)
	if err != nil {
		return nil, mcppkg.GovernedExecutor{}, fmt.Errorf("initialize local MCP production Guardian: %w", err)
	}
	return newLocalMCPRuntimeWithEvaluatorAndEffects(guard, githubEffects)
}

// newLocalMCPRuntimeWithEvaluator builds the local MCP runtime whose governance
// decisions come from evaluator. Wiring the kernel's snapshot-bound Guardian
// lets the deployed gateway enforce the currently reconciled policy authority
// (including reference-pack runtime_actions) instead of a static boot-time
// graph that never sees reconciler updates.
func newLocalMCPRuntimeWithEvaluator(evaluator mcppkg.PolicyEvaluator) (*mcppkg.ToolCatalog, mcppkg.GovernedExecutor, error) {
	return newLocalMCPRuntimeWithEvaluatorAndEffects(evaluator, nil)
}

func newLocalMCPRuntimeWithEvaluatorAndEffects(evaluator mcppkg.PolicyEvaluator, githubEffects *githubEffectsRuntime) (*mcppkg.ToolCatalog, mcppkg.GovernedExecutor, error) {
	if evaluator == nil {
		return nil, mcppkg.GovernedExecutor{}, fmt.Errorf("mcp policy evaluator is required")
	}
	evaluator, err := bindEmergencyStopScope(evaluator)
	if err != nil {
		return nil, mcppkg.GovernedExecutor{}, err
	}
	catalog := mcppkg.NewInMemoryCatalog()
	catalog.RegisterCommonTools()
	catalog.RegisterGovernanceTools()
	if githubEffects != nil {
		for _, ref := range githubEffects.toolRefs() {
			if err := catalog.Register(context.Background(), ref); err != nil {
				return nil, mcppkg.GovernedExecutor{}, fmt.Errorf("register github effect tool %s: %w", ref.Name, err)
			}
		}
	}
	firewall := mcppkg.NewGovernanceFirewall(evaluator, catalog, lifecycleFirewallOptions()...)

	return catalog, firewall.GovernedExecutor(localMCPToolHandler(evaluator, githubEffects)), nil
}

func lifecycleFirewallOptions() []mcppkg.GovernanceFirewallOption {
	lifecycleEnv := os.Getenv("HELM_ENV")
	options := []mcppkg.GovernanceFirewallOption{mcppkg.WithLifecycleEnvironment(lifecycleEnv)}
	if lifecycleEnv == events.EnvSynthetic {
		options = append(options, mcppkg.WithLifecyclePublisher(events.SlogPublisher(nil)))
	}
	return options
}

func newLocalMCPGateway() (*mcppkg.Gateway, error) {
	return newConfiguredLocalMCPGateway(mcppkg.GatewayConfig{})
}

func newConfiguredLocalMCPGateway(cfg mcppkg.GatewayConfig) (*mcppkg.Gateway, error) {
	catalog, executor, err := newLocalMCPRuntime()
	if err != nil {
		return nil, err
	}

	return mcppkg.NewGateway(catalog, cfg, mcppkg.WithGovernedExecutor(executor)), nil
}

func newConfiguredLocalMCPGatewayWithSigner(cfg mcppkg.GatewayConfig, signer helmcrypto.Signer) (*mcppkg.Gateway, error) {
	catalog, executor, err := newLocalMCPRuntimeWithSigner(signer)
	if err != nil {
		return nil, err
	}

	return mcppkg.NewGateway(catalog, cfg, mcppkg.WithGovernedExecutor(executor)), nil
}

// newLocalMCPGatewayWithEvaluator builds the MCP gateway on an existing
// governance evaluator (typically the kernel Guardian bound to the reconciled
// policy snapshot store).
func newLocalMCPGatewayWithEvaluator(cfg mcppkg.GatewayConfig, evaluator mcppkg.PolicyEvaluator) (*mcppkg.Gateway, error) {
	return newLocalMCPGatewayWithEvaluatorAndEffects(cfg, evaluator, nil)
}

func newLocalMCPGatewayWithEvaluatorAndEffects(cfg mcppkg.GatewayConfig, evaluator mcppkg.PolicyEvaluator, githubEffects *githubEffectsRuntime) (*mcppkg.Gateway, error) {
	catalog, executor, err := newLocalMCPRuntimeWithEvaluatorAndEffects(evaluator, githubEffects)
	if err != nil {
		return nil, err
	}

	return mcppkg.NewGateway(catalog, cfg, mcppkg.WithGovernedExecutor(executor)), nil
}

// receiptPersistingEvaluator persists a signed receipt for every governed MCP
// gateway decision — ALLOW and DENY. Persistence is fail-closed: a decision
// that cannot be receipted surfaces as a governance error and blocks the call,
// matching the /api/v1/evaluate route and the transparency-anchor posture.
//
// Receipts are written in the tenant of the authenticated principal (R9), so
// that tenant reads them through /api/v1/receipts. The gateway routes are
// mounted under RouteAuthConfiguredTenant (see registerDeployedMCPRoutes),
// which binds the one configured tenant, HELM_RUNTIME_TENANT_ID, to the
// credential. The gateway is therefore single-tenant: a caller asserting
// another tenant is refused, and registered principal bindings do not extend
// it. A decision without an authenticated tenant is refused, never receipted
// outside tenant scope.
type receiptPersistingEvaluator struct {
	svc   *Services
	inner mcppkg.PolicyEvaluator
}

func (e *receiptPersistingEvaluator) EvaluateDecision(ctx context.Context, req guardian.DecisionRequest) (*contracts.DecisionRecord, error) {
	tenantID := ""
	if principal, err := helmauth.GetPrincipal(ctx); err == nil && principal != nil {
		tenantID = strings.TrimSpace(principal.GetTenantID())
	}
	if tenantID == "" {
		return nil, fmt.Errorf("gateway decision has no authenticated tenant to receipt it under")
	}
	decision, err := e.inner.EvaluateDecision(ctx, req)
	if err != nil || decision == nil {
		return decision, err
	}
	body, err := canonicalize.JCS(req)
	if err != nil {
		return nil, fmt.Errorf("canonicalize gateway decision request: %w", err)
	}
	if err := persistDecisionReceiptForTenant(ctx, e.svc, decision, req.Principal, tenantID, body, map[string]any{
		"source":   "mcp.gateway",
		"action":   req.Action,
		"resource": req.Resource,
		"reason":   decision.Reason,
	}); err != nil {
		return nil, fmt.Errorf("persist gateway decision receipt: %w", err)
	}
	return decision, nil
}

func localMCPToolHandler(evaluator mcppkg.PolicyEvaluator, githubEffects *githubEffectsRuntime) mcppkg.ToolHandler {
	return func(ctx context.Context, req mcppkg.ToolExecutionRequest) (mcppkg.ToolExecutionResponse, error) {
		if strings.HasPrefix(req.ToolName, "github.") {
			if githubEffects == nil {
				resp, err := structuredLocalMCPResponse(map[string]any{
					"error":      "github effects dispatch is not configured",
					"denied_by":  "local-mcp-runtime",
					"next_steps": []string{"set " + githubEffectsTokenEnv + " and restart 'mcp serve'"},
				})
				if err != nil {
					return resp, err
				}
				resp.IsError = true
				return resp, nil
			}
			return githubEffects.execute(ctx, req)
		}
		return runLocalMCPTool(ctx, evaluator, req)
	}
}

func runLocalMCPTool(ctx context.Context, evaluator mcppkg.PolicyEvaluator, req mcppkg.ToolExecutionRequest) (mcppkg.ToolExecutionResponse, error) {
	switch req.ToolName {
	case "helm.verify":
		decision, err := evaluator.EvaluateDecision(ctx, guardian.DecisionRequest{
			Principal: stringArgument(req.Arguments, "principal"),
			Action:    stringArgument(req.Arguments, "action"),
			Resource:  stringArgument(req.Arguments, "resource"),
			Context: map[string]any{
				"args_hash": stringArgument(req.Arguments, "args_hash"),
			},
		})
		if err != nil {
			return mcppkg.ToolExecutionResponse{}, fmt.Errorf("evaluate governance action: %w", err)
		}
		if decision == nil {
			return mcppkg.ToolExecutionResponse{}, fmt.Errorf("evaluate governance action: empty decision")
		}
		return structuredLocalMCPResponse(map[string]any{
			"verdict":         decision.Verdict,
			"receipt_id":      decision.ID,
			"reason_code":     decision.ReasonCode,
			"proofgraph_node": decision.RequirementSetHash,
		})

	case "helm.evaluate":
		envelopeJSON, err := json.Marshal(req.Arguments["envelope"])
		if err != nil {
			return mcppkg.ToolExecutionResponse{}, fmt.Errorf("encode A2A envelope: %w", err)
		}
		var envelope a2a.Envelope
		if err := json.Unmarshal(envelopeJSON, &envelope); err != nil {
			return mcppkg.ToolExecutionResponse{}, fmt.Errorf("decode A2A envelope: %w", err)
		}
		featuresJSON, err := json.Marshal(req.Arguments["local_features"])
		if err != nil {
			return mcppkg.ToolExecutionResponse{}, fmt.Errorf("encode local A2A features: %w", err)
		}
		var localFeatures []a2a.Feature
		if err := json.Unmarshal(featuresJSON, &localFeatures); err != nil {
			return mcppkg.ToolExecutionResponse{}, fmt.Errorf("decode local A2A features: %w", err)
		}
		result, err := a2a.NewDefaultVerifier().Negotiate(ctx, &envelope, localFeatures)
		if err != nil {
			return mcppkg.ToolExecutionResponse{}, fmt.Errorf("evaluate A2A envelope: %w", err)
		}
		return structuredLocalMCPResponse(result)

	case "file_read":
		path, _ := req.Arguments["path"].(string)
		resolvedPath, err := resolveLocalMCPPath(path)
		if err != nil {
			return mcppkg.ToolExecutionResponse{
				Content: err.Error(),
				IsError: true,
			}, nil
		}

		info, err := os.Stat(resolvedPath)
		if err != nil {
			return mcppkg.ToolExecutionResponse{
				Content: fmt.Sprintf("read %s: %v", resolvedPath, err),
				IsError: true,
			}, nil
		}
		if info.Size() > maxLocalMCPFileSize {
			return mcppkg.ToolExecutionResponse{
				Content: fmt.Sprintf("read %s: file exceeds %d bytes", resolvedPath, maxLocalMCPFileSize),
				IsError: true,
			}, nil
		}

		data, err := os.ReadFile(resolvedPath)
		if err != nil {
			return mcppkg.ToolExecutionResponse{
				Content: fmt.Sprintf("read %s: %v", resolvedPath, err),
				IsError: true,
			}, nil
		}

		return mcppkg.ToolExecutionResponse{
			Content: string(data),
			ContentItems: mcppkg.StructuredTextContent(map[string]any{
				"path":       resolvedPath,
				"text":       string(data),
				"size_bytes": len(data),
			}, string(data)),
			StructuredContent: map[string]any{
				"path":       resolvedPath,
				"text":       string(data),
				"size_bytes": len(data),
			},
		}, nil

	case "file_write":
		path, _ := req.Arguments["path"].(string)
		content, _ := req.Arguments["content"].(string)

		resolvedPath, err := resolveLocalMCPPath(path)
		if err != nil {
			return mcppkg.ToolExecutionResponse{
				Content: err.Error(),
				IsError: true,
			}, nil
		}

		if err := os.MkdirAll(filepath.Dir(resolvedPath), 0750); err != nil {
			return mcppkg.ToolExecutionResponse{
				Content: fmt.Sprintf("prepare %s: %v", resolvedPath, err),
				IsError: true,
			}, nil
		}
		if err := os.WriteFile(resolvedPath, []byte(content), 0600); err != nil {
			return mcppkg.ToolExecutionResponse{
				Content: fmt.Sprintf("write %s: %v", resolvedPath, err),
				IsError: true,
			}, nil
		}

		return mcppkg.ToolExecutionResponse{
			Content: fmt.Sprintf("wrote %d bytes to %s", len(content), resolvedPath),
			ContentItems: mcppkg.StructuredTextContent(map[string]any{
				"path":          resolvedPath,
				"bytes_written": len(content),
				"status":        "written",
			}, fmt.Sprintf("wrote %d bytes to %s", len(content), resolvedPath)),
			StructuredContent: map[string]any{
				"path":          resolvedPath,
				"bytes_written": len(content),
				"status":        "written",
			},
		}, nil
	default:
		return mcppkg.ToolExecutionResponse{
			Content: fmt.Sprintf("tool %q not supported", req.ToolName),
			IsError: true,
		}, nil
	}
}

func stringArgument(arguments map[string]any, name string) string {
	value, _ := arguments[name].(string)
	return value
}

func structuredLocalMCPResponse(value any) (mcppkg.ToolExecutionResponse, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return mcppkg.ToolExecutionResponse{}, fmt.Errorf("encode MCP tool result: %w", err)
	}
	var structured map[string]any
	if err := json.Unmarshal(body, &structured); err != nil {
		return mcppkg.ToolExecutionResponse{}, fmt.Errorf("normalize MCP tool result: %w", err)
	}
	return mcppkg.ToolExecutionResponse{
		Content:           string(body),
		ContentItems:      mcppkg.StructuredTextContent(structured, string(body)),
		StructuredContent: structured,
	}, nil
}

func resolveLocalMCPPath(rawPath string) (string, error) {
	if strings.TrimSpace(rawPath) == "" {
		return "", fmt.Errorf("path is required")
	}

	cleaned := filepath.Clean(rawPath)
	if filepath.IsAbs(cleaned) {
		return cleaned, nil
	}

	wd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve working directory: %w", err)
	}
	return filepath.Join(wd, cleaned), nil
}
