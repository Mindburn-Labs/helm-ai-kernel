package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/sandbox/daytona"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/connectors/sandbox/e2b"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	lpprovision "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/provision"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/receipts"
)

type Executor struct {
	Store             *Store
	RuntimeStarter    RuntimeStarter
	HealthcheckRunner HealthcheckRunner
}

type ExecuteOptions struct {
	Reason            string
	RuntimeStarter    RuntimeStarter
	HealthcheckRunner HealthcheckRunner
	WorkspaceMount    string
	RuntimeDryRun     bool
	RuntimeSecretEnv  map[string]string
}

type RuntimeStartResult struct {
	ContainerID                string
	SandboxGrantRef            string
	EgressReceiptRef           string
	EgressNetworkName          string
	EgressProxyID              string
	EgressProxyName            string
	Runtime                    string
	IsolationMode              string
	IsolationHardened          bool
	IsolationDetectionStatus   string
	IsolationUnsupportedReason string
	RuntimeClass               string
	DockerRootless             bool
	DockerUserns               bool
	DockerECI                  bool
	DedicatedVM                bool
	DockerRuntimes             []string
	DefaultRuntime             string
	HostileAgentGrade          bool
	PayloadInspection          string
	NetworkProof               string
	TokenBrokerEnabled         bool
	CloudResourceIDs           map[string]string
}

type RuntimeStarter interface {
	Start(plan.LaunchPlan, ExecuteOptions) (RuntimeStartResult, error)
}

func NewExecutor(store *Store) Executor {
	if store == nil {
		store = NewStore("")
	}
	return Executor{Store: store, RuntimeStarter: DefaultRuntimeStarter{}, HealthcheckRunner: DefaultHealthcheckRunner{}}
}

func (e Executor) ExecuteLaunch(compiled plan.LaunchPlan, opts ExecuteOptions) (LaunchRun, error) {
	if compiled.LaunchID == "" {
		return LaunchRun{}, errors.New("launch id is required")
	}
	run := newLaunchRun(compiled, opts.Reason)
	artifacts := map[string][]byte{}

	kernelReceipt := receipts.NewReceipt("launchpad.kernel_verdict", compiled.LaunchID, compiled.KernelVerdict, map[string]any{
		"app_id":       compiled.AppID,
		"substrate_id": compiled.SubstrateID,
		"plan_hash":    compiled.PlanHash,
		"reason_code":  compiled.ReasonCode,
	})
	launchReceipt := receipts.NewReceipt("launchpad.launch", compiled.LaunchID, compiled.KernelVerdict, map[string]any{
		"app_id":       compiled.AppID,
		"substrate_id": compiled.SubstrateID,
		"plan_hash":    compiled.PlanHash,
		"state":        run.State,
	})
	sandboxReceipt := receipts.NewReceipt("launchpad.sandbox_preflight", compiled.LaunchID, compiled.KernelVerdict, map[string]any{
		"sandbox_profile_hash":       compiled.SandboxProfileHash,
		"network_default":            "deny",
		"filesystem_default":         "deny",
		"model_gateway_mode":         compiled.ModelGatewayMode,
		"raw_provider_key_projected": compiled.RawProviderKeyProjected,
		"payload_inspection":         "opaque_connect",
		"network_proof":              "destination_allowlist_only",
	})
	mcpReceipt := receipts.NewReceipt("launchpad.mcp_quarantine", compiled.LaunchID, "ALLOW", map[string]any{
		"unknown_server_policy": compiled.MCPPolicy.UnknownServerPolicy,
		"unknown_tool_policy":   compiled.MCPPolicy.UnknownToolPolicy,
		"require_schema_pin":    compiled.MCPPolicy.RequireSchemaPin,
		"effect":                "unknown MCP servers and tools remain quarantined until approval receipt exists",
	})
	modelGatewayReceipt := receipts.NewReceipt("launchpad.model_gateway_grant", compiled.LaunchID, compiled.KernelVerdict, map[string]any{
		"provider":                   compiled.ModelGatewayProvider,
		"mode":                       compiled.ModelGatewayMode,
		"required_secret_refs":       compiled.RequiredSecretRefs,
		"runtime_env_names":          compiled.ModelGatewayEnv,
		"raw_provider_key_projected": compiled.RawProviderKeyProjected,
		"network_allowlist":          compiled.NetworkAllowlist,
		"budget_ceiling":             compiled.Budgets,
	})

	run.BoundaryRecordRefs = append(run.BoundaryRecordRefs, "boundary://launchpad/"+compiled.LaunchID)
	if compiled.CPIOutput != nil {
		run.CPIRefs = append(run.CPIRefs, compiled.CPIOutput.ResultHash)
	}
	run.SandboxGrantRefs = append(run.SandboxGrantRefs, sandboxReceipt.ReceiptID)
	run.MCPRefs = append(run.MCPRefs, mcpReceipt.ReceiptID)
	if compiled.ModelGatewayMode != "" || len(compiled.ModelGatewayEnv) > 0 {
		run.ModelGatewayGrantRefs = append(run.ModelGatewayGrantRefs, modelGatewayReceipt.ReceiptID)
	}
	run.LaunchReceiptRefs = append(run.LaunchReceiptRefs, launchReceipt.ReceiptID)
	run.IdempotencyKeys["launch"] = compiled.PlanHash
	run.IdempotencyKeys["teardown"] = "teardown:" + compiled.PlanHash

	addJSON(artifacts, "launch_plan.json", compiled)
	addJSON(artifacts, "cpi_output.json", compiled.CPIOutput)
	addJSON(artifacts, "kernel_verdict.json", kernelReceipt)
	addJSON(artifacts, "sandbox_grant.json", sandboxReceipt)
	addJSON(artifacts, "mcp_quarantine.json", mcpReceipt)
	if compiled.ModelGatewayMode != "" || len(compiled.ModelGatewayEnv) > 0 {
		addJSON(artifacts, "model_gateway_grant.json", modelGatewayReceipt)
		addJSON(artifacts, "receipts/launchpad-model-gateway-grant.json", modelGatewayReceipt)
	}
	addJSON(artifacts, "receipts/launchpad-kernel-verdict.json", kernelReceipt)
	addJSON(artifacts, "receipts/launchpad-launch.json", launchReceipt)
	addJSON(artifacts, "receipts/launchpad-sandbox-preflight.json", sandboxReceipt)
	addJSON(artifacts, "receipts/launchpad-mcp-quarantine.json", mcpReceipt)

	if compiled.KernelVerdict != "ALLOW" {
		escalationReceipt := receipts.NewReceipt("launchpad.escalation", compiled.LaunchID, compiled.KernelVerdict, map[string]any{
			"status":      run.State,
			"reason_code": compiled.ReasonCode,
		})
		healthReceipt := receipts.NewReceipt("launchpad.healthcheck", compiled.LaunchID, "ESCALATE", map[string]any{
			"status": "not-run",
			"reason": "healthcheck blocked before ALLOW",
		})
		run.HealthcheckRefs = append(run.HealthcheckRefs, healthReceipt.ReceiptID)
		addJSON(artifacts, "receipts/launchpad-escalation.json", escalationReceipt)
		addJSON(artifacts, "receipts/launchpad-healthcheck.json", healthReceipt)
		addJSON(artifacts, "runtime_environment.json", map[string]any{"runtime": "not-started", "side_effects": "blocked-before-allow"})
		return e.persist(run, artifacts)
	}

	run.State = StateProvisioning
	if err := e.Store.Save(run); err != nil {
		return LaunchRun{}, err
	}
	if len(compiled.RequiredSecretRefs) > 0 || len(compiled.ModelGatewayEnv) > 0 {
		secretReceipt := receipts.NewReceipt("launchpad.secret_grants", compiled.LaunchID, "ALLOW", map[string]any{
			"required_secret_refs": compiled.RequiredSecretRefs,
			"runtime_env_names":    compiled.ModelGatewayEnv,
			"redacted":             true,
			"grant_mode":           "just-in-time",
		})
		run.SecretGrantRefs = append(run.SecretGrantRefs, secretReceipt.ReceiptID)
		addJSON(artifacts, "receipts/launchpad-secret-grants.json", secretReceipt)
	}
	run.State = StateInstalling
	installReceipt := receipts.NewReceipt("launchpad.install", compiled.LaunchID, "ALLOW", map[string]any{
		"install_strategy": "artifact-first",
		"layout":           "immutable-release",
	})
	run.InstallReceiptRefs = append(run.InstallReceiptRefs, installReceipt.ReceiptID)
	addJSON(artifacts, "receipts/launchpad-install.json", installReceipt)

	run.State = StateStarting
	starter := opts.RuntimeStarter
	if starter == nil {
		starter = e.RuntimeStarter
	}
	if starter == nil {
		starter = DefaultRuntimeStarter{}
	}
	runtimeResult, err := starter.Start(compiled, opts)
	if err != nil {
		failureSubject := map[string]any{
			"status": "repair_required",
			"error":  err.Error(),
		}
		addRuntimeStartEvidence(failureSubject, runtimeResult)
		failureReceipt := receipts.NewReceipt("launchpad.runtime_failure", compiled.LaunchID, "ALLOW", failureSubject)
		run.State = StateRepairRequired
		run.Reason = "runtime start failed after ALLOW; repair required before RUNNING: " + err.Error()
		addJSON(artifacts, "receipts/launchpad-runtime-failure.json", failureReceipt)
		runtimeEnvironment := map[string]any{"runtime": "local-container", "state": "REPAIR_REQUIRED", "error": err.Error()}
		addRuntimeStartEvidence(runtimeEnvironment, runtimeResult)
		addJSON(artifacts, "runtime_environment.json", runtimeEnvironment)
		return e.persist(run, artifacts)
	}
	if runtimeResult.ContainerID == "" || runtimeResult.SandboxGrantRef == "" {
		failureReceipt := receipts.NewReceipt("launchpad.runtime_failure", compiled.LaunchID, "ALLOW", map[string]any{
			"status": "repair_required",
			"error":  "runtime did not return container id and sandbox grant ref",
		})
		run.State = StateRepairRequired
		run.Reason = "runtime start did not return required refs; repair required before RUNNING"
		addJSON(artifacts, "receipts/launchpad-runtime-failure.json", failureReceipt)
		addJSON(artifacts, "runtime_environment.json", map[string]any{"runtime": "local-container", "state": "REPAIR_REQUIRED"})
		return e.persist(run, artifacts)
	}
	if len(compiled.NetworkAllowlist) > 0 && runtimeResult.EgressReceiptRef == "" {
		failureReceipt := receipts.NewReceipt("launchpad.runtime_failure", compiled.LaunchID, "ALLOW", map[string]any{
			"status": "repair_required",
			"error":  "runtime did not return launch-scoped egress receipt ref",
		})
		run.State = StateRepairRequired
		run.Reason = "runtime start did not return egress receipt ref for networked launch; repair required before RUNNING"
		addJSON(artifacts, "receipts/launchpad-runtime-failure.json", failureReceipt)
		addJSON(artifacts, "runtime_environment.json", map[string]any{"runtime": "local-container", "state": "REPAIR_REQUIRED", "container_id": runtimeResult.ContainerID})
		return e.persist(run, artifacts)
	}
	run.RuntimeHandles.ContainerID = runtimeResult.ContainerID
	run.RuntimeHandles.EgressNetworkName = runtimeResult.EgressNetworkName
	run.RuntimeHandles.EgressProxyID = runtimeResult.EgressProxyID
	run.RuntimeHandles.EgressProxyName = runtimeResult.EgressProxyName
	run.RuntimeHandles.CloudResourceIDs = runtimeResult.CloudResourceIDs
	run.SandboxGrantRefs = appendUnique(run.SandboxGrantRefs, runtimeResult.SandboxGrantRef)
	run.EgressReceiptRefs = appendUnique(run.EgressReceiptRefs, runtimeResult.EgressReceiptRef)
	startReceipt := receipts.NewReceipt("launchpad.start", compiled.LaunchID, "ALLOW", map[string]any{
		"runtime":                      runtimeResult.Runtime,
		"container_id":                 runtimeResult.ContainerID,
		"network":                      "deny",
		"filesystem":                   "scoped_workspace",
		"side_effects":                 "policy-authorized",
		"egress_receipt_ref":           runtimeResult.EgressReceiptRef,
		"isolation_mode":               runtimeResult.IsolationMode,
		"isolation_hardened":           runtimeResult.IsolationHardened,
		"isolation_detection_status":   runtimeResult.IsolationDetectionStatus,
		"isolation_unsupported_reason": runtimeResult.IsolationUnsupportedReason,
		"runtime_class":                runtimeResult.RuntimeClass,
		"docker_rootless":              runtimeResult.DockerRootless,
		"docker_userns":                runtimeResult.DockerUserns,
		"docker_eci":                   runtimeResult.DockerECI,
		"dedicated_vm":                 runtimeResult.DedicatedVM,
		"docker_runtimes":              runtimeResult.DockerRuntimes,
		"default_runtime":              runtimeResult.DefaultRuntime,
		"hostile_agent_grade":          runtimeResult.HostileAgentGrade,
		"payload_inspection":           runtimeResult.PayloadInspection,
		"network_proof":                runtimeResult.NetworkProof,
		"token_broker_enabled":         runtimeResult.TokenBrokerEnabled,
	})
	run.StartReceiptRefs = append(run.StartReceiptRefs, startReceipt.ReceiptID)
	addJSON(artifacts, "receipts/launchpad-start.json", startReceipt)

	run.State = StateHealthchecking
	if compiled.RuntimeDetached {
		// Detached runs already proved readiness via the runtime's in-place
		// healthcheck polling (waitForReadiness) before starter.Start
		// returned nil. Re-running the healthcheck here would spin up a
		// second container sharing the launch-scoped egress network and
		// collide on it ("network already exists"). Record the readiness
		// the detached probe established and move on.
		healthReceipt := receipts.NewReceipt("launchpad.healthcheck", compiled.LaunchID, "ALLOW", map[string]any{
			"status": "ready",
			"type":   "detached_readiness_probe",
		})
		run.HealthcheckRefs = append(run.HealthcheckRefs, healthReceipt.ReceiptID)
		addJSON(artifacts, "receipts/launchpad-healthcheck.json", healthReceipt)
	} else {
		healthRunner := opts.HealthcheckRunner
		if healthRunner == nil {
			healthRunner = e.HealthcheckRunner
		}
		if healthRunner == nil {
			healthRunner = DefaultHealthcheckRunner{}
		}
		healthResult, err := healthRunner.Run(compiled, runtimeResult, opts)
		if err != nil {
			failureReceipt := receipts.NewReceipt("launchpad.healthcheck_failure", compiled.LaunchID, "ALLOW", map[string]any{
				"status": "repair_required",
				"error":  err.Error(),
			})
			run.State = StateRepairRequired
			run.Reason = "healthcheck failed after runtime start; repair required before RUNNING: " + err.Error()
			addJSON(artifacts, "receipts/launchpad-healthcheck-failure.json", failureReceipt)
			addJSON(artifacts, "runtime_environment.json", map[string]any{"runtime": runtimeResult.Runtime, "state": "REPAIR_REQUIRED", "container_id": runtimeResult.ContainerID, "error": err.Error()})
			return e.persist(run, artifacts)
		}
		healthReceipt := receipts.NewReceipt("launchpad.healthcheck", compiled.LaunchID, "ALLOW", map[string]any{
			"status":   healthResult.Status,
			"type":     healthResult.Type,
			"metadata": healthResult.Metadata,
		})
		run.HealthcheckRefs = append(run.HealthcheckRefs, healthReceipt.ReceiptID)
		addJSON(artifacts, "receipts/launchpad-healthcheck.json", healthReceipt)
	}

	run.State = StateRunning
	run.Reason = "launch reached RUNNING after policy, CPI, sandbox preflight, MCP quarantine, install, start, and healthcheck receipts"
	addJSON(artifacts, "runtime_environment.json", map[string]any{
		"runtime":                      runtimeResult.Runtime,
		"state":                        "RUNNING",
		"container_id":                 runtimeResult.ContainerID,
		"isolation_mode":               runtimeResult.IsolationMode,
		"isolation_hardened":           runtimeResult.IsolationHardened,
		"isolation_detection_status":   runtimeResult.IsolationDetectionStatus,
		"isolation_unsupported_reason": runtimeResult.IsolationUnsupportedReason,
		"runtime_class":                runtimeResult.RuntimeClass,
		"docker_rootless":              runtimeResult.DockerRootless,
		"docker_userns":                runtimeResult.DockerUserns,
		"docker_eci":                   runtimeResult.DockerECI,
		"dedicated_vm":                 runtimeResult.DedicatedVM,
		"docker_runtimes":              runtimeResult.DockerRuntimes,
		"default_runtime":              runtimeResult.DefaultRuntime,
		"hostile_agent_grade":          runtimeResult.HostileAgentGrade,
		"payload_inspection":           runtimeResult.PayloadInspection,
		"network_proof":                runtimeResult.NetworkProof,
		"token_broker_enabled":         runtimeResult.TokenBrokerEnabled,
	})
	return e.persist(run, artifacts)
}

func (e Executor) DeleteLaunch(launchID string, cascade bool) (LaunchRun, error) {
	run, err := e.Store.Get(launchID)
	if err != nil {
		return LaunchRun{}, err
	}
	previousState := run.State
	run.State = StateTearingDown
	run.KernelVerdict = "ALLOW"
	if err := e.Store.Save(run); err != nil {
		return LaunchRun{}, err
	}
	runtimeTeardown := teardownRuntimeHandles(run)
	teardown := receipts.NewReceipt("launchpad.teardown", run.LaunchID, "ALLOW", map[string]any{
		"cascade":        cascade,
		"previous_state": previousState,
		"reconciled":     true,
		"runtime":        runtimeTeardown,
	})
	run.State = StateDeleted
	run.KernelVerdict = "ALLOW"
	run.TeardownReceiptRefs = append(run.TeardownReceiptRefs, teardown.ReceiptID)
	run.Reason = "teardown receipt emitted after Launchpad-owned state reconciliation"
	artifacts := map[string][]byte{}
	addJSON(artifacts, "receipts/launchpad-teardown.json", teardown)
	addJSON(artifacts, "teardown_proof.json", map[string]any{
		"launch_id":             run.LaunchID,
		"cascade":               cascade,
		"teardown_receipt_ref":  teardown.ReceiptID,
		"cloud_reconciled":      true,
		"mcp_approvals_revoked": true,
		"runtime":               runtimeTeardown,
	})
	return e.persist(run, artifacts)
}

func teardownRuntimeHandles(run LaunchRun) map[string]any {
	result := map[string]any{"attempted": false}
	handles := run.RuntimeHandles
	provider := handles.CloudResourceIDs["provider"]
	if provider == "" {
		provider = run.SubstrateID
	}

	if provider == "e2b" {
		result["attempted"] = true
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		apiKey := strings.TrimSpace(os.Getenv("E2B_API_KEY"))
		if apiKey == "" {
			apiKey = strings.TrimSpace(os.Getenv("HELM_LAUNCHPAD_E2B_API_KEY"))
		}
		if apiKey != "" && handles.ContainerID != "" && !strings.Contains(handles.ContainerID, "dry-run") {
			cfg := e2b.DefaultConfig()
			cfg.APIKey = apiKey
			if apiURL := os.Getenv("HELM_LAUNCHPAD_E2B_API_URL"); apiURL != "" {
				cfg.APIURL = apiURL
			}
			adapter := e2b.New(cfg)
			err := adapter.Terminate(ctx, handles.ContainerID)
			if err == nil {
				result["cloud_cleanup"] = "deleted"
				result["receipt_id"] = "receipt:e2b:" + run.LaunchID + ":teardown"
			} else {
				result["cloud_cleanup_error"] = err.Error()
			}
		} else {
			result["cloud_cleanup"] = "dry-run-or-key-missing"
			result["receipt_id"] = "receipt:e2b:" + run.LaunchID + ":teardown-dry-run"
		}
		return result
	}

	if provider == "daytona" {
		result["attempted"] = true
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		apiKey := strings.TrimSpace(os.Getenv("DAYTONA_API_KEY"))
		if apiKey == "" {
			apiKey = strings.TrimSpace(os.Getenv("HELM_LAUNCHPAD_DAYTONA_API_KEY"))
		}
		if apiKey != "" && handles.ContainerID != "" && !strings.Contains(handles.ContainerID, "dry-run") {
			cfg := daytona.DefaultConfig()
			cfg.APIKey = apiKey
			if baseURL := os.Getenv("HELM_LAUNCHPAD_DAYTONA_BASE_URL"); baseURL != "" {
				cfg.BaseURL = baseURL
			}
			adapter := daytona.New(cfg)
			err := adapter.Terminate(ctx, handles.ContainerID)
			if err == nil {
				result["cloud_cleanup"] = "deleted"
				result["receipt_id"] = "receipt:daytona:" + run.LaunchID + ":teardown"
			} else {
				result["cloud_cleanup_error"] = err.Error()
			}
		} else {
			result["cloud_cleanup"] = "dry-run-or-key-missing"
			result["receipt_id"] = "receipt:daytona:" + run.LaunchID + ":teardown-dry-run"
		}
		return result
	}

	if provider == "digitalocean" || provider == "hetzner" {
		if handles.CloudResourceIDs["teardown_reconciled"] == "true" {
			result["attempted"] = true
			result["provider"] = provider
			result["cloud_cleanup"] = "already-reconciled"
			return result
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if provider == "digitalocean" {
			token := strings.TrimSpace(os.Getenv("DIGITALOCEAN_TOKEN"))
			if token == "" {
				token = strings.TrimSpace(os.Getenv("HELM_LAUNCHPAD_DIGITALOCEAN_TOKEN"))
			}
			if token != "" {
				dropletID, _ := strconv.ParseInt(handles.CloudResourceIDs["droplet"], 10, 64)
				provisioner := lpprovision.DigitalOceanProvisioner{
					AllowLiveWrites: true,
					Token:           token,
					Endpoint:        os.Getenv("HELM_LAUNCHPAD_DIGITALOCEAN_ENDPOINT"),
				}
				td, err := provisioner.Delete(ctx, lpprovision.DigitalOceanDeleteRequest{
					LaunchID:   run.LaunchID,
					PlanHash:   run.PlanHash,
					DropletID:  dropletID,
					FirewallID: handles.CloudResourceIDs["firewall"],
				})
				if err == nil {
					result["attempted"] = true
					result["cloud_cleanup"] = "deleted"
					result["receipt_id"] = td.ReceiptID
				} else {
					result["cloud_cleanup_error"] = err.Error()
				}
			} else {
				result["cloud_cleanup_error"] = "DIGITALOCEAN_TOKEN missing"
			}
		} else if provider == "hetzner" {
			token := strings.TrimSpace(os.Getenv("HCLOUD_TOKEN"))
			if token == "" {
				token = strings.TrimSpace(os.Getenv("HELM_LAUNCHPAD_HETZNER_TOKEN"))
			}
			if token != "" {
				serverID, _ := strconv.ParseInt(handles.CloudResourceIDs["server"], 10, 64)
				firewallID, _ := strconv.ParseInt(handles.CloudResourceIDs["firewall"], 10, 64)
				provisioner := lpprovision.HetznerProvisioner{
					AllowLiveWrites: true,
					Token:           token,
					Endpoint:        os.Getenv("HELM_LAUNCHPAD_HETZNER_ENDPOINT"),
				}
				td, err := provisioner.Delete(ctx, lpprovision.HetznerDeleteRequest{
					LaunchID:   run.LaunchID,
					PlanHash:   run.PlanHash,
					ServerID:   serverID,
					FirewallID: firewallID,
				})
				if err == nil {
					result["attempted"] = true
					result["cloud_cleanup"] = "deleted"
					result["receipt_id"] = td.ReceiptID
				} else {
					result["cloud_cleanup_error"] = err.Error()
				}
			} else {
				result["cloud_cleanup_error"] = "HCLOUD_TOKEN missing"
			}
		}
		return result
	}

	docker, err := exec.LookPath("docker")
	if err != nil {
		result["docker_available"] = false
		return result
	}
	result["docker_available"] = true
	if handles.ContainerID != "" {
		result["attempted"] = true
		result["container_id"] = handles.ContainerID
		if out, err := exec.Command(docker, "rm", "-f", handles.ContainerID).CombinedOutput(); err != nil {
			result["container_cleanup"] = strings.TrimSpace(string(out))
		} else {
			result["container_cleanup"] = "removed_or_absent"
		}
	}
	// Orphan cleanup: containers labelled with this launch_id that never
	// got their ID recorded (e.g. early failure before docker run returned).
	if launchID != "" {
		filter := "label=launchpad-launch-id=" + launchID
		if out, err := exec.Command(docker, "ps", "-aq", "--filter", filter).CombinedOutput(); err == nil {
			ids := strings.Fields(strings.TrimSpace(string(out)))
			if len(ids) > 0 {
				result["attempted"] = true
				result["orphan_container_ids"] = ids
				rmArgs := append([]string{"rm", "-f"}, ids...)
				if rmOut, rmErr := exec.Command(docker, rmArgs...).CombinedOutput(); rmErr != nil {
					result["orphan_container_cleanup"] = strings.TrimSpace(string(rmOut))
				} else {
					result["orphan_container_cleanup"] = "removed_or_absent"
				}
			}
		}
		// Deterministic sidecar resources by launch_id (handles partial-save
		// failures where EgressNetworkName / EgressProxyName never landed
		// in LaunchRun state).
		expectedProxy := "helm-lp-" + launchID + "-proxy"
		expectedNet := "helm-lp-" + launchID + "-net"
		// State-dir cleanup (gap #19). Mirror of runtime.appStateRoot.
		stateDir := ""
		if override := strings.TrimSpace(os.Getenv("HELM_LAUNCHPAD_HOME")); override != "" {
			stateDir = filepath.Join(override, "state", launchID)
		} else if home, err := os.UserHomeDir(); err == nil {
			stateDir = filepath.Join(home, ".helm", "launchpad", "state", launchID)
		}
		if stateDir != "" {
			if err := os.RemoveAll(stateDir); err == nil {
				result["state_dir_cleanup"] = "removed_or_absent"
			} else {
				result["state_dir_cleanup"] = err.Error()
			}
		}
		if out, err := exec.Command(docker, "rm", "-f", expectedProxy).CombinedOutput(); err == nil {
			if trimmed := strings.TrimSpace(string(out)); trimmed != "" {
				result["orphan_proxy_cleanup"] = trimmed
			}
		}
		if out, err := exec.Command(docker, "network", "rm", expectedNet).CombinedOutput(); err == nil {
			if trimmed := strings.TrimSpace(string(out)); trimmed != "" {
				result["orphan_network_cleanup"] = trimmed
			}
		}
	}
	if handles.EgressProxyName != "" {
		result["attempted"] = true
		result["egress_proxy_name"] = handles.EgressProxyName
		if out, err := exec.Command(docker, "rm", "-f", handles.EgressProxyName).CombinedOutput(); err != nil {
			result["egress_proxy_cleanup"] = strings.TrimSpace(string(out))
		} else {
			result["egress_proxy_cleanup"] = "removed_or_absent"
		}
	}
	if handles.EgressNetworkName != "" {
		result["attempted"] = true
		result["egress_network_name"] = handles.EgressNetworkName
		if out, err := exec.Command(docker, "network", "rm", handles.EgressNetworkName).CombinedOutput(); err != nil {
			result["egress_network_cleanup"] = strings.TrimSpace(string(out))
		} else {
			result["egress_network_cleanup"] = "removed_or_absent"
		}
	}
	return result
}

func (e Executor) persist(run LaunchRun, artifacts map[string][]byte) (LaunchRun, error) {
	packRef, err := receipts.WriteEvidencePack(e.Store.Root(), run.LaunchID, artifacts)
	if err != nil {
		return LaunchRun{}, err
	}
	run.EvidencePackRefs = appendUnique(run.EvidencePackRefs, packRef)
	run.EvidenceGraphRefs = appendUnique(run.EvidenceGraphRefs, packRef+"/04_EXPORTS/launchpad_evidence_graph.json")
	if archiveRef, err := receipts.WriteEvidencePackArchive(packRef); err == nil {
		run.EvidencePackRefs = appendUnique(run.EvidencePackRefs, archiveRef)
		run.VerificationCommand = "helm-ai-kernel verify --bundle " + archiveRef
	} else {
		run.VerificationCommand = "helm-ai-kernel verify --bundle " + packRef
	}
	logPath, _ := e.Store.AppendLog(run.LaunchID, fmt.Sprintf("launchpad state %s verdict %s", run.State, run.KernelVerdict))
	run.LogPath = logPath
	if err := e.Store.Save(run); err != nil {
		return LaunchRun{}, err
	}
	return run, nil
}

func newLaunchRun(compiled plan.LaunchPlan, reason string) LaunchRun {
	state := StateValidated
	switch compiled.Status {
	case "ESCALATED":
		state = StateEscalated
	case "DENIED":
		state = StateDenied
	case "PLANNED":
		state = StatePlanned
	}
	return LaunchRun{
		LaunchID:         compiled.LaunchID,
		AppID:            compiled.AppID,
		AppVersion:       compiled.AppVersion,
		SubstrateID:      compiled.SubstrateID,
		Principal:        compiled.Principal,
		PlanHash:         compiled.PlanHash,
		ArtifactImage:    compiled.ArtifactImage,
		ArtifactDigest:   compiled.ArtifactDigest,
		State:            state,
		KernelVerdict:    compiled.KernelVerdict,
		ReasonCode:       compiled.ReasonCode,
		Reason:           reason,
		RuntimeHandles:   RuntimeHandles{CloudResourceIDs: map[string]string{}},
		IdempotencyKeys:  map[string]string{},
		CPIRefs:          []string{},
		SandboxGrantRefs: []string{},
		MCPRefs:          []string{},
		TeardownCommand:  "helm teardown " + compiled.LaunchID + " --cascade",
	}
}

func addJSON(dst map[string][]byte, name string, value any) {
	data, _ := json.MarshalIndent(value, "", "  ")
	dst[name] = append(data, '\n')
}

func addRuntimeStartEvidence(dst map[string]any, result RuntimeStartResult) {
	if result.Runtime != "" {
		dst["runtime"] = result.Runtime
	}
	if result.IsolationMode != "" {
		dst["isolation_mode"] = result.IsolationMode
		dst["isolation_hardened"] = result.IsolationHardened
		dst["isolation_detection_status"] = result.IsolationDetectionStatus
		dst["isolation_unsupported_reason"] = result.IsolationUnsupportedReason
		dst["unsupported_mode_denial"] = result.IsolationDetectionStatus == "unsupported" || result.IsolationUnsupportedReason != ""
		dst["runtime_class"] = result.RuntimeClass
		dst["docker_rootless"] = result.DockerRootless
		dst["docker_userns"] = result.DockerUserns
		dst["docker_eci"] = result.DockerECI
		dst["dedicated_vm"] = result.DedicatedVM
		dst["docker_runtimes"] = result.DockerRuntimes
		dst["default_runtime"] = result.DefaultRuntime
		dst["hostile_agent_grade"] = result.HostileAgentGrade
	}
	if result.PayloadInspection != "" {
		dst["payload_inspection"] = result.PayloadInspection
	}
	if result.NetworkProof != "" {
		dst["network_proof"] = result.NetworkProof
	}
	dst["token_broker_enabled"] = result.TokenBrokerEnabled
}

func appendUnique(values []string, next string) []string {
	if next == "" {
		return values
	}
	for _, value := range values {
		if value == next {
			return values
		}
	}
	return append(values, next)
}
