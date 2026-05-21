package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
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
	ContainerID       string
	SandboxGrantRef   string
	EgressReceiptRef  string
	EgressNetworkName string
	EgressProxyID     string
	EgressProxyName   string
	Runtime           string
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
		"sandbox_profile_hash": compiled.SandboxProfileHash,
		"network_default":      "deny",
		"filesystem_default":   "deny",
	})
	mcpReceipt := receipts.NewReceipt("launchpad.mcp_quarantine", compiled.LaunchID, "ALLOW", map[string]any{
		"unknown_server_policy": compiled.MCPPolicy.UnknownServerPolicy,
		"unknown_tool_policy":   compiled.MCPPolicy.UnknownToolPolicy,
		"require_schema_pin":    compiled.MCPPolicy.RequireSchemaPin,
		"effect":                "unknown MCP servers and tools remain quarantined until approval receipt exists",
	})

	run.BoundaryRecordRefs = append(run.BoundaryRecordRefs, "boundary://launchpad/"+compiled.LaunchID)
	if compiled.CPIOutput != nil {
		run.CPIRefs = append(run.CPIRefs, compiled.CPIOutput.ResultHash)
	}
	run.SandboxGrantRefs = append(run.SandboxGrantRefs, sandboxReceipt.ReceiptID)
	run.MCPRefs = append(run.MCPRefs, mcpReceipt.ReceiptID)
	run.LaunchReceiptRefs = append(run.LaunchReceiptRefs, launchReceipt.ReceiptID)
	run.IdempotencyKeys["launch"] = compiled.PlanHash
	run.IdempotencyKeys["teardown"] = "teardown:" + compiled.PlanHash

	addJSON(artifacts, "launch_plan.json", compiled)
	addJSON(artifacts, "cpi_output.json", compiled.CPIOutput)
	addJSON(artifacts, "kernel_verdict.json", kernelReceipt)
	addJSON(artifacts, "sandbox_grant.json", sandboxReceipt)
	addJSON(artifacts, "mcp_quarantine.json", mcpReceipt)
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
		failureReceipt := receipts.NewReceipt("launchpad.runtime_failure", compiled.LaunchID, "ALLOW", map[string]any{
			"status": "repair_required",
			"error":  err.Error(),
		})
		run.State = StateRepairRequired
		run.Reason = "runtime start failed after ALLOW; repair required before RUNNING: " + err.Error()
		addJSON(artifacts, "receipts/launchpad-runtime-failure.json", failureReceipt)
		addJSON(artifacts, "runtime_environment.json", map[string]any{"runtime": "local-container", "state": "REPAIR_REQUIRED", "error": err.Error()})
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
	run.SandboxGrantRefs = appendUnique(run.SandboxGrantRefs, runtimeResult.SandboxGrantRef)
	run.EgressReceiptRefs = appendUnique(run.EgressReceiptRefs, runtimeResult.EgressReceiptRef)
	startReceipt := receipts.NewReceipt("launchpad.start", compiled.LaunchID, "ALLOW", map[string]any{
		"runtime":            runtimeResult.Runtime,
		"container_id":       runtimeResult.ContainerID,
		"network":            "deny",
		"filesystem":         "scoped_workspace",
		"side_effects":       "policy-authorized",
		"egress_receipt_ref": runtimeResult.EgressReceiptRef,
	})
	run.StartReceiptRefs = append(run.StartReceiptRefs, startReceipt.ReceiptID)
	addJSON(artifacts, "receipts/launchpad-start.json", startReceipt)

	run.State = StateHealthchecking
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

	run.State = StateRunning
	run.Reason = "launch reached RUNNING after policy, CPI, sandbox preflight, MCP quarantine, install, start, and healthcheck receipts"
	addJSON(artifacts, "runtime_environment.json", map[string]any{"runtime": runtimeResult.Runtime, "state": "RUNNING", "container_id": runtimeResult.ContainerID})
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
	runtimeTeardown := teardownRuntimeHandles(run.RuntimeHandles)
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

func teardownRuntimeHandles(handles RuntimeHandles) map[string]any {
	result := map[string]any{"attempted": false}
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
	if archiveRef, err := receipts.WriteEvidencePackArchive(packRef); err == nil {
		run.EvidencePackRefs = appendUnique(run.EvidencePackRefs, archiveRef)
		run.VerificationCommand = "helm evidence verify " + archiveRef + " --offline"
	} else {
		run.VerificationCommand = "helm evidence verify " + packRef + " --offline"
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
