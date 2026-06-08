package launchkit

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/modelproviders"
	lpplan "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	lpsecrets "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/secrets"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/session"
)

type Orchestrator struct {
	Catalog   *registry.Catalog
	Store     *session.Store
	Executor  session.Executor
	Providers map[Target]EnvironmentProvider
}

func New(catalog *registry.Catalog, store *session.Store) Orchestrator {
	if store == nil {
		store = session.NewStore("")
	}
	return Orchestrator{
		Catalog:   catalog,
		Store:     store,
		Executor:  session.NewExecutor(store),
		Providers: DefaultProviders(),
	}
}

func (o Orchestrator) Up(opts Options) (Result, error) {
	opts = normalizeOptions(opts)
	result := Result{
		AppID:       opts.AppID,
		Mode:        opts.Mode,
		Target:      opts.Target,
		Gates:       canonicalGates(),
		VerifyOnly:  opts.Mode == ModeVerifyOnly,
		GeneratedAt: time.Now().UTC(),
	}
	if o.Catalog == nil {
		return result, fmt.Errorf("launchkit catalog is required")
	}
	if o.Store == nil {
		o.Store = session.NewStore(opts.StoreRoot)
	}
	if o.Executor.Store == nil {
		o.Executor = session.NewExecutor(o.Store)
	}
	if o.Providers == nil {
		o.Providers = DefaultProviders()
	}
	provider := o.provider(opts.Target)
	result.SubstrateID = provider.SubstrateID()
	result.Provider = provider.Probe()
	result.Gates = setGate(result.Gates, "environment.detect", GateAllow, "", result.Provider.Detail)

	app, ok := o.Catalog.App(opts.AppID)
	if !ok {
		compiled := lpplan.FailurePlan(opts.AppID, result.SubstrateID, opts.Principal, "DENY", "DENIED", "ERR_LAUNCHKIT_UNKNOWN_APP")
		return o.persistBlocked(result, compiled, "unknown app")
	}
	result.SupportLevel = app.SupportLevel
	result.Gates = setGate(result.Gates, "dependency.bootstrap", GateAllow, "", "LaunchKit registry and local state store are ready.")

	if app.SupportLevel == registry.SupportLevelVerifyOnly {
		if opts.Mode == ModeLive {
			compiled := lpplan.FailurePlan(app.ID, result.SubstrateID, opts.Principal, "ESCALATE", "ESCALATED", "ERR_LAUNCHKIT_VERIFY_ONLY_SUPPORT_LEVEL")
			return o.persistBlocked(result, compiled, "app is verify_only; live-agent LaunchKit coverage requires runtime command evidence beyond version smoke checks")
		}
		opts.Mode = ModeVerifyOnly
		result.Mode = ModeVerifyOnly
		result.VerifyOnly = true
		result.Gates = setGate(result.Gates, "app.support", GateAllow, "", "AppSpec is verify_only; LaunchKit will stop after contract proof and not claim live-agent F2 coverage.")
	} else if app.Availability != registry.AvailabilityOSSSupported || !app.Conformance.FullyVerified() {
		compiled := lpplan.FailurePlan(app.ID, result.SubstrateID, opts.Principal, "ESCALATE", "ESCALATED", "ERR_LAUNCHKIT_APP_UNSUPPORTED")
		return o.persistBlocked(result, compiled, "app is not fully verified for LaunchKit availability")
	} else {
		result.Gates = setGate(result.Gates, "app.support", GateAllow, "", "AppSpec is oss_supported and fully verified.")
	}

	supplyChain := VerifySupplyChain(app)
	result.Gates = applySupplyChainGates(result.Gates, supplyChain)
	if supplyChain.ReasonCode != "" {
		compiled := lpplan.FailurePlan(app.ID, result.SubstrateID, opts.Principal, "DENY", "DENIED", supplyChain.ReasonCode)
		return o.persistBlocked(result, compiled, "supply-chain verification failed")
	}

	if isCloudTarget(opts.Target) {
		return o.cloudPreflight(result, app, opts)
	}
	if opts.Mode == ModeLive && !result.Provider.Available {
		compiled := lpplan.FailurePlan(app.ID, result.SubstrateID, opts.Principal, "ESCALATE", "ESCALATED", "ERR_LAUNCHKIT_LOCAL_RUNTIME_UNAVAILABLE")
		return o.persistBlocked(result, compiled, "local container runtime is not ready")
	}

	compiled, mode, runtimeSecrets, err := o.compile(app, opts, result.Provider.Available)
	result.Mode = mode
	applyCompiledResult(&result, compiled)
	if err != nil {
		result.Gates = bindContractGate(result.Gates, compiled)
		result.Gates = setGate(result.Gates, "launchplan.compile", statusFromVerdict(compiled.KernelVerdict), compiled.ReasonCode, err.Error())
		result.Gates = setGate(result.Gates, "policy.compile", statusFromVerdict(compiled.KernelVerdict), compiled.ReasonCode, "Policy/CPI compile did not authorize runtime.")
		return o.persistBlocked(result, compiled, err.Error())
	}
	if opts.ResumeRunID != "" {
		compiled = rebindLaunchID(compiled, opts.ResumeRunID)
	}
	result.Plan = &compiled
	applyCompiledResult(&result, compiled)
	result.Gates = bindContractGate(result.Gates, compiled)
	result.Gates = setGate(result.Gates, "launchplan.compile", GateAllow, "", "LaunchPlan compiled before runtime side effects.")
	result.Gates = setGate(result.Gates, "policy.compile", GateAllow, "", "Policy and CPI output are bound to the LaunchPlan.")
	result.Gates = setGate(result.Gates, "secret.preflight", GateAllow, "", secretSummary(mode, compiled.RequiredSecretRefs))
	result.Gates = setGate(result.Gates, "sandbox.grant", GateAllow, "", "Sandbox grant will be issued before runtime dispatch.")
	result.Gates = setGate(result.Gates, "mcp.quarantine", GateAllow, "", "Unknown MCP servers and tools remain quarantined by default.")

	if opts.Mode == ModeVerifyOnly {
		result.Gates = setGate(result.Gates, "runtime.launch", GateSkipped, "", "verify-only mode stops before runtime launch")
		result.Gates = setGate(result.Gates, "healthcheck", GateSkipped, "", "verify-only mode stops before healthcheck")
		return result, nil
	}

	run, err := o.Executor.ExecuteLaunch(compiled, session.ExecuteOptions{
		Reason:           "helm up requested through LaunchKit",
		RuntimeDryRun:    mode == ModeDemo,
		RuntimeSecretEnv: runtimeSecrets,
		RuntimeStarter:   runtimeStarterForMode(mode),
	})
	if err != nil {
		return result, err
	}
	result.Run = &run
	result.ResultClass = run.ResultClass
	result.RepairClass = run.RepairClass
	result.EvidenceRefs = append([]string{}, run.EvidenceRefs...)
	result.StartedRuntime = run.RuntimeHandles.ContainerID != ""
	result.ConsoleURL = consoleURL(opts.ConsoleBaseURL, run.LaunchID)
	result.OfflineVerifyCommand = run.VerificationCommand
	result.ResumeCommand = "helm up " + app.ID + " --resume " + run.LaunchID
	result.Gates = bindRunGates(result.Gates, run)
	return result, nil
}

func runtimeStarterForMode(mode Mode) session.RuntimeStarter {
	if mode == ModeDemo {
		return demoRuntimeStarter{}
	}
	return nil
}

type demoRuntimeStarter struct{}

func (demoRuntimeStarter) Start(compiled lpplan.LaunchPlan, opts session.ExecuteOptions) (session.RuntimeStartResult, error) {
	opts.RuntimeDryRun = true
	result, err := session.DefaultRuntimeStarter{}.Start(compiled, opts)
	if err != nil {
		return session.RuntimeStartResult{}, err
	}
	if len(compiled.NetworkAllowlist) > 0 && result.EgressReceiptRef == "" {
		result.EgressReceiptRef = "launchkit.demo_egress_disabled:" + compiled.PlanHash
	}
	result.Runtime = "launchkit-demo"
	return result, nil
}

func (o Orchestrator) provider(target Target) EnvironmentProvider {
	if provider, ok := o.Providers[target]; ok {
		return provider
	}
	return CloudProvider{Target: target, Region: "unknown"}
}

func (o Orchestrator) compile(app registry.AppSpec, opts Options, localRuntimeReady bool) (lpplan.LaunchPlan, Mode, map[string]string, error) {
	mode := opts.Mode
	if mode == ModeAuto {
		mode = ModeLive
		if !localRuntimeReady || missingLiveSecrets(app) {
			mode = ModeDemo
		}
	}
	if app.SupportLevel == registry.SupportLevelVerifyOnly {
		mode = ModeVerifyOnly
	}
	runtimeSecrets := map[string]string{}
	restore := func() {}
	if mode == ModeDemo {
		runtimeSecrets, restore = applyScopedDemoSecrets(app)
		defer restore()
	}
	if _, err := lpsecrets.NewStore(o.Store.Root()).ApplyAppEnv(app); err != nil {
		return lpplan.FailurePlan(app.ID, "local-container", opts.Principal, "ESCALATE", "ESCALATED", "ERR_LAUNCHKIT_SECRET_BINDING_INVALID"), mode, runtimeSecrets, err
	}
	compiled, err := lpplan.CompileWithRoot(app, mustSubstrate(o.Catalog, "local-container"), opts.Principal, o.Catalog.Root)
	return compiled, mode, runtimeSecrets, err
}

func (o Orchestrator) persistBlocked(result Result, compiled lpplan.LaunchPlan, reason string) (Result, error) {
	run, err := o.Executor.ExecuteLaunch(compiled, session.ExecuteOptions{Reason: reason})
	if err != nil {
		return result, err
	}
	result.Plan = &compiled
	result.Run = &run
	applyCompiledResult(&result, compiled)
	result.ResultClass = run.ResultClass
	result.RepairClass = run.RepairClass
	result.EvidenceRefs = append([]string{}, run.EvidenceRefs...)
	result.ConsoleURL = consoleURL("", run.LaunchID)
	result.OfflineVerifyCommand = run.VerificationCommand
	result.ResumeCommand = "helm up " + compiled.AppID + " --resume " + run.LaunchID
	result.Gates = bindRunGates(result.Gates, run)
	return result, nil
}

func (o Orchestrator) cloudPreflight(result Result, app registry.AppSpec, opts Options) (Result, error) {
	reason := "ERR_LAUNCHKIT_CLOUD_AUTH_REQUIRED"
	if !opts.Yes {
		reason = "ERR_LAUNCHKIT_CLOUD_APPROVAL_REQUIRED"
	}
	compiled := lpplan.FailurePlan(app.ID, string(opts.Target), opts.Principal, "ESCALATE", "ESCALATED", reason)
	result.Gates = setGate(result.Gates, "secret.preflight", GateEscalate, reason, "Cloud launch requires authenticated provider secrets before runtime.")
	return o.persistBlocked(result, compiled, "cloud preflight requires authentication and explicit approval")
}

func normalizeOptions(opts Options) Options {
	opts.Target = NormalizeTarget(string(opts.Target))
	if opts.Mode == "" {
		opts.Mode = ModeAuto
	}
	if opts.Principal == "" {
		opts.Principal = "local.operator"
	}
	return opts
}

func mustSubstrate(catalog *registry.Catalog, id string) registry.SubstrateSpec {
	substrate, ok := catalog.Substrate(id)
	if !ok {
		return registry.SubstrateSpec{ID: id, Kind: id, Availability: "missing"}
	}
	return substrate
}

func isCloudTarget(target Target) bool {
	return strings.HasPrefix(string(target), "cloud:")
}

func missingLiveSecrets(app registry.AppSpec) bool {
	groups := launchkitModelGatewayEnvGroups(app)
	if len(groups) == 0 {
		return false
	}
	for _, group := range groups {
		complete := true
		for _, envName := range group {
			if value, ok := os.LookupEnv(envName); !ok || value == "" {
				complete = false
				break
			}
		}
		if complete {
			return false
		}
	}
	return true
}

func applyScopedDemoSecrets(app registry.AppSpec) (map[string]string, func()) {
	values := map[string]string{}
	previous := map[string]*string{}
	groups := launchkitModelGatewayEnvGroups(app)
	if len(groups) == 0 {
		return values, func() {}
	}
	for _, envName := range groups[0] {
		if envName == "" {
			continue
		}
		if value, ok := os.LookupEnv(envName); ok {
			v := value
			previous[envName] = &v
		} else {
			previous[envName] = nil
		}
		values[envName] = "helm-demo-secret-redacted"
		_ = os.Setenv(envName, values[envName])
	}
	return values, func() {
		for key, value := range previous {
			if value == nil {
				_ = os.Unsetenv(key)
			} else {
				_ = os.Setenv(key, *value)
			}
		}
	}
}

func launchkitModelGatewayEnvGroups(app registry.AppSpec) [][]string {
	provider := strings.ToLower(strings.TrimSpace(app.ModelGateway.Provider))
	if provider == "byo" || provider == "multi" {
		catalog, err := modelproviders.DefaultCatalog()
		if err == nil {
			if groups, err := catalog.EnvGroupsForProviderIDs(app.ModelGateway.ProviderIDs); err == nil && len(groups) > 0 {
				return groups
			}
		}
	}
	groups := make([][]string, 0, len(app.ModelGatewayEnv))
	for _, envName := range app.ModelGatewayEnv {
		envName = strings.TrimSpace(envName)
		if envName != "" {
			groups = append(groups, []string{envName})
		}
	}
	return groups
}

func rebindLaunchID(compiled lpplan.LaunchPlan, launchID string) lpplan.LaunchPlan {
	if strings.TrimSpace(launchID) == "" {
		return compiled
	}
	compiled.LaunchID = launchID
	compiled.ActionIR = lpplan.CompileActionIR(compiled)
	compiled.TeardownIR = lpplan.CompileTeardownIR(compiled)
	if cpiOutput, err := lpplan.EvaluateActions(compiled, compiled.ActionIR); err == nil {
		compiled.CPIOutput = &cpiOutput
	}
	return compiled
}

func canonicalGates() []Gate {
	return []Gate{
		gate("environment.detect", "Environment detection", "helm up <app>"),
		gate("dependency.bootstrap", "Dependency/bootstrap", "helm up <app>"),
		gate("app.support", "AppSpec support", "helm app inspect <app>"),
		gate("f2.contract_preflight", "F2 contract preflight", "helm app preflight <app> --json"),
		gate("artifact.digest", "OCI digest verification", "helm app inspect <app>"),
		gate("artifact.signature", "Signature verification", "helm app inspect <app>"),
		gate("artifact.sbom", "SBOM verification", "helm app inspect <app>"),
		gate("artifact.scan", "Scan verification", "helm app inspect <app>"),
		gate("launchplan.compile", "LaunchPlan compile", "helm app preflight <app>"),
		gate("policy.compile", "Policy/CPI compile", "helm policy simulate <app>"),
		gate("secret.preflight", "Secret preflight", "helm secret list"),
		gate("sandbox.grant", "Sandbox grant", "helm sandbox inspect <run_id>"),
		gate("mcp.quarantine", "MCP registry/quarantine", "helm mcp quarantine"),
		gate("runtime.launch", "Runtime launch", "helm run open <run_id>"),
		gate("healthcheck", "Healthcheck", "helm run logs <run_id>"),
		gate("receipts.emit", "Receipts", "helm run receipts <run_id>"),
		gate("evidence.export", "EvidencePack export", "helm evidence export <run_id>"),
		gate("offline.verify", "Offline verify command", "helm-ai-kernel verify --bundle <file>"),
		gate("console.deeplink", "Console deep link", "helm run open <run_id>"),
	}
}

func applyCompiledResult(result *Result, compiled lpplan.LaunchPlan) {
	if result == nil {
		return
	}
	result.ContractPreflight = compiled.ContractPreflight
	result.ResultClass = compiled.ResultClass
	result.RepairClass = compiled.RepairClass
	result.SupportLevel = compiled.SupportLevel
	result.EvidenceRefs = append([]string{}, compiled.EvidenceRefs...)
}

func bindContractGate(gates []Gate, compiled lpplan.LaunchPlan) []Gate {
	if compiled.ContractPreflight == nil {
		return setGate(gates, "f2.contract_preflight", statusFromVerdict(compiled.KernelVerdict), compiled.ReasonCode, "Contract preflight was not emitted.")
	}
	status := statusFromVerdict(compiled.ContractPreflight.Verdict)
	summary := "Contract preflight proved image, command, sandbox, egress proxy, writable paths, secret projection, MCP manifests, healthcheck, EvidencePack export, and offline verify before attack execution."
	if compiled.ContractPreflight.Verdict != "ALLOW" {
		summary = "Contract preflight failed before any attack prompt could run."
	}
	return setGate(gates, "f2.contract_preflight", status, compiled.ReasonCode, summary)
}

func gate(id, label, cli string) Gate {
	return Gate{ID: id, Label: label, Status: GatePending, CLIEquivalent: cli}
}

func setGate(gates []Gate, id string, status GateStatus, reason, summary string) []Gate {
	for index := range gates {
		if gates[index].ID == id {
			gates[index].Status = status
			gates[index].ReasonCode = reason
			gates[index].Summary = summary
			return gates
		}
	}
	return append(gates, Gate{ID: id, Status: status, ReasonCode: reason, Summary: summary})
}

func applySupplyChainGates(gates []Gate, report SupplyChainReport) []Gate {
	status := GateAllow
	if report.ReasonCode != "" {
		status = GateDeny
	}
	gates = setGate(gates, "artifact.digest", boolGate(report.ArtifactDigestVerified, status), report.ReasonCode, "Pinned OCI digest checked against AppSpec and supply-chain evidence.")
	gates = setGate(gates, "artifact.signature", boolGate(report.SignatureVerified, status), report.ReasonCode, "Cosign signature evidence checked against the pinned digest.")
	gates = setGate(gates, "artifact.sbom", boolGate(report.SBOMVerified, status), report.ReasonCode, "SBOM evidence checked.")
	gates = setGate(gates, "artifact.scan", boolGate(report.ScanVerified, status), report.ReasonCode, "Vulnerability scan evidence checked.")
	return gates
}

func boolGate(ok bool, failure GateStatus) GateStatus {
	if ok {
		return GateAllow
	}
	return failure
}

func statusFromVerdict(verdict string) GateStatus {
	switch verdict {
	case "ALLOW":
		return GateAllow
	case "DENY":
		return GateDeny
	default:
		return GateEscalate
	}
}

func bindRunGates(gates []Gate, run session.LaunchRun) []Gate {
	status := statusFromVerdict(run.KernelVerdict)
	if run.KernelVerdict != "ALLOW" {
		gates = setGate(gates, "runtime.launch", GateSkipped, run.ReasonCode, "No runtime was launched because a prior gate did not allow.")
		gates = setGate(gates, "healthcheck", GateSkipped, run.ReasonCode, "Healthcheck was blocked before runtime.")
	} else if run.State == session.StateRunning && len(run.StartReceiptRefs) > 0 && run.RuntimeHandles.ContainerID != "" {
		gates = setGate(gates, "runtime.launch", GateAllow, "", "Runtime start receipt and handle are attached to the run.")
		if len(run.HealthcheckRefs) > 0 {
			gates = setGate(gates, "healthcheck", GateAllow, "", "Healthcheck receipt is attached to the run.")
		} else {
			gates = setGate(gates, "healthcheck", GateEscalate, repairReason(run), "Healthcheck did not certify a running workload; repair is required before RUNNING.")
		}
	} else if len(run.StartReceiptRefs) > 0 && run.RuntimeHandles.ContainerID != "" {
		gates = setGate(gates, "runtime.launch", GateEscalate, repairReason(run), "Runtime returned a handle but did not reach RUNNING; repair is required before production proof.")
		gates = setGate(gates, "healthcheck", GateEscalate, repairReason(run), "Healthcheck did not certify RUNNING; repair is required before production proof.")
	} else {
		gates = setGate(gates, "runtime.launch", GateEscalate, repairReason(run), "Runtime did not return a start receipt and handle; repair is required before RUNNING.")
		gates = setGate(gates, "healthcheck", GateSkipped, repairReason(run), "Healthcheck was blocked because runtime did not start.")
	}
	receiptStatus, receiptReason, receiptSummary := receiptGateStatus(run, status)
	evidenceStatus, evidenceReason := evidenceGateStatus(run, status)
	verifyStatus, verifyReason := verifyGateStatus(run, status)
	gates = setGate(gates, "receipts.emit", receiptStatus, receiptReason, receiptSummary)
	gates = setGate(gates, "evidence.export", evidenceStatus, evidenceReason, "EvidencePack refs are attached to the run.")
	gates = setGate(gates, "offline.verify", verifyStatus, verifyReason, run.VerificationCommand)
	gates = setGate(gates, "console.deeplink", status, run.ReasonCode, "Console can open the receipt-backed run.")
	return gates
}

func receiptGateStatus(run session.LaunchRun, fallback GateStatus) (GateStatus, string, string) {
	if run.KernelVerdict != "ALLOW" {
		return fallback, run.ReasonCode, "Receipt refs are blocked because a prior gate did not allow."
	}
	if len(run.StartReceiptRefs) == 0 {
		return GateEscalate, repairReason(run), "Runtime start receipt is missing; repair is required before RUNNING."
	}
	if requiresEgressReceipt(run) && len(run.EgressReceiptRefs) == 0 {
		return GateEscalate, "ERR_LAUNCHKIT_EGRESS_RECEIPT_MISSING", "Launch-scoped egress receipt is missing; repair is required before production proof."
	}
	return GateAllow, "", "Receipt refs are attached to the run."
}

func evidenceGateStatus(run session.LaunchRun, fallback GateStatus) (GateStatus, string) {
	if run.KernelVerdict != "ALLOW" {
		return fallback, run.ReasonCode
	}
	if len(run.EvidencePackRefs) == 0 {
		return GateEscalate, "ERR_LAUNCHKIT_EVIDENCEPACK_MISSING"
	}
	return GateAllow, ""
}

func verifyGateStatus(run session.LaunchRun, fallback GateStatus) (GateStatus, string) {
	if run.KernelVerdict != "ALLOW" {
		return fallback, run.ReasonCode
	}
	if strings.TrimSpace(run.VerificationCommand) == "" {
		return GateEscalate, "ERR_LAUNCHKIT_OFFLINE_VERIFY_COMMAND_MISSING"
	}
	return GateAllow, ""
}

func requiresEgressReceipt(run session.LaunchRun) bool {
	handles := run.RuntimeHandles
	return handles.EgressNetworkName != "" || handles.EgressProxyID != "" || handles.EgressProxyName != ""
}

func repairReason(run session.LaunchRun) string {
	if run.ReasonCode != "" {
		return run.ReasonCode
	}
	if run.State == session.StateRepairRequired {
		return "ERR_LAUNCHKIT_RUNTIME_REPAIR_REQUIRED"
	}
	return ""
}

func secretSummary(mode Mode, refs []string) string {
	if mode == ModeDemo {
		return "Demo mode generated scoped, redacted demo secrets; no real external side effects are enabled."
	}
	if len(refs) == 0 {
		return "No required runtime secrets."
	}
	return "Required runtime secret grants are present."
}

func consoleURL(baseURL, runID string) string {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		baseURL = "http://127.0.0.1:7714"
	}
	if runID == "" {
		return baseURL
	}
	return baseURL + "/runs/" + runID
}
