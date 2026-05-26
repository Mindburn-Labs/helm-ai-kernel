package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	lpimporter "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/importer"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	lppromotion "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/promotion"
	lpprovision "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/provision"
	lpreceipts "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/receipts"
	lpregistry "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	lprepair "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/repair"
	lpsecrets "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/secrets"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/session"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier"
)

func init() {
	Register(Subcommand{Name: "launch", Aliases: []string{"launchpad"}, Usage: "Launch verified AI apps through HELM Launchpad", RunFn: runLaunchCmd})
}

func runLaunchCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel launch <matrix|apps|substrates|plan|status|logs|repair|delete|evidence|promote|secrets|imports|app> [args]")
		return 2
	}
	catalog, err := lpregistry.LoadCatalog("")
	if err != nil {
		fmt.Fprintf(stderr, "launchpad registry error: %v\n", err)
		return 1
	}
	if err := catalog.Validate(); err != nil {
		fmt.Fprintf(stderr, "launchpad validation error: %v\n", err)
		return 1
	}
	switch args[0] {
	case "matrix":
		return writeLaunchJSON(stdout, catalog.Matrix())
	case "apps":
		return writeLaunchJSON(stdout, catalog.Apps)
	case "substrates":
		return writeLaunchJSON(stdout, catalog.Substrates)
	case "plan":
		return runLaunchPlan(args[1:], catalog, stdout, stderr)
	case "status":
		return runLaunchStatus(args[1:], stdout, stderr)
	case "logs":
		return runLaunchLogs(args[1:], stdout, stderr)
	case "repair":
		return runLaunchRepair(args[1:], stdout, stderr)
	case "delete":
		return runLaunchDelete(args[1:], stdout, stderr)
	case "evidence":
		return runLaunchEvidence(args[1:], stdout, stderr)
	case "promote":
		return runLaunchPromote(args[1:], catalog, stdout, stderr)
	case "secrets":
		return runLaunchSecrets(args[1:], stdout, stderr)
	case "imports":
		return runLaunchImports(args[1:], stdout, stderr)
	default:
		return runLaunchStart(args, catalog, stdout, stderr)
	}
}

type launchEvidenceExport struct {
	LaunchID         string                `json:"launch_id"`
	EvidencePackRefs []string              `json:"evidence_pack_refs"`
	Checks           []launchEvidenceCheck `json:"checks"`
	State            session.State         `json:"state"`
	KernelVerdict    string                `json:"kernel_verdict"`
}

type launchEvidenceCheck struct {
	Ref      string `json:"ref"`
	Exists   bool   `json:"exists"`
	Verified bool   `json:"verified"`
	Summary  string `json:"summary,omitempty"`
	Error    string `json:"error,omitempty"`
}

func runLaunchEvidence(args []string, stdout, stderr io.Writer) int {
	export := false
	jsonOut := false
	outputDir := ""
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		switch arg := args[i]; arg {
		case "--export":
			export = true
		case "--json":
			jsonOut = true
		case "--output":
			if i+1 >= len(args) {
				fmt.Fprintln(stderr, "launch evidence --output requires a directory")
				return 2
			}
			outputDir = args[i+1]
			export = true
			jsonOut = true
			i++
		default:
			rest = append(rest, arg)
		}
	}
	if len(rest) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel launch evidence <launch_id> --export --json [--output <dir>]")
		return 2
	}
	if !export {
		fmt.Fprintln(stderr, "launch evidence requires --export to avoid implying a new evidence mutation")
		return 2
	}
	run, err := session.NewStore("").Get(rest[0])
	if err != nil {
		fmt.Fprintf(stderr, "launch evidence error: %v\n", err)
		return 1
	}
	result := launchEvidenceExport{
		LaunchID:         run.LaunchID,
		EvidencePackRefs: run.EvidencePackRefs,
		Checks:           verifyLaunchEvidenceRefs(run.EvidencePackRefs),
		State:            run.State,
		KernelVerdict:    run.KernelVerdict,
	}
	if outputDir != "" {
		if err := os.MkdirAll(outputDir, 0o700); err != nil {
			fmt.Fprintf(stderr, "launch evidence output error: %v\n", err)
			return 1
		}
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return 1
		}
		if err := os.WriteFile(filepath.Join(outputDir, "launch_evidence_export.json"), append(data, '\n'), 0o600); err != nil {
			fmt.Fprintf(stderr, "launch evidence output error: %v\n", err)
			return 1
		}
	}
	if jsonOut {
		return writeLaunchJSON(stdout, result)
	}
	for _, ref := range result.EvidencePackRefs {
		fmt.Fprintln(stdout, ref)
	}
	return 0
}

func verifyLaunchEvidenceRefs(refs []string) []launchEvidenceCheck {
	checks := make([]launchEvidenceCheck, 0, len(refs))
	for _, ref := range refs {
		check := launchEvidenceCheck{Ref: ref}
		info, err := os.Stat(ref)
		if err != nil {
			check.Error = err.Error()
			checks = append(checks, check)
			continue
		}
		check.Exists = true
		verifyTarget := ref
		var cleanup func()
		if !info.IsDir() {
			tempDir, err := os.MkdirTemp("", "helm-launch-evidence-*")
			if err != nil {
				check.Error = err.Error()
				checks = append(checks, check)
				continue
			}
			cleanup = func() { _ = os.RemoveAll(tempDir) }
			if err := extractEvidenceArchive(ref, tempDir); err != nil {
				cleanup()
				check.Error = err.Error()
				checks = append(checks, check)
				continue
			}
			verifyTarget = tempDir
		}
		report, err := verifier.VerifyBundle(verifyTarget)
		if cleanup != nil {
			cleanup()
		}
		if err != nil {
			check.Error = err.Error()
			checks = append(checks, check)
			continue
		}
		check.Verified = report.Verified
		check.Summary = report.Summary
		checks = append(checks, check)
	}
	return checks
}

func runLaunchPlan(args []string, catalog *lpregistry.Catalog, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("launch plan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) < 2 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel launch plan <app> <substrate> --json")
		return 2
	}
	compiled, code := compileLaunchPlan(catalog, rest[0], rest[1], "local.operator", stderr)
	if code != 0 && !*jsonOut {
		return code
	}
	return writeLaunchJSON(stdout, compiled)
}

func runLaunchStart(args []string, catalog *lpregistry.Catalog, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel launch <app> <substrate> [--headless] [--output json]")
		return 2
	}
	fs := flag.NewFlagSet("launch start", flag.ContinueOnError)
	fs.SetOutput(stderr)
	headless := fs.Bool("headless", false, "run without TUI")
	output := fs.String("output", "text", "text or json")
	liveCloudBeta := fs.Bool("live-cloud-beta", false, "allow opt-in cloud beta provisioning gates")
	approvalID := fs.String("approval", "", "approval receipt id for cloud beta")
	costCeiling := fs.Float64("cost-ceiling-usd", 0, "maximum approved cloud cost for this launch")
	if err := fs.Parse(args[2:]); err != nil {
		return 2
	}
	compiled, code := compileLaunchPlan(catalog, args[0], args[1], "local.operator", stderr)
	if code != 0 {
		if *output == "json" {
			_ = writeLaunchJSON(stdout, compiled)
		}
		return code
	}
	substrate, _ := catalog.Substrate(args[1])
	if substrate.Kind == "cloud" {
		return runLaunchCloudGate(compiled, substrate, *liveCloudBeta, *approvalID, *costCeiling, stdout, stderr)
	}
	run, err := session.NewExecutor(session.NewStore("")).ExecuteLaunch(compiled, session.ExecuteOptions{Reason: "launch requested through CLI"})
	if err != nil {
		fmt.Fprintf(stderr, "launch session error: %v\n", err)
		return 1
	}
	if *headless || *output == "json" {
		return writeLaunchJSON(stdout, run)
	}
	fmt.Fprintf(stdout, "Launch %s recorded with state %s and verdict %s.\n", run.LaunchID, run.State, run.KernelVerdict)
	return 0
}

type launchCloudGateResponse struct {
	LaunchID             string            `json:"launch_id"`
	AppID                string            `json:"app_id"`
	AppVersion           string            `json:"app_version"`
	SubstrateID          string            `json:"substrate_id"`
	Provider             string            `json:"provider"`
	KernelVerdict        string            `json:"kernel_verdict"`
	Status               string            `json:"status"`
	ReasonCode           string            `json:"reason_code"`
	ApprovalID           string            `json:"approval_id,omitempty"`
	CostCeilingUSD       float64           `json:"cost_ceiling_usd,omitempty"`
	EstimatedCostUSD     float64           `json:"estimated_cost_usd"`
	ProviderResourceRefs map[string]string `json:"provider_resource_refs"`
	IdempotencyKey       string            `json:"idempotency_key"`
	ReconcileStatus      string            `json:"reconcile_status"`
	TeardownRequired     bool              `json:"teardown_required"`
	EvidencePackRefs     []string          `json:"evidence_pack_refs"`
}

func runLaunchCloudGate(compiled plan.LaunchPlan, substrate lpregistry.SubstrateSpec, live bool, approvalID string, costCeiling float64, stdout, stderr io.Writer) int {
	provider := substrate.Provisioner
	key := lpprovision.IdempotencyKey(provider, compiled.LaunchID, compiled.PlanHash)
	response := launchCloudGateResponse{
		LaunchID:             compiled.LaunchID,
		AppID:                compiled.AppID,
		AppVersion:           compiled.AppVersion,
		SubstrateID:          substrate.ID,
		Provider:             provider,
		KernelVerdict:        "ESCALATE",
		Status:               "ESCALATED",
		ReasonCode:           "ERR_LAUNCHPAD_CLOUD_APPROVAL_REQUIRED",
		ApprovalID:           approvalID,
		CostCeilingUSD:       costCeiling,
		EstimatedCostUSD:     estimateCloudLaunchCost(substrate.ID),
		ProviderResourceRefs: map[string]string{},
		IdempotencyKey:       key,
		ReconcileStatus:      string(lpprovision.ReconcileRequired),
		TeardownRequired:     true,
		EvidencePackRefs:     []string{},
	}
	if !live {
		fmt.Fprintln(stderr, "cloud Launchpad substrates require --live-cloud-beta and remain dry-run by default")
		if writeLaunchJSON(stdout, response) != 0 {
			return 1
		}
		return 1
	}
	if approvalID == "" || costCeiling <= 0 {
		fmt.Fprintln(stderr, "cloud Launchpad beta requires --approval and --cost-ceiling-usd")
		if writeLaunchJSON(stdout, response) != 0 {
			return 1
		}
		return 1
	}
	if costCeiling < response.EstimatedCostUSD {
		response.ReasonCode = "ERR_LAUNCHPAD_CLOUD_COST_CEILING_TOO_LOW"
		fmt.Fprintln(stderr, "cloud Launchpad beta cost ceiling is below the estimated cost")
		if writeLaunchJSON(stdout, response) != 0 {
			return 1
		}
		return 1
	}
	result, receiptRefs, err := createCloudLaunch(compiled, substrate, approvalID, costCeiling)
	if err != nil {
		response.ReasonCode = cloudGateReason(err)
		response.Status = "ESCALATED"
		fmt.Fprintf(stderr, "cloud Launchpad beta provisioning failed: %v\n", err)
		if writeLaunchJSON(stdout, response) != 0 {
			return 1
		}
		return 1
	}
	response.KernelVerdict = "ALLOW"
	response.Status = "PROVISIONED"
	response.ReasonCode = "LAUNCHPAD_CLOUD_BETA_PROVISIONED"
	response.ProviderResourceRefs = result.ResourceRefs
	response.IdempotencyKey = result.IdempotencyKey
	response.ReconcileStatus = string(result.ReconcileStatus)
	response.EvidencePackRefs = result.EvidencePackRefs
	evidenceRefs, err := persistCloudLaunch(compiled, substrate, response, receiptRefs)
	if err != nil {
		fmt.Fprintf(stderr, "cloud Launchpad beta evidence error: %v\n", err)
		if writeLaunchJSON(stdout, response) != 0 {
			return 1
		}
		return 1
	}
	response.EvidencePackRefs = evidenceRefs
	if writeLaunchJSON(stdout, response) != 0 {
		return 1
	}
	return 0
}

func estimateCloudLaunchCost(substrateID string) float64 {
	switch substrateID {
	case "digitalocean":
		return 0.01
	case "hetzner":
		return 0.01
	default:
		return 0
	}
}

type cloudProvisionResult struct {
	ResourceRefs     map[string]string
	IdempotencyKey   string
	ReconcileStatus  lpprovision.ReconcileStatus
	EvidencePackRefs []string
}

func createCloudLaunch(compiled plan.LaunchPlan, substrate lpregistry.SubstrateSpec, approvalID string, costCeiling float64) (cloudProvisionResult, []string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	name := cloudResourceName(compiled)
	switch substrate.Provisioner {
	case "digitalocean":
		token := firstEnv("DIGITALOCEAN_TOKEN", "HELM_LAUNCHPAD_DIGITALOCEAN_TOKEN")
		if token == "" {
			return cloudProvisionResult{}, nil, errCloudProviderSecretMissing("digitalocean")
		}
		provisioner := lpprovision.DigitalOceanProvisioner{
			AllowLiveWrites: true,
			Token:           token,
			Endpoint:        os.Getenv("HELM_LAUNCHPAD_DIGITALOCEAN_ENDPOINT"),
		}
		result, err := provisioner.Create(ctx, lpprovision.DigitalOceanProvisionRequest{
			LaunchID:     compiled.LaunchID,
			PlanHash:     compiled.PlanHash,
			Name:         name,
			Region:       firstEnvValue("HELM_LAUNCHPAD_DO_REGION", "nyc3"),
			Size:         firstEnvValue("HELM_LAUNCHPAD_DO_SIZE", "s-1vcpu-1gb"),
			Image:        firstEnvValue("HELM_LAUNCHPAD_DO_IMAGE", "ubuntu-24-04-x64"),
			Tags:         cloudTags(compiled, approvalID),
			FirewallName: name + "-firewall",
		})
		if err != nil {
			return cloudProvisionResult{}, nil, err
		}
		return cloudProvisionResult{
			ResourceRefs:    result.ResourceRefs,
			IdempotencyKey:  result.IdempotencyKey,
			ReconcileStatus: result.ReconcileOutcome.Status,
		}, result.ReceiptRefs, nil
	case "hetzner":
		token := firstEnv("HCLOUD_TOKEN", "HELM_LAUNCHPAD_HETZNER_TOKEN")
		if token == "" {
			return cloudProvisionResult{}, nil, errCloudProviderSecretMissing("hetzner")
		}
		provisioner := lpprovision.HetznerProvisioner{
			AllowLiveWrites: true,
			Token:           token,
			Endpoint:        os.Getenv("HELM_LAUNCHPAD_HETZNER_ENDPOINT"),
		}
		result, err := provisioner.Create(ctx, lpprovision.HetznerProvisionRequest{
			LaunchID:     compiled.LaunchID,
			PlanHash:     compiled.PlanHash,
			Name:         name,
			Location:     firstEnvValue("HELM_LAUNCHPAD_HETZNER_LOCATION", "nbg1"),
			ServerType:   firstEnvValue("HELM_LAUNCHPAD_HETZNER_SERVER_TYPE", "cx22"),
			Image:        firstEnvValue("HELM_LAUNCHPAD_HETZNER_IMAGE", "ubuntu-24.04"),
			Labels:       cloudLabels(compiled, approvalID, costCeiling),
			FirewallName: name + "-firewall",
		})
		if err != nil {
			return cloudProvisionResult{}, nil, err
		}
		return cloudProvisionResult{
			ResourceRefs:    result.ResourceRefs,
			IdempotencyKey:  result.IdempotencyKey,
			ReconcileStatus: result.ReconcileOutcome.Status,
		}, result.ReceiptRefs, nil
	default:
		return cloudProvisionResult{}, nil, fmt.Errorf("unsupported cloud provisioner %q", substrate.Provisioner)
	}
}

func persistCloudLaunch(compiled plan.LaunchPlan, substrate lpregistry.SubstrateSpec, response launchCloudGateResponse, providerReceiptRefs []string) ([]string, error) {
	store := session.NewStore("")
	approvalReceipt := lpreceipts.NewReceipt("launchpad.cloud_approval", compiled.LaunchID, "ALLOW", map[string]any{
		"approval_id":        response.ApprovalID,
		"cost_ceiling_usd":   response.CostCeilingUSD,
		"estimated_cost_usd": response.EstimatedCostUSD,
		"provider":           response.Provider,
		"substrate_id":       response.SubstrateID,
	})
	provisionReceipt := lpreceipts.NewReceipt("launchpad.cloud_provision", compiled.LaunchID, "ALLOW", map[string]any{
		"provider":               response.Provider,
		"resource_refs":          response.ProviderResourceRefs,
		"idempotency_key":        response.IdempotencyKey,
		"reconcile_status":       response.ReconcileStatus,
		"teardown_required":      response.TeardownRequired,
		"provider_receipt_refs":  providerReceiptRefs,
		"runtime_handoff_status": "provider-vm-provisioned",
	})
	healthReceipt := lpreceipts.NewReceipt("launchpad.cloud_healthcheck", compiled.LaunchID, "ALLOW", map[string]any{
		"status": "provider-resource-provisioned",
		"type":   "cloud-beta-provisioner",
	})
	artifacts := map[string][]byte{}
	addJSON(artifacts, "launch_plan.json", compiled)
	addJSON(artifacts, "cloud_launch_response.json", response)
	addJSON(artifacts, "cloud_provision_result.json", map[string]any{
		"provider":              response.Provider,
		"resource_refs":         response.ProviderResourceRefs,
		"idempotency_key":       response.IdempotencyKey,
		"reconcile_status":      response.ReconcileStatus,
		"provider_receipt_refs": providerReceiptRefs,
	})
	addJSON(artifacts, "receipts/launchpad-cloud-approval.json", approvalReceipt)
	addJSON(artifacts, "receipts/launchpad-cloud-provision.json", provisionReceipt)
	addJSON(artifacts, "receipts/launchpad-cloud-healthcheck.json", healthReceipt)
	run := session.LaunchRun{
		LaunchID:            compiled.LaunchID,
		AppID:               compiled.AppID,
		AppVersion:          compiled.AppVersion,
		SubstrateID:         compiled.SubstrateID,
		Principal:           compiled.Principal,
		PlanHash:            compiled.PlanHash,
		ArtifactImage:       compiled.ArtifactImage,
		ArtifactDigest:      compiled.ArtifactDigest,
		State:               session.StateProvisioning,
		KernelVerdict:       "ALLOW",
		Reason:              "cloud beta provider resources provisioned behind approval and cost ceiling receipts",
		BoundaryRecordRefs:  []string{"boundary://launchpad/" + compiled.LaunchID},
		SandboxGrantRefs:    []string{provisionReceipt.ReceiptID},
		LaunchReceiptRefs:   append(providerReceiptRefs, provisionReceipt.ReceiptID),
		HealthcheckRefs:     []string{healthReceipt.ReceiptID},
		EvidencePackRefs:    []string{},
		RuntimeHandles:      session.RuntimeHandles{CloudResourceIDs: response.ProviderResourceRefs},
		IdempotencyKeys:     map[string]string{"cloud": response.IdempotencyKey, "teardown": "teardown:" + response.IdempotencyKey},
		VerificationCommand: "",
		TeardownCommand:     "helm-ai-kernel launch delete " + compiled.LaunchID + " --cascade",
	}
	if run.RuntimeHandles.CloudResourceIDs == nil {
		run.RuntimeHandles.CloudResourceIDs = map[string]string{}
	}
	run.RuntimeHandles.CloudResourceIDs["provider"] = substrate.Provisioner
	packRef, err := lpreceipts.WriteEvidencePack(store.Root(), run.LaunchID, artifacts)
	if err != nil {
		return nil, err
	}
	run.EvidencePackRefs = appendUniqueLaunchString(run.EvidencePackRefs, packRef)
	run.EvidenceGraphRefs = appendUniqueLaunchString(run.EvidenceGraphRefs, packRef+"/04_EXPORTS/launchpad_evidence_graph.json")
	if archiveRef, err := lpreceipts.WriteEvidencePackArchive(packRef); err == nil {
		run.EvidencePackRefs = appendUniqueLaunchString(run.EvidencePackRefs, archiveRef)
		run.VerificationCommand = "helm-ai-kernel verify --bundle " + archiveRef
	} else {
		run.VerificationCommand = "helm-ai-kernel verify --bundle " + packRef
	}
	logPath, _ := store.AppendLog(run.LaunchID, "launchpad cloud beta provisioned provider resources without storing provider secrets")
	run.LogPath = logPath
	if err := store.Save(run); err != nil {
		return nil, err
	}
	return run.EvidencePackRefs, nil
}

type cloudProviderSecretMissingError struct {
	provider string
}

func (e cloudProviderSecretMissingError) Error() string {
	return e.provider + " provider token required"
}

func errCloudProviderSecretMissing(provider string) error {
	return cloudProviderSecretMissingError{provider: provider}
}

func cloudGateReason(err error) string {
	if _, ok := err.(cloudProviderSecretMissingError); ok {
		return "ERR_LAUNCHPAD_CLOUD_PROVIDER_SECRET_MISSING"
	}
	return "ERR_LAUNCHPAD_CLOUD_PROVISION_FAILED"
}

func cloudResourceName(compiled plan.LaunchPlan) string {
	id := strings.ToLower(strings.ReplaceAll(compiled.LaunchID, "_", "-"))
	if len(id) > 36 {
		id = id[:36]
	}
	return "helm-launchpad-" + id
}

func cloudTags(compiled plan.LaunchPlan, approvalID string) []string {
	return []string{
		"helm-launchpad-app-" + compiled.AppID,
		"helm-launchpad-substrate-" + compiled.SubstrateID,
		"helm-launchpad-approval-" + sanitizeCloudTag(approvalID),
	}
}

func cloudLabels(compiled plan.LaunchPlan, approvalID string, costCeiling float64) []string {
	return []string{
		"helm-launchpad-app=" + sanitizeCloudTag(compiled.AppID),
		"helm-launchpad-substrate=" + sanitizeCloudTag(compiled.SubstrateID),
		"helm-launchpad-approval=" + sanitizeCloudTag(approvalID),
		"helm-launchpad-cost-ceiling-usd=" + sanitizeCloudTag(fmt.Sprintf("%.2f", costCeiling)),
	}
}

func sanitizeCloudTag(value string) string {
	value = strings.ToLower(value)
	replacer := strings.NewReplacer(" ", "-", "/", "-", ":", "-", "@", "-", ".", "-")
	value = replacer.Replace(value)
	if value == "" {
		return "unset"
	}
	if len(value) > 48 {
		return value[:48]
	}
	return value
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func firstEnvValue(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func compileLaunchPlan(catalog *lpregistry.Catalog, appID, substrateID, principal string, stderr io.Writer) (plan.LaunchPlan, int) {
	app, ok := catalog.App(appID)
	if !ok {
		fmt.Fprintf(stderr, "unknown app: %s\n", appID)
		return plan.FailurePlan(appID, substrateID, principal, "DENY", "DENIED", "ERR_LAUNCHPAD_UNKNOWN_APP"), 1
	}
	substrate, ok := catalog.Substrate(substrateID)
	if !ok {
		fmt.Fprintf(stderr, "unknown substrate: %s\n", substrateID)
		return plan.FailurePlan(appID, substrateID, principal, "DENY", "DENIED", "ERR_LAUNCHPAD_UNKNOWN_SUBSTRATE"), 1
	}
	if _, err := lpsecrets.NewStore("").ApplyAppEnv(app); err != nil {
		fmt.Fprintf(stderr, "launch secrets error: %v\n", err)
		return plan.FailurePlan(appID, substrateID, principal, "ESCALATE", "ESCALATED", "ERR_LAUNCHPAD_SECRET_BINDING_INVALID"), 1
	}
	compiled, err := plan.CompileWithRoot(app, substrate, principal, catalog.Root)
	if err != nil {
		fmt.Fprintf(stderr, "launch plan escalated: %v\n", err)
	}
	return compiled, 0
}

func runLaunchStatus(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel launch status <launch_id> --json")
		return 2
	}
	run, err := session.NewStore("").Get(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "launch status error: %v\n", err)
		return 1
	}
	return writeLaunchJSON(stdout, run)
}

func runLaunchLogs(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel launch logs <launch_id>")
		return 2
	}
	data, err := session.NewStore("").ReadLog(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "launch logs error: %v\n", err)
		return 1
	}
	redacted := redactLaunchLog(string(data), os.Getenv("OPENAI_API_KEY"), os.Getenv("OPENROUTER_API_KEY"))
	fmt.Fprint(stdout, redacted)
	return 0
}

func runLaunchRepair(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel launch repair <launch_id>")
		return 2
	}
	store := session.NewStore("")
	run, err := store.Get(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "launch repair error: %v\n", err)
		return 1
	}
	diagnostics := []lprepair.Diagnostic{{Code: "ERR_REPAIR_REQUIRES_OPERATOR_APPROVAL", Message: "repair is deterministic planning only until operator approval is recorded"}}
	if run.State == session.StateEscalated {
		diagnostics = append(diagnostics, lprepair.Diagnostic{Code: "ERR_LAUNCH_ESCALATED", Message: run.Reason})
	}
	return writeLaunchJSON(stdout, lprepair.EscalatedPlan(args[0], diagnostics))
}

func runLaunchDelete(args []string, stdout, stderr io.Writer) int {
	cascade := false
	rest := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "--cascade" {
			cascade = true
			continue
		}
		rest = append(rest, arg)
	}
	if len(rest) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel launch delete <launch_id> --cascade")
		return 2
	}
	store := session.NewStore("")
	run, err := store.Get(rest[0])
	if err != nil {
		fmt.Fprintf(stderr, "launch delete error: %v\n", err)
		return 1
	}
	cloudArtifacts, cloudReceiptRefs, err := deleteCloudResourcesForRun(run)
	if err != nil {
		fmt.Fprintf(stderr, "launch delete error: %v\n", err)
		return 1
	}
	if len(cloudArtifacts) > 0 {
		if run.RuntimeHandles.CloudResourceIDs == nil {
			run.RuntimeHandles.CloudResourceIDs = map[string]string{}
		}
		run.RuntimeHandles.CloudResourceIDs["teardown_reconciled"] = "true"
		if err := store.Save(run); err != nil {
			fmt.Fprintf(stderr, "launch delete save error: %v\n", err)
			return 1
		}
	}
	deleted, err := session.NewExecutor(store).DeleteLaunch(rest[0], cascade)
	if err != nil {
		fmt.Fprintf(stderr, "launch delete error: %v\n", err)
		return 1
	}
	if len(cloudArtifacts) > 0 {
		deleted.TeardownReceiptRefs = append(deleted.TeardownReceiptRefs, cloudReceiptRefs...)
		deleted.Reason = "teardown receipt emitted after Launchpad-owned local and cloud state reconciliation"
		if refs, err := appendLaunchEvidencePack(store, &deleted, cloudArtifacts); err != nil {
			fmt.Fprintf(stderr, "launch delete evidence error: %v\n", err)
			return 1
		} else {
			deleted.EvidencePackRefs = refs
		}
		if err := store.Save(deleted); err != nil {
			fmt.Fprintf(stderr, "launch delete save error: %v\n", err)
			return 1
		}
	}
	return writeLaunchJSON(stdout, deleted)
}

func deleteCloudResourcesForRun(run session.LaunchRun) (map[string][]byte, []string, error) {
	if run.RuntimeHandles.CloudResourceIDs == nil || len(run.RuntimeHandles.CloudResourceIDs) == 0 {
		return nil, nil, nil
	}
	provider := run.RuntimeHandles.CloudResourceIDs["provider"]
	if provider == "" {
		provider = run.SubstrateID
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	switch provider {
	case "digitalocean":
		token := firstEnv("DIGITALOCEAN_TOKEN", "HELM_LAUNCHPAD_DIGITALOCEAN_TOKEN")
		if token == "" {
			return nil, nil, errCloudProviderSecretMissing("digitalocean")
		}
		dropletID, err := parseCloudInt64(run.RuntimeHandles.CloudResourceIDs["droplet"])
		if err != nil {
			return nil, nil, err
		}
		provisioner := lpprovision.DigitalOceanProvisioner{
			AllowLiveWrites: true,
			Token:           token,
			Endpoint:        os.Getenv("HELM_LAUNCHPAD_DIGITALOCEAN_ENDPOINT"),
		}
		teardown, err := provisioner.Delete(ctx, lpprovision.DigitalOceanDeleteRequest{
			LaunchID:   run.LaunchID,
			PlanHash:   run.PlanHash,
			DropletID:  dropletID,
			FirewallID: run.RuntimeHandles.CloudResourceIDs["firewall"],
		})
		if err != nil {
			return nil, nil, err
		}
		reconcile, err := provisioner.Reconcile(ctx, run.LaunchID)
		if err != nil {
			return nil, nil, err
		}
		return cloudDeleteArtifacts(run, provider, teardown, reconcile), []string{teardown.ReceiptID, "receipt:digitalocean:" + run.LaunchID + ":post-delete-reconcile"}, nil
	case "hetzner":
		token := firstEnv("HCLOUD_TOKEN", "HELM_LAUNCHPAD_HETZNER_TOKEN")
		if token == "" {
			return nil, nil, errCloudProviderSecretMissing("hetzner")
		}
		serverID, err := parseCloudInt64(run.RuntimeHandles.CloudResourceIDs["server"])
		if err != nil {
			return nil, nil, err
		}
		firewallID, err := parseCloudInt64(run.RuntimeHandles.CloudResourceIDs["firewall"])
		if err != nil {
			return nil, nil, err
		}
		provisioner := lpprovision.HetznerProvisioner{
			AllowLiveWrites: true,
			Token:           token,
			Endpoint:        os.Getenv("HELM_LAUNCHPAD_HETZNER_ENDPOINT"),
		}
		teardown, err := provisioner.Delete(ctx, lpprovision.HetznerDeleteRequest{
			LaunchID:   run.LaunchID,
			PlanHash:   run.PlanHash,
			ServerID:   serverID,
			FirewallID: firewallID,
		})
		if err != nil {
			return nil, nil, err
		}
		reconcile, err := provisioner.Reconcile(ctx, run.LaunchID)
		if err != nil {
			return nil, nil, err
		}
		return cloudDeleteArtifacts(run, provider, teardown, reconcile), []string{teardown.ReceiptID, "receipt:hetzner:" + run.LaunchID + ":post-delete-reconcile"}, nil
	default:
		return nil, nil, fmt.Errorf("unsupported cloud provider %q for launch %s", provider, run.LaunchID)
	}
}

func cloudDeleteArtifacts(run session.LaunchRun, provider string, teardown any, reconcile any) map[string][]byte {
	receipt := lpreceipts.NewReceipt("launchpad.cloud_teardown", run.LaunchID, "ALLOW", map[string]any{
		"provider":  provider,
		"teardown":  teardown,
		"reconcile": reconcile,
	})
	artifacts := map[string][]byte{}
	addJSON(artifacts, "cloud_teardown_result.json", map[string]any{
		"provider":  provider,
		"teardown":  teardown,
		"reconcile": reconcile,
	})
	addJSON(artifacts, "receipts/launchpad-cloud-teardown.json", receipt)
	return artifacts
}

func appendLaunchEvidencePack(store *session.Store, run *session.LaunchRun, artifacts map[string][]byte) ([]string, error) {
	packRef, err := lpreceipts.WriteEvidencePack(store.Root(), run.LaunchID, artifacts)
	if err != nil {
		return nil, err
	}
	run.EvidencePackRefs = appendUniqueLaunchString(run.EvidencePackRefs, packRef)
	run.EvidenceGraphRefs = appendUniqueLaunchString(run.EvidenceGraphRefs, packRef+"/04_EXPORTS/launchpad_evidence_graph.json")
	if archiveRef, err := lpreceipts.WriteEvidencePackArchive(packRef); err == nil {
		run.EvidencePackRefs = appendUniqueLaunchString(run.EvidencePackRefs, archiveRef)
		run.VerificationCommand = "helm-ai-kernel verify --bundle " + archiveRef
	} else if run.VerificationCommand == "" {
		run.VerificationCommand = "helm-ai-kernel verify --bundle " + packRef
	}
	return run.EvidencePackRefs, nil
}

func parseCloudInt64(value string) (int64, error) {
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid cloud resource id %q", value)
	}
	return parsed, nil
}

func appendUniqueLaunchString(values []string, next string) []string {
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

func addJSON(dst map[string][]byte, name string, value any) {
	data, _ := json.MarshalIndent(value, "", "  ")
	dst[name] = append(data, '\n')
}

func runLaunchSecrets(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel launch secrets <set|status> [args]")
		return 2
	}
	switch args[0] {
	case "set":
		fs := flag.NewFlagSet("launch secrets set", flag.ContinueOnError)
		fs.SetOutput(stderr)
		provider := fs.String("provider", "", "secret provider label")
		valueEnv := fs.String("value-env", "", "environment variable that holds the secret value")
		jsonOut := fs.Bool("json", false, "emit JSON")
		parseArgs := args[1:]
		positionalName := ""
		if len(parseArgs) > 0 && !strings.HasPrefix(parseArgs[0], "-") {
			positionalName = parseArgs[0]
			parseArgs = parseArgs[1:]
		}
		if err := fs.Parse(parseArgs); err != nil {
			return 2
		}
		rest := fs.Args()
		if positionalName != "" {
			rest = append([]string{positionalName}, rest...)
		}
		if len(rest) != 1 {
			fmt.Fprintln(stderr, "Usage: helm-ai-kernel launch secrets set <name> --provider <provider> --value-env <ENV> [--json]")
			return 2
		}
		binding, err := lpsecrets.NewStore("").Set(rest[0], *provider, *valueEnv)
		if err != nil {
			fmt.Fprintf(stderr, "launch secrets set error: %v\n", err)
			return 1
		}
		if *jsonOut {
			return writeLaunchJSON(stdout, binding)
		}
		fmt.Fprintf(stdout, "Launchpad secret %s is bound to %s via %s.\n", binding.Name, binding.Provider, binding.ValueEnv)
		return 0
	case "status":
		statuses, err := lpsecrets.NewStore("").Statuses()
		if err != nil {
			fmt.Fprintf(stderr, "launch secrets status error: %v\n", err)
			return 1
		}
		return writeLaunchJSON(stdout, map[string]any{"secrets": statuses})
	default:
		fmt.Fprintf(stderr, "unknown launch secrets command: %s\n", args[0])
		return 2
	}
}

func runLaunchPromote(args []string, catalog *lpregistry.Catalog, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("launch promote", flag.ContinueOnError)
	fs.SetOutput(stderr)
	manifestPath := fs.String("manifest", "", "Launchpad artifact manifest JSON from CI")
	appID := fs.String("app", "", "app id to promote")
	specPath := fs.String("spec", "", "app spec path to write when --write is set")
	artifactVerificationRef := fs.String("artifact-verification-ref", "", "artifact verification evidence ref")
	liveE2ERunID := fs.String("live-e2e-run-id", "", "live local-container e2e run id")
	evidencePackRef := fs.String("evidence-pack-ref", "", "offline-verifiable EvidencePack ref")
	teardownReceiptRef := fs.String("teardown-receipt-ref", "", "teardown receipt ref")
	writeSpec := fs.Bool("write", false, "write promoted app spec YAML")
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *manifestPath == "" || *appID == "" {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel launch promote --manifest <promotion-manifest.json> --app <app> [--artifact-verification-ref <ref> --live-e2e-run-id <id> --evidence-pack-ref <ref> --teardown-receipt-ref <ref>] [--write] [--json]")
		return 2
	}
	manifest, err := lppromotion.LoadManifest(*manifestPath)
	if err != nil {
		fmt.Fprintf(stderr, "launch promotion manifest error: %v\n", err)
		return 1
	}
	artifact, ok := manifest.Entry(*appID)
	if !ok {
		fmt.Fprintf(stderr, "launch promotion error: artifact for app %s not found\n", *appID)
		return 1
	}
	app, ok := catalog.App(*appID)
	if !ok {
		fmt.Fprintf(stderr, "launch promotion error: app %s not found in registry\n", *appID)
		return 1
	}
	refs, err := manifest.EvidenceRefsFor(artifact, lppromotion.EvidenceRefs{
		ArtifactVerificationRef: *artifactVerificationRef,
		LiveE2ERunID:            *liveE2ERunID,
		EvidencePackRef:         *evidencePackRef,
		TeardownReceiptRef:      *teardownReceiptRef,
	})
	if err != nil {
		fmt.Fprintf(stderr, "launch promotion denied: %v\n", err)
		return 1
	}
	promoted, err := lppromotion.Promote(app, artifact, refs)
	if err != nil {
		fmt.Fprintf(stderr, "launch promotion denied: %v\n", err)
		return 1
	}
	if *writeSpec {
		target := *specPath
		if target == "" {
			target = filepath.Join(catalog.Root, "registry", "launchpad", "apps", promoted.ID+".yaml")
		}
		if err := lppromotion.WriteAppSpec(target, promoted); err != nil {
			fmt.Fprintf(stderr, "launch promotion write error: %v\n", err)
			return 1
		}
	}
	if *jsonOut {
		return writeLaunchJSON(stdout, promoted)
	}
	if *writeSpec {
		fmt.Fprintf(stdout, "Promoted %s to oss_supported from signed artifact manifest.\n", promoted.ID)
	} else {
		fmt.Fprintf(stdout, "Promotion dry run for %s passed; use --write to update the app spec.\n", promoted.ID)
	}
	return 0
}

func redactLaunchLog(value string, secrets ...string) string {
	redacted := value
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		redacted = strings.ReplaceAll(redacted, secret, "[REDACTED]")
	}
	return redacted
}

func writeLaunchJSON(stdout io.Writer, v any) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return 1
	}
	return 0
}

func runLaunchImports(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel launchpad imports <list|preflight|promote|teardown> [args]")
		return 2
	}
	store := session.NewStore("")
	importStore := lpimporter.NewStore(store.Root())
	switch args[0] {
	case "list":
		records, err := importStore.List()
		if err != nil {
			fmt.Fprintf(stderr, "imports list error: %v\n", err)
			return 1
		}
		return writeLaunchJSON(stdout, map[string]any{"imports": records})
	case "preflight":
		if len(args) < 2 {
			fmt.Fprintln(stderr, "Usage: helm-ai-kernel launchpad imports preflight <import_id>")
			return 2
		}
		record, err := importStore.Get(args[1])
		if err != nil {
			fmt.Fprintf(stderr, "imports preflight error: %v\n", err)
			return 1
		}
		record = lpimporter.Preflight(record, time.Now().UTC())
		if err := importStore.Save(record); err != nil {
			fmt.Fprintf(stderr, "imports preflight save error: %v\n", err)
			return 1
		}
		return writeLaunchJSON(stdout, record)
	case "promote":
		if len(args) < 2 {
			fmt.Fprintln(stderr, "Usage: helm-ai-kernel launchpad imports promote <import_id>")
			return 2
		}
		record, err := importStore.Get(args[1])
		if err != nil {
			fmt.Fprintf(stderr, "imports promote error: %v\n", err)
			return 1
		}
		return writeLaunchJSON(stdout, map[string]any{
			"promotion_state":        record.LaunchRecipe.PromotionState,
			"generated_app_specs":    record.LaunchRecipe.GeneratedAppSpecs,
			"promotion_requirements": record.LaunchRecipe.PromotionRequirements,
		})
	case "teardown":
		if len(args) < 2 {
			fmt.Fprintln(stderr, "Usage: helm-ai-kernel launchpad imports teardown <import_id>")
			return 2
		}
		record, err := importStore.Get(args[1])
		if err != nil {
			fmt.Fprintf(stderr, "imports teardown error: %v\n", err)
			return 1
		}
		record.State = lpimporter.StateTornDown
		record.EvidenceLedger.Status = "teardown_recorded"
		if err := importStore.Save(record); err != nil {
			fmt.Fprintf(stderr, "imports teardown save error: %v\n", err)
			return 1
		}
		return writeLaunchJSON(stdout, record)
	default:
		fmt.Fprintf(stderr, "Unknown imports subcommand: %s\n", args[0])
		return 2
	}
}
