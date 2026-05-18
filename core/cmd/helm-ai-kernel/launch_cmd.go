package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	lppromotion "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/promotion"
	lpregistry "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	lprepair "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/repair"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/session"
)

func init() {
	Register(Subcommand{Name: "launch", Usage: "Launch verified AI apps through HELM Launchpad", RunFn: runLaunchCmd})
}

func runLaunchCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel launch <matrix|apps|substrates|plan|status|logs|repair|delete|app> [args]")
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
	case "promote":
		return runLaunchPromote(args[1:], catalog, stdout, stderr)
	default:
		return runLaunchStart(args, catalog, stdout, stderr)
	}
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
	_ = run
	deleted, err := session.NewExecutor(store).DeleteLaunch(rest[0], cascade)
	if err != nil {
		fmt.Fprintf(stderr, "launch delete error: %v\n", err)
		return 1
	}
	return writeLaunchJSON(stdout, deleted)
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
