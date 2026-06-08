package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/readmodel"
	lpregistry "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	lpsecrets "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/secrets"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/session"
)

func init() {
	Register(Subcommand{Name: "app", Usage: "Run, preflight, and inspect Launchpad AppSpecs", RunFn: runAppCmd})
}

func runAppCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel app <run|preflight|inspect> <app> [--substrate local-container] [--json]")
		return 2
	}
	switch args[0] {
	case "run":
		return runAppRun(args[1:], stdout, stderr)
	case "preflight":
		return runAppPreflight(args[1:], stdout, stderr)
	case "inspect":
		return runAppInspect(args[1:], stdout, stderr)
	case "--help", "-h":
		fmt.Fprintln(stdout, "Usage: helm-ai-kernel app <run|preflight|inspect> <app> [--substrate local-container] [--json]")
		return 0
	default:
		fmt.Fprintf(stderr, "Unknown app subcommand: %s\n", args[0])
		return 2
	}
}

func runAppPreflight(args []string, stdout, stderr io.Writer) int {
	appID, substrateID, jsonOut, code := parseAppCommandArgs("app preflight", args, stderr)
	if code != 0 {
		return code
	}
	catalog, err := loadLaunchpadCatalog(stderr)
	if err != nil {
		return 1
	}
	compiled, _ := compileLaunchPlan(catalog, appID, substrateID, "local.operator", stderr)
	app, appOK := catalog.App(appID)
	substrate, substrateOK := catalog.Substrate(substrateID)
	if !appOK || !substrateOK {
		return writeLaunchJSON(stdout, compiled)
	}
	gates := readmodel.GatesFromPlan(app, substrate, compiled, nil)
	if jsonOut {
		return writeLaunchJSON(stdout, map[string]any{"plan": compiled, "gates": gates})
	}
	printGateSummary(stdout, "HELM PREFLIGHT", compiled.KernelVerdict, compiled.ReasonCode, gates)
	return exitForVerdict(compiled.KernelVerdict)
}

func runAppRun(args []string, stdout, stderr io.Writer) int {
	appID, substrateID, jsonOut, code := parseAppCommandArgs("app run", args, stderr)
	if code != 0 {
		return code
	}
	catalog, err := loadLaunchpadCatalog(stderr)
	if err != nil {
		return 1
	}
	compiled, _ := compileLaunchPlan(catalog, appID, substrateID, "local.operator", stderr)
	run, err := session.NewExecutor(session.NewStore("")).ExecuteLaunch(compiled, session.ExecuteOptions{Reason: "app run requested through CLI"})
	if err != nil {
		fmt.Fprintf(stderr, "app run error: %v\n", err)
		return 1
	}
	if jsonOut {
		return writeLaunchJSON(stdout, map[string]any{"run": run, "instance": readmodel.RuntimeFromRun(run), "events": readmodel.EventsFromRun(run)})
	}
	printRunSummary(stdout, run)
	return exitForVerdict(run.KernelVerdict)
}

func runAppInspect(args []string, stdout, stderr io.Writer) int {
	appID, substrateID, jsonOut, code := parseAppCommandArgs("app inspect", args, stderr)
	if code != 0 {
		return code
	}
	catalog, err := loadLaunchpadCatalog(stderr)
	if err != nil {
		return 1
	}
	statuses, _ := lpsecrets.NewStore("").Statuses()
	runs, _ := session.NewStore("").List()
	apps := readmodel.RegistryApps(catalog, statuses, runs)
	for _, app := range apps {
		if app.ID != appID {
			continue
		}
		if jsonOut {
			return writeLaunchJSON(stdout, app)
		}
		fmt.Fprintf(stdout, "%s\n", app.Name)
		fmt.Fprintf(stdout, "  AppSpec:   %s\n", app.AppID)
		fmt.Fprintf(stdout, "  Source:    %s@%s\n", app.OCIRef, app.ImmutableDigest)
		fmt.Fprintf(stdout, "  Status:    %s (%s)\n", app.Status.State, app.Status.Verdict)
		fmt.Fprintf(stdout, "  Policy:    %s\n", app.PolicyRef)
		fmt.Fprintf(stdout, "  CLI:       helm app run %s --substrate %s\n", app.AppID, substrateID)
		return 0
	}
	fmt.Fprintf(stderr, "unknown app: %s\n", appID)
	return 1
}

func parseAppCommandArgs(name string, args []string, stderr io.Writer) (string, string, bool, int) {
	substrate := "local-container"
	jsonOut := false
	apps := []string{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			jsonOut = true
		case "--substrate":
			if i+1 >= len(args) {
				fmt.Fprintf(stderr, "Usage: helm-ai-kernel %s <app> [--substrate local-container] [--json]\n", name)
				return "", "", false, 2
			}
			substrate = args[i+1]
			i++
		case "--resume":
			if i+1 >= len(args) {
				fmt.Fprintf(stderr, "Usage: helm-ai-kernel %s <app> [--substrate local-container] [--json]\n", name)
				return "", "", false, 2
			}
			i++
		default:
			if strings.HasPrefix(args[i], "-") {
				fmt.Fprintf(stderr, "unknown %s flag: %s\n", name, args[i])
				return "", "", false, 2
			}
			apps = append(apps, args[i])
		}
	}
	if len(apps) != 1 {
		fmt.Fprintf(stderr, "Usage: helm-ai-kernel %s <app> [--substrate local-container] [--json]\n", name)
		return "", "", false, 2
	}
	return apps[0], substrate, jsonOut, 0
}

func loadLaunchpadCatalog(stderr io.Writer) (*lpregistry.Catalog, error) {
	catalog, err := lpregistry.LoadCatalog("")
	if err != nil {
		fmt.Fprintf(stderr, "launchpad registry error: %v\n", err)
		return nil, err
	}
	if err := catalog.Validate(); err != nil {
		fmt.Fprintf(stderr, "launchpad validation error: %v\n", err)
		return nil, err
	}
	return catalog, nil
}

func printGateSummary(stdout io.Writer, title, verdict, reason string, gates []readmodel.GateResult) {
	fmt.Fprintf(stdout, "%s: %s\n", title, verdict)
	if reason != "" {
		fmt.Fprintf(stdout, "Reason: %s\n", reason)
	}
	for _, gate := range gates {
		marker := "[OK]"
		if gate.Verdict == "DENY" {
			marker = "[DENY]"
		}
		if gate.Verdict == "ESCALATE" {
			marker = "[ESC]"
		}
		fmt.Fprintf(stdout, "  %-6s %-24s %s\n", marker, gate.Label, gate.Summary)
	}
}

func printRunSummary(stdout io.Writer, run session.LaunchRun) {
	fmt.Fprintf(stdout, "HELM %s: %s\n", run.KernelVerdict, firstNonEmpty(run.ReasonCode, string(run.State)))
	if run.KernelVerdict != "ALLOW" {
		fmt.Fprintln(stdout, "No container was started.")
		fmt.Fprintln(stdout, "Side effects: none")
	} else {
		fmt.Fprintf(stdout, "Container: %s\n", firstNonEmpty(run.RuntimeHandles.ContainerID, "unproven"))
		fmt.Fprintln(stdout, "Side effects: policy-authorized")
	}
	if len(run.LaunchReceiptRefs) > 0 {
		fmt.Fprintf(stdout, "Launch receipt: %s\n", run.LaunchReceiptRefs[0])
	}
	if len(run.EvidencePackRefs) > 0 {
		fmt.Fprintf(stdout, "EvidencePack: %s\n", run.EvidencePackRefs[len(run.EvidencePackRefs)-1])
	}
	if run.VerificationCommand != "" {
		fmt.Fprintf(stdout, "Verify: %s\n", run.VerificationCommand)
	}
	if run.ReasonCode == "ERR_LAUNCHPAD_REQUIRED_SECRET_MISSING" {
		fmt.Fprintln(stdout, "Fix:")
		fmt.Fprintln(stdout, "  helm secret set <logical_name> --provider env --value-env <ENV>")
		fmt.Fprintf(stdout, "  helm app run %s --resume %s\n", run.AppID, run.LaunchID)
	}
	fmt.Fprintf(stdout, "Inspect: helm run open %s\n", run.LaunchID)
	fmt.Fprintf(stdout, "Console: %s/runs/%s\n", strings.TrimRight(firstNonEmpty(os.Getenv("HELM_CONSOLE_URL"), "http://127.0.0.1:7714"), "/"), run.LaunchID)
}

func exitForVerdict(verdict string) int {
	if verdict == "ALLOW" {
		return 0
	}
	return 1
}
