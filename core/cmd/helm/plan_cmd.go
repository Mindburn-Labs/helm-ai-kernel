package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/effectgraph"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/intentcompiler"
)

func init() {
	Register(Subcommand{
		Name:    "plan",
		Aliases: []string{},
		Usage:   "Compile or evaluate execution plans",
		RunFn:   runPlanCmd,
	})
}

// runPlanCmd dispatches `helm plan <subcommand>`.
//
// Subcommands:
//
//	compile  — Compile task descriptions into a PlanSpec DAG
//	evaluate — Evaluate a PlanSpec DAG against policy (mock evaluator)
func runPlanCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "Usage: helm plan <compile|evaluate> [options]")
		return 2
	}

	switch args[0] {
	case "compile":
		return runPlanCompile(args[1:], stdout, stderr)
	case "evaluate":
		return runPlanEvaluate(args[1:], stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "Unknown plan subcommand: %s\n", args[0])
		_, _ = fmt.Fprintln(stderr, "Usage: helm plan <compile|evaluate> [options]")
		return 2
	}
}

// runPlanCompile implements `helm plan compile`.
//
// Accepts either:
//   - --steps "step1" "step2" ... (inline task descriptions)
//   - --input <file> (JSON file with {"steps": ["..."]})
//
// Outputs a PlanSpec JSON to stdout or --output file.
func runPlanCompile(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("plan compile", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		inputFile  string
		outputFile string
		planName   string
		jsonOutput bool
	)

	cmd.StringVar(&inputFile, "input", "", "JSON input file with steps")
	cmd.StringVar(&outputFile, "output", "", "Output file (default: stdout)")
	cmd.StringVar(&planName, "name", "", "Plan name")
	cmd.BoolVar(&jsonOutput, "json", true, "Output as JSON")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	var steps []string

	if inputFile != "" {
		// Read from file.
		data, err := os.ReadFile(inputFile)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error reading input file: %v\n", err)
			return 2
		}
		var input struct {
			Steps []string `json:"steps"`
		}
		if err := json.Unmarshal(data, &input); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error parsing input JSON: %v\n", err)
			return 2
		}
		steps = input.Steps
	} else if cmd.NArg() > 0 {
		// Inline steps from remaining args.
		steps = cmd.Args()
	} else {
		_, _ = fmt.Fprintln(stderr, "Error: provide --input <file> or inline step descriptions")
		_, _ = fmt.Fprintln(stderr, "Usage: helm plan compile [--input file.json | step1 step2 ...]")
		return 2
	}

	compiler := intentcompiler.NewCompiler()
	result, err := compiler.Compile(&intentcompiler.CompileRequest{
		RawSteps: steps,
		PlanName: planName,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Compilation failed: %v\n", err)
		return 1
	}

	// Print warnings.
	for _, w := range result.Warnings {
		_, _ = fmt.Fprintf(stderr, "WARNING: %s\n", w)
	}

	// Output plan.
	data, err := json.MarshalIndent(result.Plan, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error marshaling plan: %v\n", err)
		return 1
	}

	if outputFile != "" {
		if err := os.WriteFile(outputFile, data, 0644); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error writing output: %v\n", err)
			return 1
		}
		_, _ = fmt.Fprintf(stderr, "Plan written to %s (%d steps, %d edges)\n",
			outputFile, len(result.Plan.DAG.Nodes), len(result.Plan.DAG.Edges))
	} else {
		_, _ = fmt.Fprintln(stdout, string(data))
	}

	return 0
}

// runPlanEvaluate implements `helm plan evaluate`.
//
// Reads a PlanSpec JSON and evaluates it through a mock policy evaluator.
// In production, this would use the real Guardian via GuardianAdapter.
func runPlanEvaluate(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("plan evaluate", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		planFile   string
		outputFile string
		actor      string
	)

	cmd.StringVar(&planFile, "plan", "", "PlanSpec JSON file (REQUIRED)")
	cmd.StringVar(&outputFile, "output", "", "Output file (default: stdout)")
	cmd.StringVar(&actor, "actor", "operator", "Principal ID")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if planFile == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --plan is required")
		return 2
	}

	// Read plan.
	data, err := os.ReadFile(planFile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error reading plan file: %v\n", err)
		return 2
	}

	var plan contracts.PlanSpec
	if err := json.Unmarshal(data, &plan); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error parsing plan JSON: %v\n", err)
		return 2
	}

	// Evaluate using allow-all policy (real Guardian wiring requires server context).
	evaluator := effectgraph.NewGraphEvaluator(&allowAllPolicy{})
	result, err := evaluator.Evaluate(context.Background(), &effectgraph.EvaluationRequest{
		Plan:  &plan,
		Actor: actor,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Evaluation failed: %v\n", err)
		return 1
	}

	// Summary to stderr.
	_, _ = fmt.Fprintf(stderr, "Evaluation: %d allowed, %d denied, %d escalated, %d blocked\n",
		len(result.AllowedSteps), len(result.DeniedSteps),
		len(result.EscalateSteps), len(result.BlockedSteps))
	_, _ = fmt.Fprintf(stderr, "Graph hash: %s\n", result.GraphHash)

	// Full result to stdout/file.
	outData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error marshaling result: %v\n", err)
		return 1
	}

	if outputFile != "" {
		if err := os.WriteFile(outputFile, outData, 0644); err != nil {
			_, _ = fmt.Fprintf(stderr, "Error writing output: %v\n", err)
			return 1
		}
	} else {
		_, _ = fmt.Fprintln(stdout, string(outData))
	}

	if len(result.DeniedSteps) > 0 {
		_, _ = fmt.Fprintf(stderr, "Denied steps: %s\n", strings.Join(result.DeniedSteps, ", "))
		return 1
	}

	return 0
}

// allowAllPolicy is a simple policy evaluator that allows everything.
// Used for CLI dry-run evaluation when no Guardian is available.
type allowAllPolicy struct{}

func (p *allowAllPolicy) EvaluateStep(_ context.Context, step *contracts.PlanStep, _ string) (*contracts.DecisionRecord, error) {
	return &contracts.DecisionRecord{
		ID:         "dec-" + step.ID,
		Verdict:    string(contracts.VerdictAllow),
		ReasonCode: "CLI_DRY_RUN",
		Reason:     "Allowed by CLI dry-run evaluator (no Guardian connected)",
	}, nil
}

func (p *allowAllPolicy) IssueIntent(_ context.Context, decision *contracts.DecisionRecord, step *contracts.PlanStep) (*contracts.AuthorizedExecutionIntent, error) {
	return &contracts.AuthorizedExecutionIntent{
		ID:         "intent-" + step.ID,
		DecisionID: decision.ID,
	}, nil
}
