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
	helmcrypto "github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/effectgraph"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/intentcompiler"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/prg"
	"gopkg.in/yaml.v3"
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
//	evaluate — Evaluate a PlanSpec DAG against policy
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
// Reads a PlanSpec JSON and evaluates it through Guardian-backed policy.
func runPlanEvaluate(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("plan evaluate", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		planFile   string
		policyFile string
		outputFile string
		actor      string
		dryRun     bool
	)

	cmd.StringVar(&planFile, "plan", "", "PlanSpec JSON file (REQUIRED)")
	cmd.StringVar(&policyFile, "policy", "", "Policy file for Guardian evaluation (REQUIRED unless --dry-run)")
	cmd.StringVar(&outputFile, "output", "", "Output file (default: stdout)")
	cmd.StringVar(&actor, "actor", "operator", "Principal ID")
	cmd.BoolVar(&dryRun, "dry-run", false, "Use explicit allow-all dry-run evaluator")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	if planFile == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --plan is required")
		return 2
	}
	if !dryRun && policyFile == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --policy is required unless --dry-run is set")
		return 2
	}
	if dryRun && policyFile != "" {
		_, _ = fmt.Fprintln(stderr, "Error: --policy and --dry-run are mutually exclusive")
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

	var policy effectgraph.PolicyEvaluator
	if dryRun {
		policy = &allowAllPolicy{}
	} else {
		rules, loadErr := loadPlanPolicy(policyFile, &plan)
		if loadErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error loading policy: %v\n", loadErr)
			return 2
		}
		signer, signerErr := helmcrypto.NewEd25519Signer("plan-evaluate")
		if signerErr != nil {
			_, _ = fmt.Fprintf(stderr, "Error creating Guardian signer: %v\n", signerErr)
			return 1
		}
		guard := guardian.NewGuardian(signer, rules, nil)
		policy = effectgraph.NewGuardianAdapter(guard)
	}

	evaluator := effectgraph.NewGraphEvaluator(policy)
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

type planPolicyFile struct {
	Rules      map[string]prg.RequirementSet `json:"rules" yaml:"rules"`
	Default    *prg.RequirementSet           `json:"default" yaml:"default"`
	Expression string                        `json:"expression" yaml:"expression"`
}

func loadPlanPolicy(path string, plan *contracts.PlanSpec) (*prg.Graph, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	graph := prg.NewGraph()
	var pf planPolicyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		if looksStructuredPlanPolicy(strings.TrimSpace(string(data))) {
			return nil, fmt.Errorf("parse policy: %w", err)
		}
		pf.Expression = strings.TrimSpace(string(data))
	}

	for action, rule := range pf.Rules {
		addNormalizedRule(graph, action, rule)
	}

	if pf.Default != nil {
		for _, effectType := range planEffectTypes(plan) {
			if _, exists := graph.Rules[effectType]; !exists {
				addNormalizedRule(graph, effectType, *pf.Default)
			}
		}
	}

	expression := strings.TrimSpace(pf.Expression)
	if len(graph.Rules) == 0 && expression == "" {
		expression = strings.TrimSpace(string(data))
	}
	if expression != "" {
		for _, effectType := range planEffectTypes(plan) {
			if _, exists := graph.Rules[effectType]; !exists {
				addNormalizedRule(graph, effectType, prg.RequirementSet{
					ID:    "plan-policy-" + effectType,
					Logic: prg.AND,
					Requirements: []prg.Requirement{{
						ID:          "expression",
						Description: "plan evaluation policy expression",
						Expression:  expression,
					}},
				})
			}
		}
	}

	if len(graph.Rules) == 0 {
		return nil, fmt.Errorf("policy file must define rules, default, or expression")
	}

	return graph, nil
}

func looksStructuredPlanPolicy(raw string) bool {
	return strings.HasPrefix(raw, "{") ||
		strings.HasPrefix(raw, "[") ||
		strings.HasPrefix(raw, "rules:") ||
		strings.HasPrefix(raw, "default:") ||
		strings.HasPrefix(raw, "expression:")
}

func addNormalizedRule(graph *prg.Graph, action string, rule prg.RequirementSet) {
	if rule.ID == "" {
		rule.ID = "plan-policy-" + action
	}
	if rule.Logic == "" {
		rule.Logic = prg.AND
	}
	_ = graph.AddRule(action, rule)
}

func planEffectTypes(plan *contracts.PlanSpec) []string {
	seen := map[string]bool{}
	var out []string
	if plan == nil || plan.DAG == nil {
		return out
	}
	for _, step := range plan.DAG.Nodes {
		if step.EffectType == "" || seen[step.EffectType] {
			continue
		}
		seen[step.EffectType] = true
		out = append(out, step.EffectType)
	}
	return out
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
