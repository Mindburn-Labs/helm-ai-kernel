package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	cliui "github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	helmcrypto "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effectgraph"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/guardian"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/intentcompiler"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/prg"
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

// runPlanCmd dispatches `helm-ai-kernel plan <subcommand>`.
//
// Subcommands:
//
//	compile      — Compile task descriptions into a PlanSpec DAG
//	evaluate     — Evaluate a PlanSpec DAG against policy
//	transactions — Inspect local PlanTransaction evidence
func runPlanCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "Usage: helm-ai-kernel plan <compile|evaluate|transactions> [options]")
		return 2
	}

	switch args[0] {
	case "compile":
		return runPlanCompile(args[1:], stdout, stderr)
	case "evaluate":
		return runPlanEvaluate(args[1:], stdout, stderr)
	case "transactions":
		return runPlanTransactions(args[1:], stdout, stderr)
	default:
		_ = cliui.WriteError(stderr, cliui.UsageErrorf("plan", "unknown subcommand: %s", args[0]))
		_, _ = fmt.Fprintln(stderr, "Usage: helm-ai-kernel plan <compile|evaluate|transactions> [options]")
		return 2
	}
}

// runPlanCompile implements `helm-ai-kernel plan compile`.
//
// Accepts either:
//   - --steps "step1" "step2" ... (inline task descriptions)
//   - --input <file> (JSON file with {"steps": ["..."]})
//
// Outputs a PlanSpec JSON to stdout or --output file.
func runPlanCompile(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("plan compile", flag.ContinueOnError)

	var (
		inputFile  string
		outputFile string
		planName   string
		jsonOutput bool
	)

	cmd.StringVar(&inputFile, "input", "", "JSON input file with steps")
	cmd.StringVar(&outputFile, "output", "", "Output file (default: stdout)")
	cmd.StringVar(&planName, "name", "", "Plan name")
	cmd.BoolVar(&jsonOutput, "json", true, "Output as JSON (alias for --format=json)")
	formatFlag := cliui.RegisterFormat(cmd, cliui.FormatText)

	if code, ok := cliui.ParseFlags(cmd, args, stderr, "plan compile", cliui.FormatJSON); !ok {
		return code
	}
	// plan compile renders PlanSpec JSON only (there is no text renderer; the
	// historical --json default is true for the same reason), so --format=json
	// is accepted as the unified alias and --format=text is a no-op, matching
	// the pre-existing --json=false behavior.
	jsonOutput = jsonOutput || formatFlag.IsJSON()
	// plan compile emits PlanSpec JSON on every success path (the --json
	// default is true and there is no text renderer), so its errors are
	// ALWAYS the JSON envelope to keep stderr parseable as one document.
	errFormat := cliui.FormatText
	if jsonOutput {
		errFormat = cliui.FormatJSON
	}

	var steps []string

	if inputFile != "" {
		// Read from file.
		data, err := os.ReadFile(inputFile)
		if err != nil {
			return cliui.WriteErrorFormat(stderr, cliui.Wrapf(err, cliui.ExitUsage, "plan compile", "reading input file"), errFormat)
		}
		var input struct {
			Steps []string `json:"steps"`
		}
		if err := json.Unmarshal(data, &input); err != nil {
			return cliui.WriteErrorFormat(stderr, cliui.Wrapf(err, cliui.ExitUsage, "plan compile", "parsing input JSON"), errFormat)
		}
		steps = input.Steps
	} else if cmd.NArg() > 0 {
		// Inline steps from remaining args.
		steps = cmd.Args()
	} else {
		_ = cliui.WriteErrorFormat(stderr, cliui.UsageErrorf("plan compile", "provide --input <file> or inline step descriptions"), errFormat)
		if errFormat != cliui.FormatJSON {
			_, _ = fmt.Fprintln(stderr, "Usage: helm-ai-kernel plan compile [--input file.json | step1 step2 ...]")
		}
		return 2
	}

	compiler := intentcompiler.NewCompiler()
	result, err := compiler.Compile(&intentcompiler.CompileRequest{
		RawSteps: steps,
		PlanName: planName,
	})
	if err != nil {
		return cliui.WriteErrorFormat(stderr, cliui.Wrapf(err, cliui.ExitFailure, "plan compile", "compilation failed"), errFormat)
	}

	// Print warnings.
	for _, w := range result.Warnings {
		_, _ = fmt.Fprintf(stderr, "WARNING: %s\n", w)
	}

	// Output plan.
	data, err := json.MarshalIndent(result.Plan, "", "  ")
	if err != nil {
		return cliui.WriteErrorFormat(stderr, cliui.Wrapf(err, cliui.ExitFailure, "plan compile", "marshaling plan"), errFormat)
	}

	if outputFile != "" {
		if err := os.WriteFile(outputFile, data, 0644); err != nil {
			return cliui.WriteErrorFormat(stderr, cliui.Wrapf(err, cliui.ExitFailure, "plan compile", "writing output"), errFormat)
		}
		_, _ = fmt.Fprintf(stderr, "Plan written to %s (%d steps, %d edges)\n",
			outputFile, len(result.Plan.DAG.Nodes), len(result.Plan.DAG.Edges))
	} else {
		_, _ = fmt.Fprintln(stdout, string(data))
	}

	return 0
}

// runPlanEvaluate implements `helm-ai-kernel plan evaluate`.
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
		return cliui.WriteError(stderr, cliui.UsageErrorf("plan evaluate", "--plan is required"))
	}
	if !dryRun && policyFile == "" {
		return cliui.WriteError(stderr, cliui.UsageErrorf("plan evaluate", "--policy is required unless --dry-run is set"))
	}
	if dryRun && policyFile != "" {
		return cliui.WriteError(stderr, cliui.UsageErrorf("plan evaluate", "--policy and --dry-run are mutually exclusive"))
	}

	// Read plan.
	data, err := os.ReadFile(planFile)
	if err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitUsage, "plan evaluate", "reading plan file"))
	}

	var plan contracts.PlanSpec
	if err := json.Unmarshal(data, &plan); err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitUsage, "plan evaluate", "parsing plan JSON"))
	}

	var policy effectgraph.PolicyEvaluator
	if dryRun {
		policy = &allowAllPolicy{}
	} else {
		rules, loadErr := loadPlanPolicy(policyFile, &plan)
		if loadErr != nil {
			return cliui.WriteError(stderr, cliui.Wrapf(loadErr, cliui.ExitUsage, "plan evaluate", "loading policy"))
		}
		signer, signerErr := helmcrypto.NewEd25519Signer("plan-evaluate")
		if signerErr != nil {
			return cliui.WriteError(stderr, cliui.Wrapf(signerErr, cliui.ExitFailure, "plan evaluate", "creating Guardian signer"))
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
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitFailure, "plan evaluate", "evaluation failed"))
	}

	// Summary to stderr.
	_, _ = fmt.Fprintf(stderr, "Evaluation: %d allowed, %d denied, %d escalated, %d blocked\n",
		len(result.AllowedSteps), len(result.DeniedSteps),
		len(result.EscalateSteps), len(result.BlockedSteps))
	_, _ = fmt.Fprintf(stderr, "Graph hash: %s\n", result.GraphHash)

	// Full result to stdout/file.
	outData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitFailure, "plan evaluate", "marshaling result"))
	}

	if outputFile != "" {
		if err := os.WriteFile(outputFile, outData, 0644); err != nil {
			return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitFailure, "plan evaluate", "writing output"))
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
