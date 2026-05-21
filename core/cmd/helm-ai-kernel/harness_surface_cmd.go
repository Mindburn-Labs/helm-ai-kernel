package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func runEvidenceScopes(args []string, stdout, stderr io.Writer) int {
	registry := newLocalSurfaceRegistry()
	return runHarnessObjectCommand(args, stdout, stderr, "evidence scopes", func(action string, id string, input string) (any, int, error) {
		switch action {
		case "list":
			return registry.ListVerificationScopes(), 0, nil
		case "get":
			scope, ok := registry.GetVerificationScope(id)
			if !ok {
				return nil, 1, fmt.Errorf("verification scope %q not found", id)
			}
			return scope, 0, nil
		case "verify":
			return registry.VerifyVerificationScope(id), 0, nil
		case "put", "create":
			var scope contracts.VerificationScope
			if err := readHarnessInput(input, &scope); err != nil {
				return nil, 2, err
			}
			sealed, err := registry.PutVerificationScope(scope)
			return sealed, 0, err
		default:
			return nil, 2, fmt.Errorf("unknown evidence scopes subcommand %q", action)
		}
	})
}

func runPlanTransactions(args []string, stdout, stderr io.Writer) int {
	registry := newLocalSurfaceRegistry()
	return runHarnessObjectCommand(args, stdout, stderr, "plan transactions", func(action string, id string, input string) (any, int, error) {
		switch action {
		case "list":
			return registry.ListPlanTransactions(), 0, nil
		case "get":
			tx, ok := registry.GetPlanTransaction(id)
			if !ok {
				return nil, 1, fmt.Errorf("plan transaction %q not found", id)
			}
			return tx, 0, nil
		case "verify":
			return registry.VerifyPlanTransaction(id), 0, nil
		case "put", "create":
			var tx contracts.PlanTransaction
			if err := readHarnessInput(input, &tx); err != nil {
				return nil, 2, err
			}
			sealed, err := registry.PutPlanTransaction(tx)
			return sealed, 0, err
		default:
			return nil, 2, fmt.Errorf("unknown plan transactions subcommand %q", action)
		}
	})
}

func runTracesCmd(args []string, stdout, stderr io.Writer) int {
	registry := newLocalSurfaceRegistry()
	return runHarnessObjectCommand(args, stdout, stderr, "traces", func(action string, id string, input string) (any, int, error) {
		switch action {
		case "list":
			return registry.ListHarnessTraces(), 0, nil
		case "get":
			trace, ok := registry.GetHarnessTrace(id)
			if !ok {
				return nil, 1, fmt.Errorf("harness trace %q not found", id)
			}
			return trace, 0, nil
		case "verify":
			return registry.VerifyHarnessTrace(id), 0, nil
		case "put", "create":
			var trace contracts.HarnessTrace
			if err := readHarnessInput(input, &trace); err != nil {
				return nil, 2, err
			}
			sealed, err := registry.PutHarnessTrace(trace)
			return sealed, 0, err
		default:
			return nil, 2, fmt.Errorf("unknown traces subcommand %q", action)
		}
	})
}

func runHarnessCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "changes" {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel harness changes <list|get|put|verify|approve> [flags]")
		return 2
	}
	registry := newLocalSurfaceRegistry()
	return runHarnessObjectCommand(args[1:], stdout, stderr, "harness changes", func(action string, id string, input string) (any, int, error) {
		switch action {
		case "list":
			return registry.ListHarnessChanges(), 0, nil
		case "get":
			contract, ok := registry.GetHarnessChange(id)
			if !ok {
				return nil, 1, fmt.Errorf("harness change contract %q not found", id)
			}
			return contract, 0, nil
		case "verify":
			return registry.VerifyHarnessChange(id), 0, nil
		case "approve":
			contract, err := registry.ApproveHarnessChange(id, input)
			return contract, 0, err
		case "put", "create":
			var contract contracts.HarnessChangeContract
			if err := readHarnessInput(input, &contract); err != nil {
				return nil, 2, err
			}
			sealed, err := registry.PutHarnessChange(contract)
			return sealed, 0, err
		default:
			return nil, 2, fmt.Errorf("unknown harness changes subcommand %q", action)
		}
	})
}

func runGUICmd(args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 || args[0] != "receipts" || args[1] != "verify" {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel gui receipts verify --input receipt.json")
		return 2
	}
	fs := flag.NewFlagSet("gui receipts verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	input := fs.String("input", "", "GUI action receipt JSON file")
	if err := fs.Parse(args[2:]); err != nil {
		return 2
	}
	var receipt contracts.GUIActionReceipt
	if err := readHarnessInput(*input, &receipt); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	sealed, err := receipt.Seal()
	if err != nil {
		_ = writeSurfaceJSON(stdout, map[string]any{"verified": false, "verdict": "FAIL", "errors": []string{err.Error()}})
		return 1
	}
	return writeSurfaceJSON(stdout, map[string]any{"verified": true, "verdict": "PASS", "receipt": sealed})
}

type harnessObjectRunner func(action string, id string, input string) (any, int, error)

func runHarnessObjectCommand(args []string, stdout, stderr io.Writer, usage string, run harnessObjectRunner) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, "Usage: helm-ai-kernel %s <list|get|put|verify> [flags]\n", usage)
		return 2
	}
	action := args[0]
	fs := flag.NewFlagSet(usage+" "+action, flag.ContinueOnError)
	fs.SetOutput(stderr)
	id := fs.String("id", "", "Object id")
	input := fs.String("input", "", "Input JSON file; for approve, receipt ref")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *id == "" && fs.NArg() > 0 {
		*id = fs.Arg(0)
	}
	if needsHarnessID(action) && *id == "" {
		fmt.Fprintln(stderr, "Error: --id is required")
		return 2
	}
	value, code, err := run(action, *id, *input)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		if code != 0 {
			return code
		}
		return 1
	}
	return writeSurfaceJSON(stdout, value)
}

func needsHarnessID(action string) bool {
	switch action {
	case "get", "verify", "approve":
		return true
	default:
		return false
	}
}

func readHarnessInput(path string, target any) error {
	if path == "" {
		return fmt.Errorf("--input is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

func init() {
	Register(Subcommand{Name: "traces", Usage: "Inspect hash-linked harness traces", RunFn: runTracesCmd})
	Register(Subcommand{Name: "harness", Usage: "Inspect harness mutation contracts", RunFn: runHarnessCmd})
	Register(Subcommand{Name: "gui", Usage: "Verify grounded GUI action receipts", RunFn: runGUICmd})
}
