package formal

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestTranslate(t *testing.T) {
	translator := NewSMTTranslator()
	out, err := translator.Translate(context.Background(), []byte("policy"), []byte("intent"))
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if !strings.Contains(out, "(check-sat)") {
		t.Fatalf("unexpected SMT output %q", out)
	}
}

func TestEvaluate(t *testing.T) {
	tests := []struct {
		name       string
		scenario   string
		want       bool
		wantErr    string
		wantStdin  string
		nonZeroOut bool
	}{
		{name: "sat", scenario: "sat", want: true, wantStdin: "proof"},
		{name: "unsat", scenario: "unsat", want: false},
		{name: "unexpected", scenario: "unknown", wantErr: "unexpected z3 output: unknown"},
		{name: "error no stdout", scenario: "error-empty", wantErr: "z3 evaluation failed"},
		{name: "error with stdout", scenario: "error-with-sat", want: true, nonZeroOut: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restore := replaceCommandContext(tt.scenario)
			defer restore()

			got, err := NewSMTTranslator().Evaluate(context.Background(), "proof")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if got != tt.want {
				t.Fatalf("Evaluate = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluateCommandStartError(t *testing.T) {
	restore := replaceCommandContext("missing-command")
	defer restore()

	_, err := NewSMTTranslator().Evaluate(context.Background(), "proof")
	if err == nil || !strings.Contains(err.Error(), "z3 evaluation failed") {
		t.Fatalf("expected command start error, got %v", err)
	}
}

func replaceCommandContext(scenario string) func() {
	original := smtCommandContext
	smtCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if scenario == "missing-command" {
			return exec.CommandContext(ctx, "definitely-not-a-real-z3-binary")
		}
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestSMTHelperProcess", "--", scenario)
		cmd.Env = append(os.Environ(), "GO_WANT_SMT_HELPER=1")
		return cmd
	}
	return func() { smtCommandContext = original }
}

func TestSMTHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_SMT_HELPER") != "1" {
		return
	}
	scenario := os.Args[len(os.Args)-1]
	_, _ = io.ReadAll(os.Stdin)
	switch scenario {
	case "sat":
		_, _ = os.Stdout.WriteString("sat\n")
	case "unsat":
		_, _ = os.Stdout.WriteString("unsat\n")
	case "unknown":
		_, _ = os.Stdout.WriteString("unknown\n")
	case "error-empty":
		_, _ = os.Stderr.WriteString("solver crashed\n")
		os.Exit(2)
	case "error-with-sat":
		_, _ = os.Stdout.WriteString("sat\n")
		os.Exit(2)
	default:
		_, _ = os.Stderr.WriteString(errors.New("unexpected helper scenario").Error())
		os.Exit(3)
	}
	os.Exit(0)
}
