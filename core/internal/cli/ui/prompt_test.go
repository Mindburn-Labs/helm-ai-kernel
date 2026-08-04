package ui

import (
	"errors"
	"strings"
	"testing"
)

func TestConfirmDecisionShowsFullContextAndRejectsNonmatchingInput(t *testing.T) {
	var output strings.Builder
	called := false
	err := NewRenderer(&output, Capabilities{Interactive: true, Width: 80}).ConfirmDecision(
		strings.NewReader("yes\n"),
		DecisionContext{
			Action:  DecisionApprove,
			Subject: "approval-42",
			Summary: "Allow the command once.",
			Details: []KeyValue{
				{Key: "Reason", Value: "Policy escalation"},
				{Key: "Evidence", Value: "receipt://r-42"},
			},
		},
		func() error {
			called = true
			return nil
		},
	)
	if !errors.Is(err, ErrConfirmationRequired) {
		t.Fatalf("ConfirmDecision error = %v, want ErrConfirmationRequired", err)
	}
	if called {
		t.Fatal("callback ran without the exact approval word")
	}
	for _, want := range []string{"Action: APPROVE", "Subject: approval-42", "Summary: Allow the command once.", "Reason: Policy escalation", "Evidence: receipt://r-42", "Type APPROVE"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("review output missing %q:\n%s", want, output.String())
		}
	}
}

func TestConfirmDecisionRunsCallbackOnlyAfterMatchingAction(t *testing.T) {
	for _, decision := range []DecisionAction{DecisionApprove, DecisionDeny} {
		t.Run(string(decision), func(t *testing.T) {
			called := false
			err := NewRenderer(&strings.Builder{}, Capabilities{Interactive: true, Width: 80}).ConfirmDecision(
				strings.NewReader(string(decision)+"\n"),
				DecisionContext{Action: decision, Subject: "approval-42"},
				func() error {
					called = true
					return nil
				},
			)
			if err != nil {
				t.Fatalf("ConfirmDecision error = %v", err)
			}
			if !called {
				t.Fatal("callback did not run after explicit confirmation")
			}
		})
	}
}

func TestConfirmDecisionFailsClosedWhenNonInteractive(t *testing.T) {
	called := false
	err := NewRenderer(&strings.Builder{}, Capabilities{Width: 80}).ConfirmDecision(
		strings.NewReader("APPROVE\n"),
		DecisionContext{Action: DecisionApprove, Subject: "approval-42"},
		func() error {
			called = true
			return nil
		},
	)
	if !errors.Is(err, ErrNonInteractive) {
		t.Fatalf("ConfirmDecision error = %v, want ErrNonInteractive", err)
	}
	if called {
		t.Fatal("callback ran in a non-interactive context")
	}
}
