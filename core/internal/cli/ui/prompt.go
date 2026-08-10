package ui

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	// ErrNonInteractive prevents approval and denial actions in pipes, JSON,
	// and other contexts where a human cannot review the decision.
	ErrNonInteractive = errors.New("interactive confirmation required")
	// ErrConfirmationRequired means the action callback was not invoked.
	ErrConfirmationRequired = errors.New("explicit confirmation required")
)

// DecisionAction is the terminal action that requires an explicit matching
// confirmation word.
type DecisionAction string

const (
	DecisionApprove DecisionAction = "APPROVE"
	DecisionDeny    DecisionAction = "DENY"
)

// DecisionContext is the complete human review payload shown before a state
// change. Details are preserved in order so a TUI cannot reduce an approval to
// an opaque hotkey.
type DecisionContext struct {
	Action  DecisionAction
	Subject string
	Summary string
	Details []KeyValue
}

// DecisionReview renders every supplied decision field before the prompt.
func (r Renderer) DecisionReview(decision DecisionContext) string {
	fields := []KeyValue{
		{Key: "Action", Value: string(decision.Action)},
		{Key: "Subject", Value: decision.Subject},
		{Key: "Summary", Value: decision.Summary},
	}
	fields = append(fields, decision.Details...)
	return r.Completion(CompletionCard{Title: "Review required", Fields: fields})
}

// ConfirmDecision renders the full context, requires the exact action word,
// and only then invokes apply. A command must keep its approval or denial
// state transition inside apply to preserve this guard.
func (r Renderer) ConfirmDecision(input io.Reader, decision DecisionContext, apply func() error) error {
	if !r.caps.Interactive || input == nil || r.chrome == nil {
		return ErrNonInteractive
	}
	if err := validateDecision(decision); err != nil {
		return err
	}
	_, _ = io.WriteString(r.chrome, r.DecisionReview(decision))
	_, _ = fmt.Fprintf(r.chrome, "Type %s to confirm; any other input cancels: ", decision.Action)

	line, err := bufio.NewReader(input).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read confirmation: %w", err)
	}
	// Echo the resolved answer on its own line. Without it, the prompt and the
	// caller's next output collided on a single line (a piped session showed
	// "…to confirm: setup: no changes made"), and the transcript was not a
	// record of what was decided.
	answer := strings.TrimSpace(line)
	if !strings.EqualFold(answer, string(decision.Action)) {
		_, _ = fmt.Fprintf(r.chrome, "→ cancelled\n")
		return ErrConfirmationRequired
	}
	_, _ = fmt.Fprintf(r.chrome, "→ %s\n", decision.Action)
	if apply == nil {
		return nil
	}
	return apply()
}

func validateDecision(decision DecisionContext) error {
	if decision.Action != DecisionApprove && decision.Action != DecisionDeny {
		return fmt.Errorf("unsupported decision action %q", decision.Action)
	}
	if strings.TrimSpace(decision.Subject) == "" {
		return errors.New("decision subject is required")
	}
	for _, detail := range decision.Details {
		if strings.TrimSpace(detail.Key) == "" {
			return errors.New("decision detail key is required")
		}
	}
	return nil
}
