package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func runApprovalsSurfaceCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel approvals <list|create|approve|deny|revoke|challenge|assert> [flags]")
		return 2
	}
	if answeredSurfaceHelp("Usage: helm-ai-kernel approvals <list|show|approve|deny|challenge|assert> [flags]", args, stdout) {
		return 0
	}
	registry := newLocalSurfaceRegistry()
	switch args[0] {
	case "list":
		return runApprovalsList(args[1:], registry, stdout, stderr)
	case "create":
		return runApprovalsCreate(args[1:], registry, stdout, stderr)
	case "approve":
		return runApprovalsTransition(args[1:], registry, contracts.ApprovalCeremonyAllowed, stdout, stderr)
	case "deny":
		return runApprovalsTransition(args[1:], registry, contracts.ApprovalCeremonyDenied, stdout, stderr)
	case "revoke":
		return runApprovalsTransition(args[1:], registry, contracts.ApprovalCeremonyRevoked, stdout, stderr)
	case "challenge":
		return runApprovalsChallenge(args[1:], registry, stdout, stderr)
	case "assert":
		return runApprovalsAssert(args[1:], registry, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "Unknown approvals subcommand: %s\n", args[0])
		return 2
	}
}

func runApprovalsList(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("approvals list", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	approvals := registry.ListApprovals()
	if *jsonOutput {
		return writeSurfaceJSON(stdout, approvals)
	}
	for _, approval := range approvals {
		fmt.Fprintf(stdout, "%s  state=%s subject=%s action=%s\n", approval.ApprovalID, approval.State, approval.Subject, approval.Action)
	}
	return 0
}

func runApprovalsCreate(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("approvals create", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	subject := cmd.String("subject", "", "Approval subject")
	action := cmd.String("action", "", "Approval action")
	requestedBy := cmd.String("requested-by", "agent:anonymous-dev", "Requester identity")
	reason := cmd.String("reason", "", "Approval reason")
	quorum := cmd.Int("quorum", 1, "Required quorum")
	timelockMs := cmd.Int64("timelock-ms", 0, "Timelock in milliseconds before approval can activate")
	expiresInMs := cmd.Int64("expires-in-ms", 0, "Expiry interval in milliseconds")
	breakGlass := cmd.Bool("break-glass", false, "Require break-glass reason and receipt")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *subject == "" || *action == "" {
		fmt.Fprintln(stderr, "Error: --subject and --action are required")
		return 2
	}
	now := time.Now().UTC()
	var timelock time.Time
	if *timelockMs > 0 {
		timelock = now.Add(time.Duration(*timelockMs) * time.Millisecond)
	}
	var expiresAt time.Time
	if *expiresInMs > 0 {
		expiresAt = now.Add(time.Duration(*expiresInMs) * time.Millisecond)
	}
	approval, err := registry.PutApproval(contracts.ApprovalCeremony{
		ApprovalID:    contracts.SurfaceID("approval", *subject+"-"+*action),
		Subject:       *subject,
		Action:        *action,
		State:         contracts.ApprovalCeremonyPending,
		RequestedBy:   *requestedBy,
		Quorum:        *quorum,
		TimelockUntil: timelock,
		ExpiresAt:     expiresAt,
		BreakGlass:    *breakGlass,
		Reason:        *reason,
		CreatedAt:     now,
		UpdatedAt:     now,
	})
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, approval)
	}
	fmt.Fprintf(stdout, "Created approval %s state=%s\n", approval.ApprovalID, approval.State)
	return 0
}

func runApprovalsChallenge(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("approvals challenge", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	approvalID := cmd.String("approval-id", "approval-bootstrap", "Approval id")
	method := cmd.String("method", "passkey", "Approval method")
	ttlMs := cmd.Int64("ttl-ms", int64((5*time.Minute)/time.Millisecond), "Challenge TTL in milliseconds")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	challenge, err := registry.CreateApprovalChallenge(*approvalID, *method, time.Duration(*ttlMs)*time.Millisecond)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, challenge)
	}
	fmt.Fprintf(stdout, "Approval challenge %s method=%s hash=%s\n", challenge.ChallengeID, challenge.Method, challenge.ChallengeHash)
	return 0
}

func runApprovalsAssert(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("approvals assert", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	challengeID := cmd.String("challenge-id", "", "Challenge id")
	actor := cmd.String("actor", "", "Principal presenting the assertion (required)")
	assertion := cmd.String("assertion", "", "Passkey/WebAuthn assertion or local signed assertion")
	receiptID := cmd.String("receipt-id", "", "Receipt this assertion is recorded against (required)")
	reason := cmd.String("reason", "passkey assertion accepted", "Reason")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *challengeID == "" || *assertion == "" {
		fmt.Fprintln(stderr, "Error: --challenge-id and --assertion are required")
		return 2
	}
	// An assertion names the principal it authenticates. Defaulting the actor or
	// the receipt would attribute a passkey ceremony to a principal who never
	// presented one.
	if missing := missingApprovalIdentity(*actor, *receiptID); len(missing) > 0 {
		fmt.Fprintf(stderr, "Error: %s required; an assertion must name the principal and the receipt\n", strings.Join(missing, ", "))
		return 2
	}
	approval, err := registry.AssertApprovalChallenge(contracts.ApprovalWebAuthnAssertion{
		ChallengeID: *challengeID,
		Actor:       *actor,
		Assertion:   *assertion,
		ReceiptID:   *receiptID,
		Reason:      *reason,
	})
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if *jsonOutput {
		return writeSurfaceJSONResult(stdout, approval, approval.State == contracts.ApprovalCeremonyAllowed)
	}
	fmt.Fprintf(stdout, "Approval %s state=%s method=%s\n", approval.ApprovalID, approval.State, approval.AuthMethod)
	if approval.State != contracts.ApprovalCeremonyAllowed {
		return 1
	}
	return 0
}

// missingApprovalIdentity names the identity fields an approval command left
// empty. It exists so the transition and assertion paths cannot drift: both
// write a principal and a receipt into the permanent ceremony record, and
// neither may invent one.
func missingApprovalIdentity(actor, receiptID string) []string {
	var missing []string
	if strings.TrimSpace(actor) == "" {
		missing = append(missing, "--actor")
	}
	if strings.TrimSpace(receiptID) == "" {
		missing = append(missing, "--receipt-id")
	}
	return missing
}

func runApprovalsTransition(args []string, registry *boundarypkg.SurfaceRegistry, state contracts.ApprovalCeremonyState, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("approvals transition", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	// None of these carry a default. A transition records who exercised authority
	// and against which receipt; a default would write an unattended command into
	// the ceremony as though a named principal had reviewed it.
	approvalID := cmd.String("approval-id", "", "Approval id (required; may also be given positionally)")
	actor := cmd.String("actor", "", "Principal exercising the authority (required)")
	receiptID := cmd.String("receipt-id", "", "Receipt this decision is recorded against (required)")
	expectedCeremonyHash := cmd.String("expected-ceremony-hash", "", "Refuse the transition unless the approval still matches this reviewed hash")
	reason := cmd.String("reason", string(state), "Reason")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *approvalID == "" && cmd.NArg() > 0 {
		*approvalID = cmd.Arg(0)
	}
	missing := missingApprovalIdentity(*actor, *receiptID)
	if strings.TrimSpace(*approvalID) == "" {
		missing = append([]string{"--approval-id"}, missing...)
	}
	if len(missing) > 0 {
		fmt.Fprintf(stderr, "Error: %s required; a transition must name the approval, the principal, and the receipt\n", strings.Join(missing, ", "))
		return 2
	}
	approval, err := registry.TransitionApprovalIfCurrent(*approvalID, state, *actor, *receiptID, *reason, *expectedCeremonyHash)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, approval)
	}
	fmt.Fprintf(stdout, "Approval %s transitioned to %s receipt=%s\n", approval.ApprovalID, approval.State, approval.ReceiptID)
	return 0
}
