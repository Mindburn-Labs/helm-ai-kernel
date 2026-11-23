package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	cliui "github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
	boundarypkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func runIdentityCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "agents" {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel identity agents [--json]")
		return 2
	}
	cmd := flag.NewFlagSet("identity agents", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args[1:]); err != nil {
		return 2
	}
	agents := newLocalSurfaceRegistry().ListAgents()
	if *jsonOutput {
		return writeSurfaceJSON(stdout, agents)
	}
	for _, agent := range agents {
		fmt.Fprintf(stdout, "%s  type=%s anonymous_dev=%t\n", agent.AgentID, agent.IdentityType, agent.AnonymousDev)
	}
	return 0
}

func runAuthzSurfaceCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: helm-ai-kernel authz <health|check|snapshots|get> [flags]")
		return 2
	}
	if answeredSurfaceHelp("Usage: helm-ai-kernel authz <health|check|snapshots|get> [flags]", args, stdout) {
		return 0
	}
	switch args[0] {
	case "health":
		return runAuthzHealth(args[1:], stdout, stderr)
	case "check":
		return runAuthzCheck(args[1:], nil, stdout, stderr)
	case "snapshots":
		return runAuthzSnapshots(args[1:], newLocalSurfaceRegistry(), stdout, stderr)
	case "get":
		return runAuthzGet(args[1:], newLocalSurfaceRegistry(), stdout, stderr)
	default:
		fmt.Fprintf(stderr, "Unknown authz subcommand: %s\n", args[0])
		return 2
	}
}

func runAuthzHealth(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("authz health", flag.ContinueOnError)
	options := registerSurfaceInspectFlags(cmd, false)
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if code, ok := cliui.ParseFlags(cmd, args, stderr, "authz health", cliui.FormatText); !ok {
		return code
	}
	if cmd.NArg() != 0 {
		return writeAuthzUsageError(stderr, *jsonOutput, "authz health", "unexpected positional argument")
	}
	started := time.Now()
	var health contracts.AuthzHealth
	if err := options.request(http.MethodGet, "/api/v1/authz/health", nil, nil, false, &health); err != nil {
		return writeAuthzUnavailable(stdout, *jsonOutput, err.Error())
	}
	if health.Status != "ready" || health.Resolver != "helm-rebac" || health.ModelID != "helm-local-v1" ||
		!surfaceSHA256(health.RelationshipHash) || health.Stale || health.ModelMismatch || !surfaceCheckIsCurrent(health.CheckedAt, started) {
		return writeAuthzUnavailable(stdout, *jsonOutput, "authorization resolver did not report a current ready state")
	}
	if *jsonOutput {
		if cliui.WriteJSON(stdout, health) != nil {
			return 1
		}
	} else {
		fmt.Fprintf(stdout, "Authz health: %s resolver=%s\n", health.Status, health.Resolver)
	}
	return 0
}

// Keep the registry parameter for callers of the existing command helper;
// health/check no longer create or seal authorization decisions locally.
func runAuthzCheck(args []string, _ *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("authz check", flag.ContinueOnError)
	options := registerSurfaceInspectFlags(cmd, false)
	subject := cmd.String("subject", "agent:anonymous-dev", "Subject")
	object := cmd.String("object", "tool:file_read", "Object")
	relation := cmd.String("relation", "can_call", "Relation")
	modelID := cmd.String("model-id", "helm-local-v1", "Authorization model id")
	stale := cmd.Bool("stale", false, "Mark tuple snapshot stale")
	modelMismatch := cmd.Bool("model-mismatch", false, "Mark model mismatch")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if code, ok := cliui.ParseFlags(cmd, args, stderr, "authz check", cliui.FormatText); !ok {
		return code
	}
	if cmd.NArg() != 0 || strings.TrimSpace(*subject) == "" || strings.TrimSpace(*object) == "" || strings.TrimSpace(*relation) == "" || strings.TrimSpace(*modelID) == "" {
		return writeAuthzUsageError(stderr, *jsonOutput, "authz check", "subject, object, relation and model-id must be nonempty; positional arguments are not accepted")
	}
	request := map[string]any{
		"resolver": "helm-rebac", "subject": *subject, "object": *object,
		"relation": *relation, "model_id": *modelID, "stale": *stale, "model_mismatch": *modelMismatch,
	}
	started := time.Now()
	var response struct {
		contracts.AuthzSnapshot
		Decision *bool `json:"decision"`
	}
	if err := options.request(http.MethodPost, "/api/v1/authz/check", nil, request, false, &response); err != nil {
		return writeAuthzUnavailable(stdout, *jsonOutput, err.Error())
	}
	if response.Decision == nil {
		return writeAuthzUnavailable(stdout, *jsonOutput, "authorization response omitted the decision")
	}
	snapshot := response.AuthzSnapshot
	snapshot.Decision = *response.Decision
	if snapshot.Validate() != nil || snapshot.Subject != *subject || snapshot.Object != *object || snapshot.Relation != *relation ||
		snapshot.Resolver != "helm-rebac" || snapshot.ModelID != *modelID || !surfaceSHA256(snapshot.RelationshipHash) ||
		snapshot.Stale || snapshot.ModelMismatch || *stale || *modelMismatch || !surfaceCheckIsCurrent(snapshot.CheckedAt, started) {
		return writeAuthzUnavailable(stdout, *jsonOutput, "authorization response is incomplete, mismatched or stale")
	}
	sealed, err := snapshot.Seal()
	if err != nil || snapshot.SnapshotHash == "" || sealed.SnapshotHash != snapshot.SnapshotHash {
		return writeAuthzUnavailable(stdout, *jsonOutput, "authorization snapshot hash does not match its fields")
	}
	if *jsonOutput {
		if cliui.WriteJSON(stdout, snapshot) != nil {
			return 1
		}
	} else {
		fmt.Fprintf(stdout, "Authz decision=%t snapshot=%s hash=%s\n", snapshot.Decision, snapshot.SnapshotID, snapshot.SnapshotHash)
	}
	if !snapshot.Decision {
		return 1
	}
	return 0
}

func writeAuthzUnavailable(stdout io.Writer, jsonOutput bool, message string) int {
	if jsonOutput {
		_ = cliui.WriteJSON(stdout, struct {
			Status  string `json:"status"`
			Checked bool   `json:"checked"`
			Message string `json:"message"`
		}{Status: "unavailable", Message: message})
	} else {
		fmt.Fprintf(stdout, "Authz unavailable: %s\n", message)
	}
	return 1
}

func writeAuthzUsageError(stderr io.Writer, jsonOutput bool, command, message string) int {
	format := cliui.FormatText
	if jsonOutput {
		format = cliui.FormatJSON
	}
	return cliui.WriteErrorFormat(stderr, cliui.UsageErrorf(command, "%s", message), format)
}

func surfaceSHA256(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func runAuthzSnapshots(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("authz snapshots", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	snapshots := registry.ListSnapshots()
	if *jsonOutput {
		return writeSurfaceJSON(stdout, snapshots)
	}
	for _, snapshot := range snapshots {
		fmt.Fprintf(stdout, "%s  decision=%t hash=%s\n", snapshot.SnapshotID, snapshot.Decision, snapshot.SnapshotHash)
	}
	return 0
}

func runAuthzGet(args []string, registry *boundarypkg.SurfaceRegistry, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("authz get", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	snapshotID := cmd.String("snapshot-id", "", "Snapshot id")
	jsonOutput := cmd.Bool("json", false, "Output as JSON")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *snapshotID == "" && cmd.NArg() > 0 {
		*snapshotID = cmd.Arg(0)
	}
	if *snapshotID == "" {
		fmt.Fprintln(stderr, "Error: --snapshot-id is required")
		return 2
	}
	snapshot, ok := registry.GetSnapshot(*snapshotID)
	if !ok {
		fmt.Fprintf(stderr, "Error: authz snapshot %q not found\n", *snapshotID)
		return 1
	}
	if *jsonOutput {
		return writeSurfaceJSON(stdout, snapshot)
	}
	fmt.Fprintf(stdout, "Authz snapshot %s decision=%t hash=%s\n", snapshot.SnapshotID, snapshot.Decision, snapshot.SnapshotHash)
	return 0
}
