package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/kernel"
)

// statePath returns the path to the freeze state file.
func freezeStatePath() string {
	dir := os.Getenv("HELM_DATA_DIR")
	if dir == "" {
		dir = "data"
	}
	return filepath.Join(dir, "freeze_state.json")
}

// persistedFreezeState is the on-disk representation of freeze state.
type persistedFreezeState struct {
	Frozen   bool                   `json:"frozen"`
	FrozenBy string                 `json:"frozen_by,omitempty"`
	FrozenAt time.Time              `json:"frozen_at,omitempty"`
	Receipts []kernel.FreezeReceipt `json:"receipts"`
}

func loadFreezeState() (*persistedFreezeState, error) {
	data, err := os.ReadFile(freezeStatePath())
	if err != nil {
		if os.IsNotExist(err) {
			return &persistedFreezeState{}, nil
		}
		return nil, err
	}
	var state persistedFreezeState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func saveFreezeState(state *persistedFreezeState) error {
	dir := filepath.Dir(freezeStatePath())
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(freezeStatePath(), data, 0600)
}

// runFreezeCmd implements `helm freeze` and `helm unfreeze`.
//
// Usage:
//
//	helm freeze   --principal <who>  [--json]
//	helm unfreeze --principal <who>  [--json]
//	helm freeze   --status           [--json]
func runFreezeCmd(args []string, stdout, stderr io.Writer, action string) int {
	cmd := flag.NewFlagSet("freeze", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		principal  string
		status     bool
		jsonOutput bool
	)
	cmd.StringVar(&principal, "principal", "", "Principal performing the action (REQUIRED for freeze/unfreeze)")
	cmd.BoolVar(&status, "status", false, "Show freeze status only")
	cmd.BoolVar(&jsonOutput, "json", false, "Output as JSON")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	// Status mode
	if status || action == "freeze-status" {
		state, err := loadFreezeState()
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error loading freeze state: %v\n", err)
			return 2
		}
		if jsonOutput {
			data, _ := json.MarshalIndent(state, "", "  ")
			_, _ = fmt.Fprintln(stdout, string(data))
		} else {
			if state.Frozen {
				_, _ = fmt.Fprintf(stdout, "🔴 FROZEN by %s at %s\n", state.FrozenBy, state.FrozenAt.Format(time.RFC3339))
			} else {
				_, _ = fmt.Fprintln(stdout, "🟢 System is NOT frozen")
			}
			if len(state.Receipts) > 0 {
				_, _ = fmt.Fprintf(stdout, "   %d transition(s) in audit trail\n", len(state.Receipts))
			}
		}
		return 0
	}

	if principal == "" {
		_, _ = fmt.Fprintln(stderr, "Error: --principal is required")
		return 2
	}

	// Load existing state
	state, err := loadFreezeState()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error loading freeze state: %v\n", err)
		return 2
	}

	fc := kernel.NewFreezeController()
	// Replay state into controller
	if state.Frozen {
		fc.Freeze(state.FrozenBy)
	}

	var receipt *kernel.FreezeReceipt
	switch action {
	case "freeze":
		receipt, err = fc.Freeze(principal)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
		state.Frozen = true
		state.FrozenBy = principal
		state.FrozenAt = receipt.Timestamp
	case "unfreeze":
		receipt, err = fc.Unfreeze(principal)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
			return 1
		}
		state.Frozen = false
		state.FrozenBy = ""
		state.FrozenAt = time.Time{}
	default:
		_, _ = fmt.Fprintf(stderr, "Unknown action: %s\n", action)
		return 2
	}

	state.Receipts = append(state.Receipts, *receipt)

	if err := saveFreezeState(state); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error saving freeze state: %v\n", err)
		return 2
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(receipt, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
	} else {
		switch action {
		case "freeze":
			_, _ = fmt.Fprintf(stdout, "🔴 FROZEN by %s at %s\n", receipt.Principal, receipt.Timestamp.Format(time.RFC3339))
			_, _ = fmt.Fprintf(stdout, "   Content Hash: %s\n", receipt.ContentHash[:16]+"…")
		case "unfreeze":
			_, _ = fmt.Fprintf(stdout, "🟢 UNFROZEN by %s at %s\n", receipt.Principal, receipt.Timestamp.Format(time.RFC3339))
			_, _ = fmt.Fprintf(stdout, "   Content Hash: %s\n", receipt.ContentHash[:16]+"…")
		}
	}

	return 0
}

func init() {
	Register(Subcommand{Name: "freeze", Aliases: []string{}, Usage: "Activate global freeze (--principal)", RunFn: func(args []string, stdout, stderr io.Writer) int { return runFreezeCmd(args, stdout, stderr, "freeze") }})
	Register(Subcommand{Name: "unfreeze", Aliases: []string{}, Usage: "Deactivate freeze (--principal)", RunFn: func(args []string, stdout, stderr io.Writer) int { return runFreezeCmd(args, stdout, stderr, "unfreeze") }})
}
