package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	cliui "github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
)

// freezeStatePath returns the freeze state file in dataDir. An empty dataDir
// means HELM_DATA_DIR, then ./data. A server started with --data-dir reads its
// freeze state from that directory, so `freeze --data-dir` must name the same
// one.
func freezeStatePath(dataDir string) string {
	return filepath.Join(normalizedDataDir(dataDir), "freeze_state.json")
}

// persistedFreezeState is the on-disk representation of freeze state.
type persistedFreezeState struct {
	Frozen   bool                   `json:"frozen"`
	FrozenBy string                 `json:"frozen_by,omitempty"`
	FrozenAt time.Time              `json:"frozen_at,omitempty"`
	Receipts []kernel.FreezeReceipt `json:"receipts"`
}

func loadFreezeState(dataDir string) (*persistedFreezeState, error) {
	data, err := os.ReadFile(freezeStatePath(dataDir))
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

func saveFreezeState(dataDir string, state *persistedFreezeState) error {
	path := freezeStatePath(dataDir)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// runFreezeCmd implements `helm-ai-kernel freeze` and `helm-ai-kernel unfreeze`.
//
// Usage:
//
//	helm-ai-kernel freeze   --principal <who>  [--data-dir DIR] [--json]
//	helm-ai-kernel unfreeze --principal <who>  [--data-dir DIR] [--json]
//	helm-ai-kernel freeze   --status           [--data-dir DIR] [--json]
func runFreezeCmd(args []string, stdout, stderr io.Writer, action string) int {
	cmd := flag.NewFlagSet("freeze", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		principal  string
		status     bool
		jsonOutput bool
		dataDir    string
	)
	cmd.StringVar(&principal, "principal", "", "Principal performing the action (REQUIRED for freeze/unfreeze)")
	cmd.StringVar(&dataDir, "data-dir", "", "Kernel data directory holding freeze_state.json; use the server's --data-dir (default $HELM_DATA_DIR, then ./data)")
	cmd.BoolVar(&status, "status", false, "Show freeze status only")
	cmd.BoolVar(&jsonOutput, "json", false, "Output as JSON (alias for --format=json)")
	formatFlag := cliui.RegisterFormat(cmd, cliui.FormatText)

	if code, ok := cliui.ParseFlags(cmd, args, stderr, "freeze", cliui.FormatText); !ok {
		return code
	}
	jsonOutput = jsonOutput || formatFlag.IsJSON()

	// Status mode
	if status || action == "freeze-status" {
		state, err := loadFreezeState(dataDir)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "Error loading freeze state: %v\n", err)
			return 2
		}
		if jsonOutput {
			data, _ := json.MarshalIndent(state, "", "  ")
			_, _ = fmt.Fprintln(stdout, string(data))
		} else {
			if state.Frozen {
				_, _ = fmt.Fprintf(stdout, "FROZEN by %s at %s\n", state.FrozenBy, state.FrozenAt.Format(time.RFC3339))
			} else {
				_, _ = fmt.Fprintln(stdout, "System is NOT frozen")
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
	state, err := loadFreezeState(dataDir)
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

	if err := saveFreezeState(dataDir, state); err != nil {
		_, _ = fmt.Fprintf(stderr, "Error saving freeze state: %v\n", err)
		return 2
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(receipt, "", "  ")
		_, _ = fmt.Fprintln(stdout, string(data))
	} else {
		switch action {
		case "freeze":
			_, _ = fmt.Fprintf(stdout, "FROZEN by %s at %s\n", receipt.Principal, receipt.Timestamp.Format(time.RFC3339))
			_, _ = fmt.Fprintf(stdout, "   Content Hash: %s\n", receipt.ContentHash[:16]+"…")
		case "unfreeze":
			_, _ = fmt.Fprintf(stdout, "UNFROZEN by %s at %s\n", receipt.Principal, receipt.Timestamp.Format(time.RFC3339))
			_, _ = fmt.Fprintf(stdout, "   Content Hash: %s\n", receipt.ContentHash[:16]+"…")
		}
	}

	return 0
}

func init() {
	Register(Subcommand{Name: "freeze", Aliases: []string{}, Usage: "Activate global freeze (--principal)", RunFn: func(args []string, stdout, stderr io.Writer) int { return runFreezeCmd(args, stdout, stderr, "freeze") }})
	Register(Subcommand{Name: "unfreeze", Aliases: []string{}, Usage: "Deactivate freeze (--principal)", RunFn: func(args []string, stdout, stderr io.Writer) int {
		return runFreezeCmd(args, stdout, stderr, "unfreeze")
	}})
}
