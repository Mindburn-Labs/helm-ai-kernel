package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	cliui "github.com/Mindburn-Labs/helm-ai-kernel/core/internal/cli/ui"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/translog"
)

func init() {
	Register(Subcommand{
		Name:  "log",
		Usage: "Receipt transparency log (append, sth, prove, verify-inclusion, verify-consistency)",
		RunFn: runTranslogCmd,
	})
}

// translogDataDir resolves the kernel data directory the same way the
// freeze surface does: flag > HELM_DATA_DIR > "data".
func translogDataDir(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if dir := os.Getenv("HELM_DATA_DIR"); dir != "" {
		return dir
	}
	return "data"
}

func openTranslog(dataDir string) (*translog.Log, error) {
	return translog.Open(filepath.Join(dataDir, "translog"))
}

// runTranslogCmd implements `helm-ai-kernel log`.
//
// Usage:
//
//	helm-ai-kernel log append --leaf-hash <hex receipt hash> [--data-dir d]
//	helm-ai-kernel log sth [--data-dir d]
//	helm-ai-kernel log prove --index N [--size M] [--data-dir d]
//	helm-ai-kernel log prove --old-size A [--new-size B] [--data-dir d]
//	helm-ai-kernel log verify-inclusion --proof <file> --root <hex>
//	helm-ai-kernel log verify-consistency --proof <file> [--old-root <hex>] [--new-root <hex>]
func runTranslogCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(stderr, "Usage: helm-ai-kernel log <append|sth|prove|verify-inclusion|verify-consistency> [flags]")
		return 2
	}
	switch args[0] {
	case "append":
		return runTranslogAppend(args[1:], stdout, stderr)
	case "sth":
		return runTranslogSTH(args[1:], stdout, stderr)
	case "prove":
		return runTranslogProve(args[1:], stdout, stderr)
	case "verify-inclusion":
		return runTranslogVerifyInclusion(args[1:], stdout, stderr)
	case "verify-consistency":
		return runTranslogVerifyConsistency(args[1:], stdout, stderr)
	default:
		return cliui.WriteError(stderr, cliui.UsageErrorf("log", "unknown subcommand: %s", args[0]).WithHint("append|sth|prove|verify-inclusion|verify-consistency"))
	}
}

func runTranslogAppend(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("log append", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	leafHashHex := cmd.String("leaf-hash", "", "Hex SHA-256 receipt hash to append as a leaf (REQUIRED)")
	dataDir := cmd.String("data-dir", "", "Kernel data directory (default $HELM_DATA_DIR or ./data)")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *leafHashHex == "" {
		return cliui.WriteError(stderr, cliui.UsageErrorf("log append", "--leaf-hash is required"))
	}
	leafInput, err := hex.DecodeString(*leafHashHex)
	if err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitUsage, "log append", "--leaf-hash is not valid hex"))
	}
	l, err := openTranslog(translogDataDir(*dataDir))
	if err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitFailure, "log append", "opening transparency log"))
	}
	index, err := l.Append(leafInput)
	if err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitFailure, "log append", "appending leaf"))
	}
	leaf := translog.LeafHash(leafInput)
	out := map[string]any{
		"leaf_index": index,
		"leaf_hash":  hex.EncodeToString(leaf[:]),
		"tree_size":  l.Size(),
	}
	return printTranslogJSON(stdout, stderr, out)
}

func runTranslogSTH(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("log sth", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	dataDir := cmd.String("data-dir", "", "Kernel data directory (default $HELM_DATA_DIR or ./data)")
	size := cmd.Uint64("size", 0, "Tree size to checkpoint (default: current size)")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	dir := translogDataDir(*dataDir)
	l, err := openTranslog(dir)
	if err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitFailure, "log sth", "opening transparency log"))
	}
	treeSize := *size
	if treeSize == 0 {
		treeSize = l.Size()
	}
	root, err := l.Root(treeSize)
	if err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitFailure, "log sth", "computing root"))
	}
	signer, err := loadOrGenerateSignerWithDataDir(dir)
	if err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitFailure, "log sth", "loading signer"))
	}
	logID := translog.LogIDFromPublicKey(signer.PublicKeyBytes())
	sth, err := translog.SignTreeHead(signer, logID, treeSize, root, time.Now())
	if err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitFailure, "log sth", "signing tree head"))
	}
	return printTranslogJSON(stdout, stderr, sth)
}

func runTranslogProve(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("log prove", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	dataDir := cmd.String("data-dir", "", "Kernel data directory (default $HELM_DATA_DIR or ./data)")
	index := cmd.Uint64("index", 0, "Leaf index for an inclusion proof")
	size := cmd.Uint64("size", 0, "Tree size for the inclusion proof (default: current size)")
	oldSize := cmd.Uint64("old-size", 0, "Old tree size for a consistency proof")
	newSize := cmd.Uint64("new-size", 0, "New tree size for the consistency proof (default: current size)")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	indexSet := false
	cmd.Visit(func(f *flag.Flag) {
		if f.Name == "index" {
			indexSet = true
		}
	})

	l, err := openTranslog(translogDataDir(*dataDir))
	if err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitFailure, "log prove", "opening transparency log"))
	}

	switch {
	case *oldSize > 0:
		ns := *newSize
		if ns == 0 {
			ns = l.Size()
		}
		proof, err := l.ConsistencyProof(*oldSize, ns)
		if err != nil {
			return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitFailure, "log prove", "building consistency proof"))
		}
		return printTranslogJSON(stdout, stderr, proof)
	case indexSet:
		ts := *size
		if ts == 0 {
			ts = l.Size()
		}
		proof, err := l.InclusionProof(*index, ts)
		if err != nil {
			return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitFailure, "log prove", "building inclusion proof"))
		}
		return printTranslogJSON(stdout, stderr, proof)
	default:
		return cliui.WriteError(stderr, cliui.UsageErrorf("log prove", "pass --index for an inclusion proof or --old-size for a consistency proof"))
	}
}

func runTranslogVerifyInclusion(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("log verify-inclusion", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	proofPath := cmd.String("proof", "", "Path to an inclusion proof JSON file (REQUIRED)")
	root := cmd.String("root", "", "Trusted hex root hash to verify against (REQUIRED)")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *proofPath == "" || *root == "" {
		return cliui.WriteError(stderr, cliui.UsageErrorf("log verify-inclusion", "--proof and --root are required"))
	}
	var proof translog.InclusionProof
	if err := readTranslogJSON(*proofPath, &proof); err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitUsage, "log verify-inclusion", "reading proof"))
	}
	if err := translog.VerifyInclusion(&proof, *root); err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitFailure, "", "INVALID"))
	}
	_, _ = fmt.Fprintf(stdout, "OK: leaf %d is included in tree of size %d under root %s\n", proof.LeafIndex, proof.TreeSize, *root)
	return 0
}

func runTranslogVerifyConsistency(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("log verify-consistency", flag.ContinueOnError)
	cmd.SetOutput(stderr)
	proofPath := cmd.String("proof", "", "Path to a consistency proof JSON file (REQUIRED)")
	oldRoot := cmd.String("old-root", "", "Trusted old hex root hash (default: value embedded in the proof)")
	newRoot := cmd.String("new-root", "", "Trusted new hex root hash (default: value embedded in the proof)")
	if err := cmd.Parse(args); err != nil {
		return 2
	}
	if *proofPath == "" {
		return cliui.WriteError(stderr, cliui.UsageErrorf("log verify-consistency", "--proof is required"))
	}
	var proof translog.ConsistencyProof
	if err := readTranslogJSON(*proofPath, &proof); err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitUsage, "log verify-consistency", "reading proof"))
	}
	if *oldRoot != "" {
		proof.OldRoot = *oldRoot
	}
	if *newRoot != "" {
		proof.NewRoot = *newRoot
	}
	if err := translog.VerifyConsistency(&proof); err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitFailure, "", "INVALID"))
	}
	_, _ = fmt.Fprintf(stdout, "OK: tree of size %d is a consistent append-only extension of tree of size %d\n", proof.NewSize, proof.OldSize)
	return 0
}

func readTranslogJSON(path string, v any) error {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied proof file path
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func printTranslogJSON(stdout, stderr io.Writer, v any) int {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return cliui.WriteError(stderr, cliui.Wrapf(err, cliui.ExitFailure, "log", "encoding output"))
	}
	_, _ = fmt.Fprintln(stdout, string(data))
	return 0
}
