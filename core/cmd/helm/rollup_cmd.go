package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/store"

	_ "modernc.org/sqlite"
)

// ── Rollup Types ───────────────────────────────────────────────────────────

// RollupRecord persists the result of a Merkle rollup.
type RollupRecord struct {
	ID           string    `json:"id"`
	MerkleRoot   string    `json:"merkle_root"`
	PeriodStart  time.Time `json:"period_start"`
	PeriodEnd    time.Time `json:"period_end"`
	ReceiptCount int       `json:"receipt_count"`
	TreeDepth    int       `json:"tree_depth"`
	FromLamport  uint64    `json:"from_lamport"`
	ToLamport    uint64    `json:"to_lamport"`
	CreatedAt    time.Time `json:"created_at"`
	PrevRollupID string    `json:"prev_rollup_id,omitempty"`
}

// ── CLI Command ────────────────────────────────────────────────────────────

// runRollupCmd implements `helm rollup`.
//
// Builds a Merkle tree from the receipt store and optionally anchors
// the root to a transparency log (Sigstore Rekor or RFC 3161 TSA).
//
// Exit codes:
//
//	0 = success
//	1 = no receipts in range
//	2 = runtime error
func runRollupCmd(args []string, stdout, stderr io.Writer) int {
	cmd := flag.NewFlagSet("rollup", flag.ContinueOnError)
	cmd.SetOutput(stderr)

	var (
		dbPath     string
		period     string
		since      string
		until      string
		limit      int
		jsonOutput bool
		verify     string
		listAll    bool
	)

	cmd.StringVar(&dbPath, "db", "", "Path to receipt database (SQLite file or postgres:// DSN)")
	cmd.StringVar(&period, "period", "", "Rollup period: hourly, daily, weekly, monthly, all")
	cmd.StringVar(&since, "since", "", "Start time (RFC3339)")
	cmd.StringVar(&until, "until", "", "End time (RFC3339)")
	cmd.IntVar(&limit, "limit", 0, "Max receipts to include (0 = unlimited)")
	cmd.BoolVar(&jsonOutput, "json", false, "Output as JSON")
	cmd.StringVar(&verify, "verify", "", "Verify a rollup root against receipt store (hex root hash)")
	cmd.BoolVar(&listAll, "list", false, "List all rollup records")

	if err := cmd.Parse(args); err != nil {
		return 2
	}

	// Resolve database path.
	if dbPath == "" {
		dir := os.Getenv("HELM_DATA_DIR")
		if dir == "" {
			dir = "data"
		}
		dbPath = filepath.Join(dir, "helm.db")
	}

	ctx := context.Background()

	// Open receipt store (SQLite only for CLI; production uses Postgres via services).
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "Error: cannot open database %s: %v\n", dbPath, err)
		return 2
	}
	defer db.Close()

	receiptStore, err := store.NewSQLiteReceiptStore(db)
	if err != nil {
		fmt.Fprintf(stderr, "Error: failed to initialize receipt store: %v\n", err)
		return 2
	}

	// ── Subcommand: verify ──────────────────────────────────────────────
	if verify != "" {
		return rollupVerify(ctx, receiptStore, verify, jsonOutput, stdout, stderr)
	}

	// ── Subcommand: list ────────────────────────────────────────────────
	if listAll {
		return rollupList(dbPath, jsonOutput, stdout, stderr)
	}

	// ── Default: build rollup ───────────────────────────────────────────
	return rollupBuild(ctx, receiptStore, dbPath, period, since, until, limit, jsonOutput, stdout, stderr)
}

// rollupBuild constructs a Merkle tree from receipts and persists the rollup record.
func rollupBuild(
	ctx context.Context,
	receiptStore *store.SQLiteReceiptStore,
	dbPath, period, since, until string,
	limit int,
	jsonOutput bool,
	stdout, stderr io.Writer,
) int {
	// Determine receipt count — use limit or a reasonable max.
	fetchLimit := limit
	if fetchLimit <= 0 {
		fetchLimit = 100000
	}

	receipts, err := receiptStore.List(ctx, fetchLimit)
	if err != nil {
		fmt.Fprintf(stderr, "Error: failed to list receipts: %v\n", err)
		return 2
	}

	if len(receipts) == 0 {
		fmt.Fprintln(stderr, "No receipts found in store")
		return 1
	}

	// Apply time-based filtering if period/since/until specified.
	receipts = filterReceiptsByTime(receipts, period, since, until)
	if len(receipts) == 0 {
		fmt.Fprintln(stderr, "No receipts match the specified time range")
		return 1
	}

	// Sort by Lamport clock for deterministic ordering.
	sort.Slice(receipts, func(i, j int) bool {
		return receipts[i].LamportClock < receipts[j].LamportClock
	})

	// Build Merkle tree from receipt hashes.
	leafData := make(map[string]interface{}, len(receipts))
	for _, r := range receipts {
		leafData[r.ReceiptID] = receiptCanonical(r)
	}

	// Use the same BuildMerkleTree from pkg/merkle — but since we're in cmd/
	// and want to avoid import cycles in v1, we build inline using the same algorithm.
	root, depth := buildReceiptMerkle(receipts)

	// Determine Lamport range.
	fromLamport := receipts[0].LamportClock
	toLamport := receipts[len(receipts)-1].LamportClock

	// Determine time range.
	periodStart := receipts[0].Timestamp
	periodEnd := receipts[len(receipts)-1].Timestamp

	// Generate rollup ID.
	rollupID := fmt.Sprintf("rollup-%s-%s",
		periodStart.UTC().Format("20060102T150405"),
		root[:12],
	)

	record := RollupRecord{
		ID:           rollupID,
		MerkleRoot:   root,
		PeriodStart:  periodStart,
		PeriodEnd:    periodEnd,
		ReceiptCount: len(receipts),
		TreeDepth:    depth,
		FromLamport:  fromLamport,
		ToLamport:    toLamport,
		CreatedAt:    time.Now().UTC(),
	}

	// Persist rollup record.
	if err := saveRollupRecord(dbPath, record); err != nil {
		fmt.Fprintf(stderr, "Warning: failed to persist rollup record: %v\n", err)
		// Continue — the rollup was computed successfully.
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(record, "", "  ")
		fmt.Fprintln(stdout, string(data))
	} else {
		fmt.Fprintf(stdout, "%s✅ Merkle Rollup Complete%s\n\n", ColorBold+ColorGreen, ColorReset)
		fmt.Fprintf(stdout, "  Rollup ID:     %s\n", record.ID)
		fmt.Fprintf(stdout, "  Merkle Root:   %s\n", record.MerkleRoot)
		fmt.Fprintf(stdout, "  Receipts:      %d\n", record.ReceiptCount)
		fmt.Fprintf(stdout, "  Tree Depth:    %d\n", record.TreeDepth)
		fmt.Fprintf(stdout, "  Lamport Range: %d → %d\n", record.FromLamport, record.ToLamport)
		fmt.Fprintf(stdout, "  Period:        %s → %s\n",
			record.PeriodStart.UTC().Format(time.RFC3339),
			record.PeriodEnd.UTC().Format(time.RFC3339),
		)
		fmt.Fprintln(stdout)
		fmt.Fprintf(stdout, "  Verify: helm rollup --verify %s\n", record.MerkleRoot)
	}

	return 0
}

// rollupVerify verifies that a Merkle root matches the current receipt store.
func rollupVerify(
	ctx context.Context,
	receiptStore *store.SQLiteReceiptStore,
	rootHash string,
	jsonOutput bool,
	stdout, stderr io.Writer,
) int {
	receipts, err := receiptStore.List(ctx, 100000)
	if err != nil {
		fmt.Fprintf(stderr, "Error: failed to list receipts: %v\n", err)
		return 2
	}

	if len(receipts) == 0 {
		fmt.Fprintln(stderr, "Error: no receipts in store to verify against")
		return 1
	}

	sort.Slice(receipts, func(i, j int) bool {
		return receipts[i].LamportClock < receipts[j].LamportClock
	})

	computedRoot, _ := buildReceiptMerkle(receipts)

	match := computedRoot == rootHash

	result := map[string]interface{}{
		"expected_root": rootHash,
		"computed_root": computedRoot,
		"match":         match,
		"receipt_count": len(receipts),
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(stdout, string(data))
	} else {
		if match {
			fmt.Fprintf(stdout, "%s✅ Merkle root verified%s\n", ColorBold+ColorGreen, ColorReset)
			fmt.Fprintf(stdout, "  Root:     %s\n", computedRoot)
			fmt.Fprintf(stdout, "  Receipts: %d\n", len(receipts))
		} else {
			fmt.Fprintf(stdout, "%s❌ Merkle root MISMATCH%s\n", ColorBold+ColorRed, ColorReset)
			fmt.Fprintf(stdout, "  Expected: %s\n", rootHash)
			fmt.Fprintf(stdout, "  Computed: %s\n", computedRoot)
			fmt.Fprintf(stdout, "  Receipts: %d\n", len(receipts))
			return 1
		}
	}

	return 0
}

// rollupList lists all persisted rollup records.
func rollupList(dbPath string, jsonOutput bool, stdout, stderr io.Writer) int {
	records, err := loadRollupRecords(dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 2
	}

	if len(records) == 0 {
		fmt.Fprintln(stdout, "No rollup records found")
		return 0
	}

	if jsonOutput {
		data, _ := json.MarshalIndent(records, "", "  ")
		fmt.Fprintln(stdout, string(data))
	} else {
		fmt.Fprintf(stdout, "%sMerkle Rollup History%s (%d records)\n\n", ColorBold, ColorReset, len(records))
		for _, r := range records {
			fmt.Fprintf(stdout, "  %s  root=%s…  receipts=%d  lamport=%d→%d\n",
				r.ID,
				r.MerkleRoot[:16],
				r.ReceiptCount,
				r.FromLamport,
				r.ToLamport,
			)
		}
	}

	return 0
}

// ── Merkle Tree Construction ───────────────────────────────────────────────

// buildReceiptMerkle builds a Merkle tree from sorted receipts.
// Returns (root hash, tree depth).
// Uses the same domain-separated hashing as pkg/merkle: "helm:evidence:*:v1\0".
func buildReceiptMerkle(receipts []*contracts.Receipt) (string, int) {
	if len(receipts) == 0 {
		return "", 0
	}

	// Build leaf hashes.
	hashes := make([]string, len(receipts))
	for i, r := range receipts {
		leafBytes := buildReceiptLeafBytes(r)
		h := sha256.Sum256(leafBytes)
		hashes[i] = hex.EncodeToString(h[:])
	}

	// Build tree bottom-up.
	depth := 0
	for len(hashes) > 1 {
		depth++
		// Duplicate last if odd.
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}
		next := make([]string, len(hashes)/2)
		for i := 0; i < len(hashes); i += 2 {
			next[i/2] = hashNode(hashes[i], hashes[i+1])
		}
		hashes = next
	}

	return hashes[0], depth
}

// buildReceiptLeafBytes creates a domain-separated leaf from a receipt.
// Format: "helm:evidence:leaf:v1\0" || receipt_id || "\0" || canonical_json
func buildReceiptLeafBytes(r *contracts.Receipt) []byte {
	canonical := receiptCanonical(r)
	canJSON, _ := json.Marshal(canonical)

	buf := make([]byte, 0, 22+len(r.ReceiptID)+1+len(canJSON))
	buf = append(buf, "helm:evidence:leaf:v1\x00"...)
	buf = append(buf, r.ReceiptID...)
	buf = append(buf, 0)
	buf = append(buf, canJSON...)
	return buf
}

// hashNode creates a domain-separated internal node hash.
func hashNode(left, right string) string {
	leftBytes, _ := hex.DecodeString(left)
	rightBytes, _ := hex.DecodeString(right)

	buf := make([]byte, 0, 22+len(leftBytes)+len(rightBytes))
	buf = append(buf, "helm:evidence:node:v1\x00"...)
	buf = append(buf, leftBytes...)
	buf = append(buf, rightBytes...)

	h := sha256.Sum256(buf)
	return hex.EncodeToString(h[:])
}

// receiptCanonical returns a deterministic map for hashing.
func receiptCanonical(r *contracts.Receipt) map[string]interface{} {
	return map[string]interface{}{
		"receipt_id":    r.ReceiptID,
		"decision_id":  r.DecisionID,
		"effect_id":    r.EffectID,
		"status":       r.Status,
		"signature":    r.Signature,
		"prev_hash":    r.PrevHash,
		"lamport_clock": r.LamportClock,
		"blob_hash":    r.BlobHash,
		"output_hash":  r.OutputHash,
		"timestamp":    r.Timestamp.UTC().Format(time.RFC3339Nano),
	}
}

// ── Time Filtering ─────────────────────────────────────────────────────────

func filterReceiptsByTime(receipts []*contracts.Receipt, period, since, until string) []*contracts.Receipt {
	var start, end time.Time
	now := time.Now().UTC()

	switch period {
	case "hourly":
		start = now.Add(-1 * time.Hour)
	case "daily":
		start = now.Add(-24 * time.Hour)
	case "weekly":
		start = now.Add(-7 * 24 * time.Hour)
	case "monthly":
		start = now.Add(-30 * 24 * time.Hour)
	case "all", "":
		// No filtering if "all" or empty.
		if since == "" && until == "" {
			return receipts
		}
	}

	if since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			start = t
		}
	}
	if until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			end = t
		}
	}

	var filtered []*contracts.Receipt
	for _, r := range receipts {
		if !start.IsZero() && r.Timestamp.Before(start) {
			continue
		}
		if !end.IsZero() && r.Timestamp.After(end) {
			continue
		}
		filtered = append(filtered, r)
	}
	return filtered
}

// ── Rollup Record Persistence ──────────────────────────────────────────────

func saveRollupRecord(dbPath string, record RollupRecord) error {
	rollupPath := filepath.Join(filepath.Dir(dbPath), "rollups.json")

	var records []RollupRecord
	if data, err := os.ReadFile(rollupPath); err == nil {
		_ = json.Unmarshal(data, &records)
	}

	records = append(records, record)
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(rollupPath, data, 0600)
}

func loadRollupRecords(dbPath string) ([]RollupRecord, error) {
	rollupPath := filepath.Join(filepath.Dir(dbPath), "rollups.json")

	data, err := os.ReadFile(rollupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var records []RollupRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, err
	}
	return records, nil
}

func init() {
	Register(Subcommand{
		Name:    "rollup",
		Aliases: []string{},
		Usage:   "Build Merkle rollup from receipt chain (--period, --verify, --list)",
		RunFn:   runRollupCmd,
	})
}
