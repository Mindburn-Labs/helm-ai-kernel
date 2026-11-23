package main

// quantum_posture: SHA-256 supplies a stable Console event ID for display.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/store"
)

func aggregateAgents(receipts []*contracts.Receipt) []map[string]any {
	type agentStats struct {
		ID       string
		Count    int
		LastSeen string
		Verdict  string
	}
	stats := map[string]*agentStats{}
	for _, receipt := range receipts {
		id := strings.TrimSpace(receipt.ExecutorID)
		if id == "" {
			id = "anonymous"
		}
		entry := stats[id]
		if entry == nil {
			entry = &agentStats{ID: id}
			stats[id] = entry
		}
		entry.Count++
		entry.Verdict = receipt.Status
		if receipt.Timestamp.After(parseTime(entry.LastSeen)) {
			entry.LastSeen = receipt.Timestamp.UTC().Format(time.RFC3339Nano)
		}
	}
	records := make([]map[string]any, 0, len(stats))
	for _, stat := range stats {
		records = append(records, map[string]any{
			"agent":     stat.ID,
			"receipts":  stat.Count,
			"last_seen": stat.LastSeen,
			"verdict":   stat.Verdict,
		})
	}
	sort.Slice(records, func(i, j int) bool {
		return fmt.Sprint(records[i]["agent"]) < fmt.Sprint(records[j]["agent"])
	})
	return records
}

func aggregateActions(receipts []*contracts.Receipt) []map[string]any {
	type actionStats struct {
		Action string
		Count  int
		Last   string
		Hash   string
	}
	stats := map[string]*actionStats{}
	for _, receipt := range receipts {
		action := strings.TrimSpace(receipt.EffectID)
		if action == "" {
			action = metadataString(receipt.Metadata, "action")
		}
		if action == "" {
			action = "unknown"
		}
		entry := stats[action]
		if entry == nil {
			entry = &actionStats{Action: action}
			stats[action] = entry
		}
		entry.Count++
		entry.Last = receipt.Timestamp.UTC().Format(time.RFC3339Nano)
		entry.Hash = receipt.ReceiptID
	}
	records := make([]map[string]any, 0, len(stats))
	for _, stat := range stats {
		records = append(records, map[string]any{
			"action":       stat.Action,
			"count":        stat.Count,
			"last_seen":    stat.Last,
			"last_receipt": stat.Hash,
		})
	}
	sort.Slice(records, func(i, j int) bool {
		return fmt.Sprint(records[i]["action"]) < fmt.Sprint(records[j]["action"])
	})
	return records
}

func metadataString(metadata map[string]any, key string) string {
	if metadata == nil {
		return ""
	}
	value, ok := metadata[key]
	if !ok || value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func receiptAuditRecords(receipts []*contracts.Receipt) []map[string]any {
	records := make([]map[string]any, 0, len(receipts))
	for _, receipt := range receipts {
		records = append(records, map[string]any{
			"event_id":    stableConsoleEventID(receipt),
			"at":          receipt.Timestamp.UTC().Format(time.RFC3339Nano),
			"actor":       receipt.ExecutorID,
			"action":      receipt.EffectID,
			"status":      receipt.Status,
			"receipt_id":  receipt.ReceiptID,
			"decision_id": receipt.DecisionID,
		})
	}
	return records
}

func replayConsoleRecords(receipts []*contracts.Receipt) []map[string]any {
	records := make([]map[string]any, 0, len(receipts))
	for _, receipt := range receipts {
		records = append(records, map[string]any{
			"receipt_id":    receipt.ReceiptID,
			"executor_id":   receipt.ExecutorID,
			"lamport_clock": receipt.LamportClock,
			"prev_hash":     receipt.PrevHash,
			"signature":     receipt.Signature != "",
		})
	}
	return records
}

func stableConsoleEventID(receipt *contracts.Receipt) string {
	sum := sha256.Sum256([]byte(receipt.ReceiptID + receipt.DecisionID + receipt.Timestamp.UTC().Format(time.RFC3339Nano)))
	return "audit_" + fmt.Sprintf("%x", sum[:6])
}

func parseTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed
}

func listConsoleReceipts(ctx context.Context, svc *Services, limit int) []*contracts.Receipt {
	tenantID, err := authenticatedReceiptTenantID(ctx)
	if err != nil {
		return nil
	}
	if svc == nil || svc.ReceiptStore == nil {
		return nil
	}
	reader, ok := svc.ReceiptStore.(store.TenantScopedLatestReceiptReader)
	if !ok {
		return nil
	}
	receipts, err := reader.ListLatestByTenant(ctx, tenantID, limit)
	if err != nil {
		return nil
	}
	return receipts
}
