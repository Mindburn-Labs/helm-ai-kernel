package inferencegateway

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts/economic"
)

// intentPrefix is the deterministic SpendIntent id prefix. The idempotency key
// is embedded so Settle can recover it from the quote alone.
const intentPrefix = "si-"

func spendIntentID(tenantID, idempotencyKey string) string {
	return intentPrefix + shortHash(tenantID, idempotencyKey)
}

// idempotencyFromIntent recovers the idempotency token bound into a SpendIntent
// id. Settle keys the ledger on this so a replay collapses onto the same debit.
func idempotencyFromIntent(intentID string) string {
	return strings.TrimPrefix(intentID, intentPrefix)
}

func quoteID(tenantID, idempotencyKey string) string {
	return "rq-" + shortHash(tenantID, idempotencyKey)
}

func receiptID(tenantID, idempotencyKey string) string {
	return "bvr-" + shortHash(tenantID, idempotencyKey)
}

func usageReceiptID(tenantID, idempotencyKey string) string {
	return "ur-" + shortHash(tenantID, idempotencyKey)
}

// evidencePackRef builds a content-addressed EvidencePack reference for the
// request. Real EvidencePack assembly lives in core/pkg/evidencepack; the
// gateway emits a stable ref keyed to the request and its price snapshot.
func evidencePackRef(tenantID, idempotencyKey, priceSnapshotHash string) string {
	digest := shortHash(tenantID, idempotencyKey, priceSnapshotHash)
	return "evidence://route-quote/" + tenantID + "/" + digest
}

// hashRoutePolicy produces the deterministic RoutePolicyHash bound into every
// quote and receipt, covering the policy id and the runtime policy knobs.
func hashRoutePolicy(policyID string, ttl time.Duration, stale StalePricePolicy, costCap CostCapPolicy, feeBps int64) string {
	canon := fmt.Sprintf("policy=%s;ttl=%d;stale=%s;cap=%s;fee_bps=%d", policyID, ttl.Nanoseconds(), stale, costCap, feeBps)
	return "sha256:" + sum(canon)
}

func settlementEntryIDs(settlement *economic.SettlementReceipt) []string {
	if settlement == nil {
		return nil
	}
	ids := make([]string, 0, len(settlement.LedgerEntries))
	for _, entry := range settlement.LedgerEntries {
		ids = append(ids, entry.ID)
	}
	return ids
}

func shortHash(parts ...string) string {
	return sum(strings.Join(parts, "\x00"))[:24]
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
