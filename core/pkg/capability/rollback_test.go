package capability

import (
	"testing"
	"time"
)

func TestRollbackPlan_Expired(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	p := RollbackPlan{GuaranteeExpiry: &past}
	if !p.Expired(time.Now()) {
		t.Fatal("past guarantee_expiry must be expired")
	}
	p.GuaranteeExpiry = &future
	if p.Expired(time.Now()) {
		t.Fatal("future guarantee_expiry must not be expired")
	}
}
