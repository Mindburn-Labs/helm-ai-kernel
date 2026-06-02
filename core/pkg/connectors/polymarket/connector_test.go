package polymarket

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/effects"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph"
)

func TestNewConnectorDefaultsAndAccessors(t *testing.T) {
	c := NewConnector(Config{})

	if c.ID() != ConnectorID {
		t.Fatalf("ID() = %q, want %q", c.ID(), ConnectorID)
	}
	if c.Graph() == nil || c.Graph().Len() != 0 {
		t.Fatalf("Graph() = %#v, want empty graph", c.Graph())
	}

	p0 := c.P0()
	if p0.AllowLive || !p0.RequireEligibleGeo || p0.MaxSingleOrderUSD != 2.0 {
		t.Fatalf("P0() = %#v, want conservative defaults", p0)
	}
	if len(p0.AllowedModes) != 1 || p0.AllowedModes[0] != "LIVE_TEST" {
		t.Fatalf("AllowedModes = %#v, want LIVE_TEST", p0.AllowedModes)
	}

	classes := AllowedDataClasses()
	if len(classes) != 3 || classes[0] != "trading:prediction_market" || classes[1] != "trading:order" || classes[2] != "trading:position" {
		t.Fatalf("AllowedDataClasses() = %#v", classes)
	}
	if nowMs() <= 0 {
		t.Fatal("nowMs() returned a non-positive timestamp")
	}

	customP0 := allowingP0()
	customP0.AllowedMarketIDs = []string{"token-1"}
	custom := NewConnector(Config{ConnectorID: "custom-polymarket", P0: &customP0})
	if custom.ID() != "custom-polymarket" {
		t.Fatalf("custom ID() = %q", custom.ID())
	}
	if custom.P0().AllowedMarketIDs[0] != "token-1" {
		t.Fatalf("custom P0() = %#v", custom.P0())
	}
}

func TestParseOrderIntentVariantsAndRequiredFields(t *testing.T) {
	params := validOrderParams("intent-float")
	params["expiration_ts"] = float64(1234)

	intent, err := parseOrderIntent(params)
	if err != nil {
		t.Fatalf("parseOrderIntent() unexpected error: %v", err)
	}
	if intent.IntentID != "intent-float" || intent.PostOnly != true || intent.NegRisk != false || intent.ExpirationTs != 1234 {
		t.Fatalf("parsed intent = %#v", intent)
	}

	params = validOrderParams("intent-int")
	params["expiration_ts"] = int64(5678)
	params["post_only"] = "not-a-bool"
	params["neg_risk"] = "not-a-bool"

	intent, err = parseOrderIntent(params)
	if err != nil {
		t.Fatalf("parseOrderIntent() with int expiration unexpected error: %v", err)
	}
	if intent.PostOnly || intent.NegRisk || intent.ExpirationTs != 5678 {
		t.Fatalf("parsed bool/int variants = %#v", intent)
	}

	if got := stringParam(map[string]any{"not_string": 12}, "not_string"); got != "" {
		t.Fatalf("stringParam() = %q, want empty string for non-string input", got)
	}

	for _, field := range []string{"intent_id", "token_id", "side", "size", "price", "mode"} {
		t.Run(field, func(t *testing.T) {
			params := validOrderParams("intent-missing-" + field)
			delete(params, field)

			_, err := parseOrderIntent(params)
			if err == nil || !strings.Contains(err.Error(), "missing required param "+field) {
				t.Fatalf("parseOrderIntent() error = %v, want missing %s", err, field)
			}
		})
	}
}

func TestValidateIntentDenialsAndAllowances(t *testing.T) {
	tests := []struct {
		name   string
		intent PolymarketOrderIntent
		p0     PolymarketP0
		reason ReasonCode
	}{
		{
			name:   "live disallowed",
			intent: baseIntent(),
			p0:     PolymarketP0{AllowLive: false, AllowedModes: []string{"LIVE_TEST"}, MaxSingleOrderUSD: 10},
			reason: ReasonLiveNotAllowed,
		},
		{
			name:   "mode disallowed",
			intent: withIntentMode(baseIntent(), "PAPER"),
			p0:     allowingP0(),
			reason: ReasonModeNotAllowed,
		},
		{
			name:   "venue unhealthy",
			intent: withIntentVenue(baseIntent(), "HALTED"),
			p0:     allowingP0(),
			reason: ReasonVenueUnhealthy,
		},
		{
			name:   "over single order notional",
			intent: withIntentSize(baseIntent(), "11"),
			p0:     allowingP0(),
			reason: ReasonOverNotional,
		},
		{
			name:   "market not allowed",
			intent: baseIntent(),
			p0:     withAllowedMarkets(allowingP0(), []string{"other-token"}),
			reason: ReasonMarketNotAllowed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deny := ValidateIntent(tt.intent, tt.p0)
			if deny == nil {
				t.Fatalf("ValidateIntent() returned nil, want %s", tt.reason)
			}
			if deny.Reason != tt.reason || !deny.Denied || deny.Detail == "" {
				t.Fatalf("ValidateIntent() = %#v, want reason %s with detail", deny, tt.reason)
			}
		})
	}

	if deny := ValidateIntent(baseIntent(), withAllowedMarkets(allowingP0(), []string{"token-1"})); deny != nil {
		t.Fatalf("ValidateIntent() with allowed market = %#v, want nil", deny)
	}

	unparseableSize := withIntentSize(baseIntent(), "not-a-number")
	if deny := ValidateIntent(unparseableSize, allowingP0()); deny != nil {
		t.Fatalf("ValidateIntent() with unparseable size = %#v, want nil", deny)
	}

	noModeAllowlist := allowingP0()
	noModeAllowlist.AllowedModes = nil
	nonLiveMode := withIntentMode(baseIntent(), "PAPER")
	if deny := ValidateIntent(nonLiveMode, noModeAllowlist); deny != nil {
		t.Fatalf("ValidateIntent() without allowed modes = %#v, want nil", deny)
	}
}

func TestExecuteRejectsPermitToolHashAndParseErrors(t *testing.T) {
	ctx := context.Background()
	p0 := allowingP0()
	c := NewConnector(Config{P0: &p0})

	_, err := c.Execute(ctx, &effects.EffectPermit{PermitID: "permit-1", ConnectorID: "other"}, ToolPlaceOrder, validOrderParams("intent-1"))
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("permit mismatch error = %v", err)
	}

	_, err = c.Execute(ctx, permitFor(c), "polymarket.unknown", validOrderParams("intent-2"))
	if err == nil || !strings.Contains(err.Error(), "unknown tool") {
		t.Fatalf("unknown tool error = %v", err)
	}

	restore := replacePolymarketHooks(t)
	canonicalHash = func(interface{}) (string, error) {
		return "", errors.New("hash failed")
	}
	_, err = c.Execute(ctx, permitFor(c), ToolPlaceOrder, validOrderParams("intent-3"))
	if err == nil || !strings.Contains(err.Error(), "canonical hash of params") {
		t.Fatalf("canonical hash error = %v", err)
	}
	restore()

	params := validOrderParams("intent-4")
	delete(params, "intent_id")
	_, err = c.Execute(ctx, permitFor(c), ToolPlaceOrder, params)
	if err == nil || !strings.Contains(err.Error(), "parse intent") {
		t.Fatalf("parse error = %v", err)
	}
}

func TestExecuteDeniedAndAllowed(t *testing.T) {
	ctx := context.Background()

	denied := NewConnector(Config{})
	_, err := denied.Execute(ctx, permitFor(denied), ToolPlaceOrder, validOrderParams("denied-intent"))
	if err == nil || !strings.Contains(err.Error(), string(ReasonLiveNotAllowed)) {
		t.Fatalf("denied Execute() error = %v", err)
	}
	if denied.Graph().Len() != 1 {
		t.Fatalf("denied Graph().Len() = %d, want 1", denied.Graph().Len())
	}

	p0 := allowingP0()
	allowed := NewConnector(Config{P0: &p0})
	out, err := allowed.Execute(ctx, permitFor(allowed), ToolCancelAll, validOrderParams("allowed-intent"))
	if err != nil {
		t.Fatalf("allowed Execute() error = %v", err)
	}
	got, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("Execute() returned %T, want map[string]any", out)
	}
	if got["status"] != "policy_approved" || got["intent_id"] != "allowed-intent" || got["mode"] != "LIVE_TEST" || got["input_hash"] == "" {
		t.Fatalf("Execute() output = %#v", got)
	}
	if allowed.Graph().Len() != 1 {
		t.Fatalf("allowed Graph().Len() = %d, want 1", allowed.Graph().Len())
	}
}

func TestExecuteGateDeniesRateLimit(t *testing.T) {
	ctx := context.Background()
	p0 := allowingP0()
	c := NewConnector(Config{P0: &p0})

	for i := 0; i < 30; i++ {
		_, err := c.Execute(ctx, permitFor(c), ToolPlaceOrder, validOrderParams(fmt.Sprintf("intent-%02d", i)))
		if err != nil {
			t.Fatalf("Execute() call %d error = %v", i, err)
		}
	}

	_, err := c.Execute(ctx, permitFor(c), ToolPlaceOrder, validOrderParams("intent-rate-limited"))
	if err == nil || !strings.Contains(err.Error(), "gate denied") {
		t.Fatalf("rate-limit Execute() error = %v", err)
	}
}

func TestExecuteInjectedDependencyErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("denied append error", func(t *testing.T) {
		restore := replacePolymarketHooks(t)
		appendNode = func(*proofgraph.Graph, proofgraph.NodeType, []byte, string, uint64) (*proofgraph.Node, error) {
			return nil, errors.New("append denied failed")
		}
		defer restore()

		c := NewConnector(Config{})
		_, err := c.Execute(ctx, permitFor(c), ToolPlaceOrder, validOrderParams("denied-append"))
		if err == nil || !strings.Contains(err.Error(), "append denied intent") {
			t.Fatalf("denied append error = %v", err)
		}
	})

	t.Run("allowed marshal error", func(t *testing.T) {
		restore := replacePolymarketHooks(t)
		marshalJSON = func(any) ([]byte, error) {
			return nil, errors.New("marshal failed")
		}
		defer restore()

		p0 := allowingP0()
		c := NewConnector(Config{P0: &p0})
		_, err := c.Execute(ctx, permitFor(c), ToolPlaceOrder, validOrderParams("marshal-error"))
		if err == nil || !strings.Contains(err.Error(), "marshal intent payload") {
			t.Fatalf("marshal error = %v", err)
		}
	})

	t.Run("allowed append error", func(t *testing.T) {
		restore := replacePolymarketHooks(t)
		appendNode = func(*proofgraph.Graph, proofgraph.NodeType, []byte, string, uint64) (*proofgraph.Node, error) {
			return nil, errors.New("append allowed failed")
		}
		defer restore()

		p0 := allowingP0()
		c := NewConnector(Config{P0: &p0})
		_, err := c.Execute(ctx, permitFor(c), ToolPlaceOrder, validOrderParams("allowed-append"))
		if err == nil || !strings.Contains(err.Error(), "append intent") {
			t.Fatalf("allowed append error = %v", err)
		}
	})
}

func replacePolymarketHooks(t *testing.T) func() {
	t.Helper()

	oldCanonicalHash := canonicalHash
	oldMarshalJSON := marshalJSON
	oldAppendNode := appendNode
	restored := false

	restore := func() {
		if restored {
			return
		}
		canonicalHash = oldCanonicalHash
		marshalJSON = oldMarshalJSON
		appendNode = oldAppendNode
		restored = true
	}
	t.Cleanup(restore)
	return restore
}

func validOrderParams(intentID string) map[string]any {
	return map[string]any{
		"intent_id":     intentID,
		"account_id":    "account-1",
		"token_id":      "token-1",
		"side":          "BUY",
		"price":         "0.42",
		"size":          "1.00",
		"order_type":    "GTC",
		"post_only":     true,
		"expiration_ts": int64(1_700_000_000),
		"neg_risk":      false,
		"venue_state":   "LIVE_ALLOWED",
		"policy_hash":   "policy-hash",
		"plan_hash":     "plan-hash",
		"mode":          "LIVE_TEST",
	}
}

func permitFor(c *Connector) *effects.EffectPermit {
	return &effects.EffectPermit{
		PermitID:    "permit-1",
		ConnectorID: c.ID(),
	}
}

func allowingP0() PolymarketP0 {
	return PolymarketP0{
		AllowLive:         true,
		MaxNotionalUSD:    100,
		MaxSingleOrderUSD: 10,
		MaxOpenOrders:     10,
		MaxDailyLossUSD:   10,
		MaxOpenPositions:  10,
		AllowedModes:      []string{"LIVE_TEST"},
	}
}

func baseIntent() PolymarketOrderIntent {
	return PolymarketOrderIntent{
		IntentID:   "intent-1",
		AccountID:  "account-1",
		TokenID:    "token-1",
		Side:       "BUY",
		Price:      "0.42",
		Size:       "1",
		OrderType:  "GTC",
		VenueState: "LIVE_ALLOWED",
		PolicyHash: "policy-hash",
		PlanHash:   "plan-hash",
		Mode:       "LIVE_TEST",
	}
}

func withIntentMode(intent PolymarketOrderIntent, mode string) PolymarketOrderIntent {
	intent.Mode = mode
	return intent
}

func withIntentVenue(intent PolymarketOrderIntent, venue string) PolymarketOrderIntent {
	intent.VenueState = venue
	return intent
}

func withIntentSize(intent PolymarketOrderIntent, size string) PolymarketOrderIntent {
	intent.Size = size
	return intent
}

func withAllowedMarkets(p0 PolymarketP0, ids []string) PolymarketP0 {
	p0.AllowedMarketIDs = ids
	return p0
}
