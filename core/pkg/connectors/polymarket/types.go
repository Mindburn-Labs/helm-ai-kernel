package polymarket

import "time"

// VenueEligibility represents the geo-eligibility status of the execution origin.
type VenueEligibility struct {
	Blocked   bool   `json:"blocked"`
	Country   string `json:"country"`
	Region    string `json:"region"`
	CheckedAt int64  `json:"checked_at"`
}

// PolymarketOrderIntent represents a signed order intent from Brain.
type PolymarketOrderIntent struct {
	IntentID     string `json:"intent_id"`
	AccountID    string `json:"account_id"`
	TokenID      string `json:"token_id"`
	Side         string `json:"side"`
	Price        string `json:"price"`
	Size         string `json:"size"`
	OrderType    string `json:"order_type"`
	PostOnly     bool   `json:"post_only"`
	ExpirationTs int64  `json:"expiration_ts"`
	NegRisk      bool   `json:"neg_risk"`
	VenueState   string `json:"venue_state"`
	PolicyHash   string `json:"policy_hash"`
	PlanHash     string `json:"plan_hash,omitempty"`
	Mode         string `json:"mode"`
}

// PolymarketP0 defines the P0 (baseline) policy ceilings for Polymarket.
type PolymarketP0 struct {
	AllowLive          bool     `json:"allow_live"`
	RequireEligibleGeo bool     `json:"require_eligible_geo"`
	MaxNotionalUSD     float64  `json:"max_notional_usd"`
	MaxSingleOrderUSD  float64  `json:"max_single_order_usd"`
	MaxOpenOrders      int      `json:"max_open_orders"`
	MaxDailyLossUSD    float64  `json:"max_daily_loss_usd"`
	MaxOpenPositions   int      `json:"max_open_positions"`
	AllowedMarketIDs   []string `json:"allowed_market_ids,omitempty"`
	AllowedTags        []string `json:"allowed_tags,omitempty"`
	AllowedModes       []string `json:"allowed_modes"`
}

// DefaultP0 returns conservative P0 defaults matching the micro-capital posture.
func DefaultP0() PolymarketP0 {
	return PolymarketP0{
		AllowLive:          false,
		RequireEligibleGeo: true,
		MaxNotionalUSD:     10.0,
		MaxSingleOrderUSD:  2.0,
		MaxOpenOrders:      2,
		MaxDailyLossUSD:    3.0,
		MaxOpenPositions:   2,
		AllowedModes:       []string{"LIVE_TEST"},
	}
}

// ReasonCode enumerates all denial reasons for the Polymarket connector.
type ReasonCode string

const (
	ReasonGeoBlocked       ReasonCode = "GEO_BLOCKED"
	ReasonModeNotAllowed   ReasonCode = "MODE_NOT_ALLOWED"
	ReasonOverNotional     ReasonCode = "OVER_NOTIONAL"
	ReasonOverOrderCount   ReasonCode = "OVER_ORDER_COUNT"
	ReasonOverDailyLoss    ReasonCode = "OVER_DAILY_LOSS"
	ReasonMarketNotAllowed ReasonCode = "MARKET_NOT_ALLOWED"
	ReasonOperatorNotArmed ReasonCode = "OPERATOR_NOT_ARMED"
	ReasonVenueUnhealthy   ReasonCode = "VENUE_UNHEALTHY"
	ReasonLiveNotAllowed   ReasonCode = "LIVE_NOT_ALLOWED"
)

// DenyResult is returned when a P0 check fails.
type DenyResult struct {
	Denied bool       `json:"denied"`
	Reason ReasonCode `json:"reason"`
	Detail string     `json:"detail"`
}

// Timestamp helper.
func nowMs() int64 {
	return time.Now().UnixMilli()
}
