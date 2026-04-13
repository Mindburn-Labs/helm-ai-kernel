package polymarket

import (
	"fmt"
	"strconv"
)

// ValidateIntent checks an order intent against P0 ceilings.
// Returns nil if the intent is allowed, or a DenyResult if denied.
func ValidateIntent(intent PolymarketOrderIntent, p0 PolymarketP0) *DenyResult {
	// 1. Live trading allowed?
	isLive := intent.Mode == "LIVE_TEST" || intent.Mode == "LIVE_ACTIVE"
	if isLive && !p0.AllowLive {
		return &DenyResult{Denied: true, Reason: ReasonLiveNotAllowed, Detail: "P0 AllowLive is false"}
	}

	// 2. Mode in allowed list?
	if len(p0.AllowedModes) > 0 {
		allowed := false
		for _, m := range p0.AllowedModes {
			if m == intent.Mode {
				allowed = true
				break
			}
		}
		if !allowed {
			return &DenyResult{Denied: true, Reason: ReasonModeNotAllowed, Detail: fmt.Sprintf("mode %s not in allowed modes %v", intent.Mode, p0.AllowedModes)}
		}
	}

	// 3. Venue state healthy?
	if intent.VenueState != "LIVE_ALLOWED" {
		return &DenyResult{Denied: true, Reason: ReasonVenueUnhealthy, Detail: fmt.Sprintf("venue state is %s, not LIVE_ALLOWED", intent.VenueState)}
	}

	// 4. Single order size?
	size, err := strconv.ParseFloat(intent.Size, 64)
	if err == nil && size > p0.MaxSingleOrderUSD {
		return &DenyResult{Denied: true, Reason: ReasonOverNotional, Detail: fmt.Sprintf("order size $%.2f exceeds P0 max $%.2f", size, p0.MaxSingleOrderUSD)}
	}

	// 5. Market allowed? (if allowlist is set)
	if len(p0.AllowedMarketIDs) > 0 {
		found := false
		for _, id := range p0.AllowedMarketIDs {
			if id == intent.TokenID {
				found = true
				break
			}
		}
		if !found {
			return &DenyResult{Denied: true, Reason: ReasonMarketNotAllowed, Detail: fmt.Sprintf("token %s not in allowed markets", intent.TokenID)}
		}
	}

	return nil // All checks passed
}
