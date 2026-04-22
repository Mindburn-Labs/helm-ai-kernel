package regwatch

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// CSLTradeAdapter monitors US Consolidated Screening List via Trade.gov API.
type CSLTradeAdapter struct{ BaseAdapter }

func NewCSLTradeAdapter() *CSLTradeAdapter {
	return &CSLTradeAdapter{BaseAdapter: BaseAdapter{
		sourceType: SourceCSLTrade, jurisdiction: jkg.JurisdictionUS,
		regulator: jkg.RegulatorID("US-ITA"), feedURL: "https://api.trade.gov/gateway/v1/consolidated_screening_list", healthy: true,
	}}
}
func (a *CSLTradeAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}
func (a *CSLTradeAdapter) IsHealthy(ctx context.Context) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.healthy
}

// WorldBankDebarredAdapter monitors World Bank debarred firms list.
type WorldBankDebarredAdapter struct{ BaseAdapter }

func NewWorldBankDebarredAdapter() *WorldBankDebarredAdapter {
	return &WorldBankDebarredAdapter{BaseAdapter: BaseAdapter{
		sourceType: SourceWorldBank, jurisdiction: jkg.JurisdictionGlobal,
		regulator: jkg.RegulatorID("WB-SANCTIONS"), feedURL: "https://www.worldbank.org/en/projects-operations/procurement/debarred-firms", healthy: true,
	}}
}
func (a *WorldBankDebarredAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}
func (a *WorldBankDebarredAdapter) IsHealthy(ctx context.Context) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.healthy
}
