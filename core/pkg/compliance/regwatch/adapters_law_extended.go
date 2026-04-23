package regwatch

import (
	"context"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/compliance/jkg"
)

// SGSSOAdapter monitors Singapore Statutes Online.
type SGSSOAdapter struct{ BaseAdapter }

func NewSGSSOAdapter() *SGSSOAdapter {
	return &SGSSOAdapter{BaseAdapter: BaseAdapter{
		sourceType: SourceSGSSO, jurisdiction: jkg.JurisdictionSG,
		regulator: jkg.RegulatorID("SG-AGC"), feedURL: "https://sso.agc.gov.sg/", healthy: true,
	}}
}
func (a *SGSSOAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}
func (a *SGSSOAdapter) IsHealthy(ctx context.Context) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.healthy
}

// CNNPCAdapter monitors China NPC Law Database.
type CNNPCAdapter struct{ BaseAdapter }

func NewCNNPCAdapter() *CNNPCAdapter {
	return &CNNPCAdapter{BaseAdapter: BaseAdapter{
		sourceType: SourceCNNPC, jurisdiction: jkg.JurisdictionCN,
		regulator: jkg.RegulatorID("CN-NPC"), feedURL: "https://flk.npc.gov.cn/", healthy: true,
	}}
}
func (a *CNNPCAdapter) FetchChanges(ctx context.Context, since time.Time) ([]*RegChange, error) {
	return []*RegChange{}, nil
}
func (a *CNNPCAdapter) IsHealthy(ctx context.Context) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.healthy
}
