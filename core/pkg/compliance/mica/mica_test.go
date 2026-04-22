package mica

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewMiCAComplianceEngine(t *testing.T) {
	issuer := IssuerInfo{
		LEI:          "529900EXAMPLE123456",
		Name:         "Test Crypto Issuer",
		Jurisdiction: "DE",
		AuthStatus:   "authorized",
	}

	engine := NewMiCAComplianceEngine(issuer)
	require.NotNil(t, engine)
}

func TestRecordAuditEvent(t *testing.T) {
	engine := NewMiCAComplianceEngine(IssuerInfo{Name: "Test"})

	event := &AuditEvent{
		EventType: "token_transfer",
		ActorID:   "user-123",
		ActorType: "operator",
		Action:    "transfer",
		Resource:  "token:ABC",
		Outcome:   "success",
		Details:   map[string]any{"amount": 100},
	}

	err := engine.RecordAuditEvent(context.Background(), event)
	require.NoError(t, err)
	require.NotEmpty(t, event.ID)
	require.NotEmpty(t, event.Hash)
	require.False(t, event.Timestamp.IsZero())
}

func TestAuditTrailChaining(t *testing.T) {
	engine := NewMiCAComplianceEngine(IssuerInfo{Name: "Test"})
	ctx := context.Background()

	// Create chain of events
	for i := 0; i < 5; i++ {
		event := &AuditEvent{
			EventType: "test_event",
			Action:    "action",
		}
		err := engine.RecordAuditEvent(ctx, event)
		require.NoError(t, err)
	}

	trail := engine.GetAuditTrail(ctx)
	require.Len(t, trail, 5)

	// Verify chain
	for i := 1; i < len(trail); i++ {
		require.Equal(t, trail[i-1].Hash, trail[i].PrevHash)
	}
}

func TestAuditTrailIntegrity(t *testing.T) {
	engine := NewMiCAComplianceEngine(IssuerInfo{Name: "Test"})
	ctx := context.Background()

	// Add events
	for i := 0; i < 3; i++ {
		_ = engine.RecordAuditEvent(ctx, &AuditEvent{
			EventType: "test",
			Action:    "test",
		})
	}

	// Verify integrity
	valid, idx := engine.VerifyAuditTrailIntegrity(ctx)
	require.True(t, valid)
	require.Equal(t, -1, idx)
}

func TestAuditTrailForPeriod(t *testing.T) {
	engine := NewMiCAComplianceEngine(IssuerInfo{Name: "Test"})
	ctx := context.Background()

	now := time.Now()
	start := now.Add(-1 * time.Hour)
	end := now.Add(1 * time.Hour)

	// Add event
	_ = engine.RecordAuditEvent(ctx, &AuditEvent{
		EventType: "test",
		Timestamp: now,
	})

	trail := engine.GetAuditTrailForPeriod(ctx, start, end)
	require.Len(t, trail, 1)
}

func TestRegisterWhitepaper(t *testing.T) {
	issuer := IssuerInfo{
		LEI:  "529900EXAMPLE123456",
		Name: "Test Issuer",
	}
	engine := NewMiCAComplianceEngine(issuer)
	ctx := context.Background()

	wp := &CryptoAssetWhitepaper{
		AssetName:   "Test Token",
		AssetSymbol: "TST",
		Category:    AssetCategoryART,
		Description: "A test asset-referenced token",
		Technology: TechnologyInfo{
			BlockchainType: "public",
			ConsensusMech:  "proof_of_stake",
		},
		Risks:  []string{"market_risk", "liquidity_risk"},
		Rights: []string{"redemption", "dividend"},
		ReserveAssets: &ReserveInfo{
			TotalValue: 1000000,
			Currency:   "EUR",
			Composition: []ReserveAsset{
				{Type: "government_bond", Percentage: 80},
				{Type: "cash", Percentage: 20},
			},
		},
	}

	err := engine.RegisterWhitepaper(ctx, wp)
	require.NoError(t, err)
	require.NotEmpty(t, wp.Hash)
	require.Equal(t, issuer.LEI, wp.Issuer.LEI)
}

func TestGetWhitepaper(t *testing.T) {
	engine := NewMiCAComplianceEngine(IssuerInfo{Name: "Test"})
	ctx := context.Background()

	wp := &CryptoAssetWhitepaper{
		AssetName:   "Test Token",
		AssetSymbol: "TST",
		Category:    AssetCategoryCryptoAsset,
	}
	_ = engine.RegisterWhitepaper(ctx, wp)

	retrieved, err := engine.GetWhitepaper(ctx, "TST")
	require.NoError(t, err)
	require.Equal(t, "Test Token", retrieved.AssetName)
}

func TestGetWhitepaperNotFound(t *testing.T) {
	engine := NewMiCAComplianceEngine(IssuerInfo{Name: "Test"})

	_, err := engine.GetWhitepaper(context.Background(), "NONEXISTENT")
	require.Error(t, err)
}

func TestExportWhitepaperJSON(t *testing.T) {
	engine := NewMiCAComplianceEngine(IssuerInfo{Name: "Test"})
	ctx := context.Background()

	wp := &CryptoAssetWhitepaper{
		AssetName:   "Test Token",
		AssetSymbol: "TST",
		Category:    AssetCategoryEMT,
	}
	_ = engine.RegisterWhitepaper(ctx, wp)

	jsonData, err := engine.ExportWhitepaperJSON(ctx, "TST")
	require.NoError(t, err)
	require.Contains(t, string(jsonData), "Test Token")
	require.Contains(t, string(jsonData), "EMT")
}

func TestExportAuditTrailJSON(t *testing.T) {
	engine := NewMiCAComplianceEngine(IssuerInfo{Name: "Test"})
	ctx := context.Background()

	_ = engine.RecordAuditEvent(ctx, &AuditEvent{
		EventType: "test_event",
		Action:    "test_action",
	})

	jsonData, err := engine.ExportAuditTrailJSON(ctx)
	require.NoError(t, err)
	require.Contains(t, string(jsonData), "test_event")
}

func TestRegulatoryFeedClient(t *testing.T) {
	client := NewRegulatoryFeedClient("test-api-key")
	require.NotNil(t, client)

	updates, err := client.FetchMiCAUpdates(context.Background())
	require.Error(t, err)
	require.Nil(t, updates)
	require.Contains(t, err.Error(), "integration missing")
}

func TestAssetCategories(t *testing.T) {
	require.Equal(t, AssetCategory("ART"), AssetCategoryART)
	require.Equal(t, AssetCategory("EMT"), AssetCategoryEMT)
	require.Equal(t, AssetCategory("CRYPTO_ASSET"), AssetCategoryCryptoAsset)
	require.Equal(t, AssetCategory("UTILITY_TOKEN"), AssetCategoryUtilityToken)
}
