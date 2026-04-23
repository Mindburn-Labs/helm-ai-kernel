package mica

import (
	"context"
	"testing"
	"time"
)

func testIssuer() IssuerInfo {
	return IssuerInfo{
		LEI: "529900TEST", Name: "TestIssuer", Jurisdiction: "EU",
		AuthStatus: "authorized",
	}
}

func TestMiCAEngine_Init(t *testing.T) {
	engine := NewMiCAComplianceEngine(testIssuer())
	if engine == nil {
		t.Fatal("engine should not be nil")
	}
	trail := engine.GetAuditTrail(context.Background())
	if len(trail) != 0 {
		t.Error("new engine should have empty audit trail")
	}
}

func TestRecordAuditEvent_AutoID(t *testing.T) {
	engine := NewMiCAComplianceEngine(testIssuer())
	ev := &AuditEvent{EventType: "transfer", Action: "send"}
	engine.RecordAuditEvent(context.Background(), ev)
	if ev.ID == "" {
		t.Error("ID should be auto-generated")
	}
}

func TestRecordAuditEvent_AutoTimestamp(t *testing.T) {
	engine := NewMiCAComplianceEngine(testIssuer())
	ev := &AuditEvent{ID: "e1", EventType: "transfer"}
	engine.RecordAuditEvent(context.Background(), ev)
	if ev.Timestamp.IsZero() {
		t.Error("timestamp should be auto-set")
	}
}

func TestRecordAuditEvent_ChainsPrevHash(t *testing.T) {
	engine := NewMiCAComplianceEngine(testIssuer())
	ctx := context.Background()
	ev1 := &AuditEvent{ID: "e1", EventType: "transfer"}
	engine.RecordAuditEvent(ctx, ev1)
	ev2 := &AuditEvent{ID: "e2", EventType: "redemption"}
	engine.RecordAuditEvent(ctx, ev2)
	if ev2.PrevHash != ev1.Hash {
		t.Error("second event's PrevHash should equal first event's Hash")
	}
}

func TestRecordAuditEvent_ProducesHash(t *testing.T) {
	engine := NewMiCAComplianceEngine(testIssuer())
	ev := &AuditEvent{ID: "e1", EventType: "issuance"}
	engine.RecordAuditEvent(context.Background(), ev)
	if ev.Hash == "" {
		t.Error("event hash should not be empty")
	}
}

func TestVerifyAuditTrailIntegrity_ValidChain(t *testing.T) {
	engine := NewMiCAComplianceEngine(testIssuer())
	ctx := context.Background()
	engine.RecordAuditEvent(ctx, &AuditEvent{ID: "e1", EventType: "a"})
	engine.RecordAuditEvent(ctx, &AuditEvent{ID: "e2", EventType: "b"})
	engine.RecordAuditEvent(ctx, &AuditEvent{ID: "e3", EventType: "c"})
	valid, idx := engine.VerifyAuditTrailIntegrity(ctx)
	if !valid {
		t.Errorf("integrity check failed at index %d", idx)
	}
}

func TestGetAuditTrailForPeriod_FiltersCorrectly(t *testing.T) {
	engine := NewMiCAComplianceEngine(testIssuer())
	ctx := context.Background()
	now := time.Now()
	engine.RecordAuditEvent(ctx, &AuditEvent{ID: "e1", EventType: "a", Timestamp: now})
	engine.RecordAuditEvent(ctx, &AuditEvent{ID: "e2", EventType: "b", Timestamp: now.Add(-48 * time.Hour)})
	result := engine.GetAuditTrailForPeriod(ctx, now.Add(-time.Hour), now.Add(time.Hour))
	if len(result) != 1 {
		t.Errorf("expected 1 event in period, got %d", len(result))
	}
}

func TestRegisterWhitepaper_SetsHash(t *testing.T) {
	engine := NewMiCAComplianceEngine(testIssuer())
	wp := &CryptoAssetWhitepaper{
		AssetName: "TestCoin", AssetSymbol: "TST", Category: AssetCategoryART,
		Description: "A test token",
	}
	err := engine.RegisterWhitepaper(context.Background(), wp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wp.Hash == "" {
		t.Error("whitepaper hash should not be empty")
	}
}

func TestRegisterWhitepaper_SetsIssuer(t *testing.T) {
	issuer := testIssuer()
	engine := NewMiCAComplianceEngine(issuer)
	wp := &CryptoAssetWhitepaper{AssetName: "X", AssetSymbol: "X", Category: AssetCategoryEMT}
	engine.RegisterWhitepaper(context.Background(), wp)
	if wp.Issuer.LEI != issuer.LEI {
		t.Error("whitepaper issuer should match engine issuer")
	}
}

func TestGetWhitepaper_ReturnsRegistered(t *testing.T) {
	engine := NewMiCAComplianceEngine(testIssuer())
	ctx := context.Background()
	engine.RegisterWhitepaper(ctx, &CryptoAssetWhitepaper{
		AssetName: "Coin", AssetSymbol: "COIN", Category: AssetCategoryCryptoAsset,
	})
	wp, err := engine.GetWhitepaper(ctx, "COIN")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wp.AssetName != "Coin" {
		t.Error("wrong whitepaper returned")
	}
}

func TestGetWhitepaper_MissingReturnsError(t *testing.T) {
	engine := NewMiCAComplianceEngine(testIssuer())
	_, err := engine.GetWhitepaper(context.Background(), "MISSING")
	if err == nil {
		t.Error("expected error for missing whitepaper")
	}
}

func TestExportWhitepaperJSON_ReturnsData(t *testing.T) {
	engine := NewMiCAComplianceEngine(testIssuer())
	ctx := context.Background()
	engine.RegisterWhitepaper(ctx, &CryptoAssetWhitepaper{
		AssetName: "Coin", AssetSymbol: "COIN", Category: AssetCategoryCryptoAsset,
	})
	data, err := engine.ExportWhitepaperJSON(ctx, "COIN")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Error("exported JSON should not be empty")
	}
}

func TestExportAuditTrailJSON_ReturnsData(t *testing.T) {
	engine := NewMiCAComplianceEngine(testIssuer())
	ctx := context.Background()
	engine.RecordAuditEvent(ctx, &AuditEvent{ID: "e1", EventType: "x"})
	data, err := engine.ExportAuditTrailJSON(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) == 0 {
		t.Error("exported JSON should not be empty")
	}
}

func TestAssetCategory_AllFour(t *testing.T) {
	cats := []AssetCategory{AssetCategoryART, AssetCategoryEMT, AssetCategoryCryptoAsset, AssetCategoryUtilityToken}
	if len(cats) != 4 {
		t.Fatalf("expected 4 asset categories, got %d", len(cats))
	}
}

func TestRegulatoryFeedClient_FetchReturnsError(t *testing.T) {
	client := NewRegulatoryFeedClient("test-key")
	if client == nil {
		t.Fatal("client should not be nil")
	}
	_, err := client.FetchMiCAUpdates(context.Background())
	if err == nil {
		t.Error("FetchMiCAUpdates should return error (not yet implemented)")
	}
}
