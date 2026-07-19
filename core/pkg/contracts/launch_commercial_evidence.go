package contracts

import (
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"time"
)

const (
	LaunchCommercialEvidenceSchemaVersion = "launch_commercial_evidence.v1"
	LaunchFXSnapshotSchemaVersion         = "launch_fx_snapshot.v1"
	LaunchTaxSnapshotSchemaVersion        = "launch_tax_snapshot.v1"

	LaunchTaxProviderEstimate    = "PROVIDER_ESTIMATE"
	LaunchTaxConservativeMaximum = "CONSERVATIVE_MAXIMUM"
)

// LaunchCommercialEvidence is the source-owned cost calculation behind one
// route quote. Provider prices stay in their native currencies; exact FX and
// tax snapshots are resolved independently before HELM accepts the converted
// gross exposure. The artifact carries no dispatch authority.
type LaunchCommercialEvidence struct {
	SchemaVersion  string                              `json:"schema_version"`
	EvidenceID     string                              `json:"evidence_id"`
	TenantID       string                              `json:"tenant_id"`
	WorkspaceID    string                              `json:"workspace_id"`
	MissionID      string                              `json:"mission_id"`
	QuoteCurrency  string                              `json:"quote_currency"`
	PlacementCosts []LaunchCommercialPlacementEvidence `json:"placement_costs"`
	RetrievedAt    string                              `json:"retrieved_at"`
	ExpiresAt      string                              `json:"expires_at"`
}

type LaunchCommercialPlacementEvidence struct {
	PlacementID           string `json:"placement_id"`
	ProviderID            string `json:"provider_id"`
	ProviderAccountRef    string `json:"provider_account_ref"`
	ProviderAccountHash   string `json:"provider_account_hash"`
	RegionID              string `json:"region_id"`
	OfferingID            string `json:"offering_id"`
	BillingCadence        string `json:"billing_cadence"`
	CommitmentTerm        string `json:"commitment_term"`
	ProviderCurrency      string `json:"provider_currency"`
	ProviderBaseCostMinor int64  `json:"provider_base_cost_minor"`
	PriceEvidenceRef      string `json:"price_evidence_ref"`
	PriceEvidenceHash     string `json:"price_evidence_hash"`
	TermsEvidenceRef      string `json:"terms_evidence_ref"`
	TermsEvidenceHash     string `json:"terms_evidence_hash"`
	FXSnapshotRef         string `json:"fx_snapshot_ref"`
	FXSnapshotHash        string `json:"fx_snapshot_hash"`
	TaxSnapshotRef        string `json:"tax_snapshot_ref"`
	TaxSnapshotHash       string `json:"tax_snapshot_hash"`
	FXReserveBPS          int64  `json:"fx_reserve_bps"`
	BaseCostMinor         int64  `json:"base_cost_minor"`
	TaxReserveMinor       int64  `json:"tax_reserve_minor"`
	FXReserveMinor        int64  `json:"fx_reserve_minor"`
	TaxFXReserveMinor     int64  `json:"tax_fx_reserve_minor"`
	GrossExposureMinor    int64  `json:"gross_exposure_minor"`
}

// LaunchFXSnapshot expresses an exact rational conversion from provider minor
// units to quote minor units. A rational rate avoids floating-point or locale
// ambiguity and makes the conservative ceiling deterministic.
type LaunchFXSnapshot struct {
	SchemaVersion     string `json:"schema_version"`
	SnapshotID        string `json:"snapshot_id"`
	SourceCurrency    string `json:"source_currency"`
	QuoteCurrency     string `json:"quote_currency"`
	RateNumerator     int64  `json:"rate_numerator"`
	RateDenominator   int64  `json:"rate_denominator"`
	OfficialSourceURL string `json:"official_source_url"`
	ContentHash       string `json:"content_hash"`
	RetrievedAt       string `json:"retrieved_at"`
	ExpiresAt         string `json:"expires_at"`
}

// LaunchTaxSnapshot binds the exact provider account and jurisdiction used by
// a tax calculation. When the provider cannot estimate tax, the cost service
// must use CONSERVATIVE_MAXIMUM; UNKNOWN is never allowed to imply zero tax.
type LaunchTaxSnapshot struct {
	SchemaVersion       string `json:"schema_version"`
	SnapshotID          string `json:"snapshot_id"`
	TenantID            string `json:"tenant_id"`
	WorkspaceID         string `json:"workspace_id"`
	ProviderID          string `json:"provider_id"`
	ProviderAccountRef  string `json:"provider_account_ref"`
	ProviderAccountHash string `json:"provider_account_hash"`
	Jurisdiction        string `json:"jurisdiction"`
	Status              string `json:"status"`
	TaxRateBPS          int64  `json:"tax_rate_bps"`
	OfficialSourceURL   string `json:"official_source_url"`
	ContentHash         string `json:"content_hash"`
	RetrievedAt         string `json:"retrieved_at"`
	ExpiresAt           string `json:"expires_at"`
}

func DeriveLaunchCommercialEvidenceHash(value LaunchCommercialEvidence) (string, error) {
	return deriveLaunchCanonicalHash(value, "commercial evidence")
}

func DeriveLaunchFXSnapshotHash(value LaunchFXSnapshot) (string, error) {
	return deriveLaunchCanonicalHash(value, "FX snapshot")
}

func DeriveLaunchTaxSnapshotHash(value LaunchTaxSnapshot) (string, error) {
	return deriveLaunchCanonicalHash(value, "tax snapshot")
}

func DeriveLaunchFXSnapshotSetHash(costs []LaunchCommercialPlacementEvidence) (string, error) {
	projection := make([]struct {
		PlacementID  string `json:"placement_id"`
		SnapshotRef  string `json:"snapshot_ref"`
		SnapshotHash string `json:"snapshot_hash"`
	}, len(costs))
	for index, cost := range costs {
		projection[index].PlacementID = cost.PlacementID
		projection[index].SnapshotRef = cost.FXSnapshotRef
		projection[index].SnapshotHash = cost.FXSnapshotHash
	}
	return deriveLaunchCanonicalHash(projection, "FX snapshot set")
}

func DeriveLaunchTaxSnapshotSetHash(costs []LaunchCommercialPlacementEvidence) (string, error) {
	projection := make([]struct {
		PlacementID  string `json:"placement_id"`
		SnapshotRef  string `json:"snapshot_ref"`
		SnapshotHash string `json:"snapshot_hash"`
	}, len(costs))
	for index, cost := range costs {
		projection[index].PlacementID = cost.PlacementID
		projection[index].SnapshotRef = cost.TaxSnapshotRef
		projection[index].SnapshotHash = cost.TaxSnapshotHash
	}
	return deriveLaunchCanonicalHash(projection, "tax snapshot set")
}

func ValidateLaunchCommercialEvidence(value LaunchCommercialEvidence) error {
	if value.SchemaVersion != LaunchCommercialEvidenceSchemaVersion || value.EvidenceID == "" || value.TenantID == "" || value.WorkspaceID == "" || value.MissionID == "" || !launchCurrencyPattern.MatchString(value.QuoteCurrency) || len(value.PlacementCosts) == 0 {
		return errors.New("launch commercial evidence identity, currency, or placements are incomplete")
	}
	previous := ""
	for _, line := range value.PlacementCosts {
		if line.PlacementID == "" || line.PlacementID <= previous || line.ProviderID == "" || !launchProviderAccountRefPattern.MatchString(line.ProviderAccountRef) || line.RegionID == "" || line.OfferingID == "" || line.BillingCadence == "" || line.CommitmentTerm == "" || !launchCurrencyPattern.MatchString(line.ProviderCurrency) {
			return errors.New("launch commercial placement evidence must be complete, unique, and sorted")
		}
		previous = line.PlacementID
		if !validLaunchSHA256(line.ProviderAccountHash) || line.PriceEvidenceRef == "" || !validLaunchSHA256(line.PriceEvidenceHash) || line.TermsEvidenceRef == "" || !validLaunchSHA256(line.TermsEvidenceHash) || line.FXSnapshotRef == "" || !validLaunchSHA256(line.FXSnapshotHash) || line.TaxSnapshotRef == "" || !validLaunchSHA256(line.TaxSnapshotHash) {
			return fmt.Errorf("launch commercial placement %s evidence references are invalid", line.PlacementID)
		}
		if line.ProviderBaseCostMinor < 0 || line.FXReserveBPS < 0 || line.FXReserveBPS > 10_000 || line.BaseCostMinor < 0 || line.TaxReserveMinor < 0 || line.FXReserveMinor < 0 || line.TaxFXReserveMinor < 0 || line.GrossExposureMinor < 0 {
			return fmt.Errorf("launch commercial placement %s cost or reserve is invalid", line.PlacementID)
		}
		reserve, ok := addLaunchMinor(line.TaxReserveMinor, line.FXReserveMinor)
		if !ok || reserve != line.TaxFXReserveMinor {
			return fmt.Errorf("launch commercial placement %s aggregate reserve is inconsistent", line.PlacementID)
		}
		gross, ok := addLaunchMinor(line.BaseCostMinor, reserve)
		if !ok || gross != line.GrossExposureMinor {
			return fmt.Errorf("launch commercial placement %s gross exposure is inconsistent", line.PlacementID)
		}
	}
	return validateLaunchEvidenceWindow(value.RetrievedAt, value.ExpiresAt, "commercial evidence")
}

func ValidateLaunchFXSnapshot(value LaunchFXSnapshot) error {
	if value.SchemaVersion != LaunchFXSnapshotSchemaVersion || value.SnapshotID == "" || !launchCurrencyPattern.MatchString(value.SourceCurrency) || !launchCurrencyPattern.MatchString(value.QuoteCurrency) || value.RateNumerator <= 0 || value.RateDenominator <= 0 || !validLaunchSHA256(value.ContentHash) {
		return errors.New("launch FX snapshot identity, currencies, rate, or content hash is invalid")
	}
	if err := validateLaunchOfficialURL(value.OfficialSourceURL, "FX snapshot"); err != nil {
		return err
	}
	return validateLaunchEvidenceWindow(value.RetrievedAt, value.ExpiresAt, "FX snapshot")
}

func ValidateLaunchTaxSnapshot(value LaunchTaxSnapshot) error {
	if value.SchemaVersion != LaunchTaxSnapshotSchemaVersion || value.SnapshotID == "" || value.TenantID == "" || value.WorkspaceID == "" || value.ProviderID == "" || !launchProviderAccountRefPattern.MatchString(value.ProviderAccountRef) || !validLaunchSHA256(value.ProviderAccountHash) || value.Jurisdiction == "" || value.TaxRateBPS < 0 || value.TaxRateBPS > 100_000 || !validLaunchSHA256(value.ContentHash) {
		return errors.New("launch tax snapshot identity, account, jurisdiction, rate, or content hash is invalid")
	}
	switch value.Status {
	case LaunchTaxProviderEstimate, LaunchTaxConservativeMaximum:
	default:
		return errors.New("launch tax snapshot status is invalid")
	}
	if err := validateLaunchOfficialURL(value.OfficialSourceURL, "tax snapshot"); err != nil {
		return err
	}
	return validateLaunchEvidenceWindow(value.RetrievedAt, value.ExpiresAt, "tax snapshot")
}

// launchCeilMulDiv returns ceil(value*numerator/denominator) without int64
// overflow. Inputs are validated as non-negative before this helper is used.
func launchCeilMulDiv(value, numerator, denominator int64) (int64, bool) {
	if value < 0 || numerator < 0 || denominator <= 0 {
		return 0, false
	}
	product := new(big.Int).Mul(big.NewInt(value), big.NewInt(numerator))
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(product, big.NewInt(denominator), remainder)
	if remainder.Sign() > 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	if !quotient.IsInt64() {
		return 0, false
	}
	return quotient.Int64(), true
}

func validateLaunchOfficialURL(rawURL, label string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("launch %s official source must be a credential-free HTTPS URL", label)
	}
	return nil
}

func validateLaunchEvidenceWindow(retrievedRaw, expiresRaw, label string) error {
	retrievedAt, err := time.Parse(time.RFC3339Nano, retrievedRaw)
	if err != nil {
		return fmt.Errorf("launch %s retrieval time is invalid", label)
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, expiresRaw)
	if err != nil || !retrievedAt.Before(expiresAt) {
		return fmt.Errorf("launch %s expiry is invalid", label)
	}
	return nil
}
