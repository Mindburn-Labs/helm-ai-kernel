package contracts

import (
	"errors"
	"fmt"
	"net/url"
	"time"
)

const LaunchOfferSnapshotSchemaVersion = "launch_offer_snapshot.v1"

// LaunchOfferSnapshot separates official offer/credit evidence from a route
// quote. Only ACTIVE_CREDIT_VERIFIED may carry a non-zero balance, and that
// status requires an exact connected provider account. Advisory eligibility
// never reduces expected cash and never increases the gross authorization cap.
type LaunchOfferSnapshot struct {
	SchemaVersion       string   `json:"schema_version"`
	SnapshotID          string   `json:"snapshot_id"`
	TenantID            string   `json:"tenant_id"`
	WorkspaceID         string   `json:"workspace_id"`
	ProviderID          string   `json:"provider_id"`
	ProviderAccountRef  string   `json:"provider_account_ref,omitempty"`
	ProviderAccountHash string   `json:"provider_account_hash,omitempty"`
	OfficialSourceURL   string   `json:"official_source_url"`
	ContentVersionHash  string   `json:"content_version_hash"`
	TermsHash           string   `json:"terms_hash"`
	ExclusionsHash      string   `json:"exclusions_hash"`
	Status              string   `json:"status"`
	Currency            string   `json:"currency"`
	VerifiedCreditMinor int64    `json:"verified_credit_minor"`
	EvidenceRefs        []string `json:"evidence_refs"`
	RetrievedAt         string   `json:"retrieved_at"`
	ExpiresAt           string   `json:"expires_at"`
}

func DeriveLaunchOfferSnapshotHash(value LaunchOfferSnapshot) (string, error) {
	return deriveLaunchCanonicalHash(value, "offer snapshot")
}

func ValidateLaunchOfferSnapshot(value LaunchOfferSnapshot) error {
	if value.SchemaVersion != LaunchOfferSnapshotSchemaVersion || value.SnapshotID == "" || value.TenantID == "" || value.WorkspaceID == "" || value.ProviderID == "" {
		return errors.New("launch offer snapshot identity is incomplete")
	}
	if !launchCurrencyPattern.MatchString(value.Currency) || value.VerifiedCreditMinor < 0 {
		return errors.New("launch offer snapshot currency or credit value is invalid")
	}
	for field, hash := range map[string]string{
		"content_version_hash": value.ContentVersionHash,
		"terms_hash":           value.TermsHash,
		"exclusions_hash":      value.ExclusionsHash,
	} {
		if !validLaunchSHA256(hash) {
			return fmt.Errorf("launch offer snapshot %s is invalid", field)
		}
	}
	officialURL, err := url.Parse(value.OfficialSourceURL)
	if err != nil || officialURL.Scheme != "https" || officialURL.Host == "" || officialURL.User != nil || officialURL.RawQuery != "" || officialURL.Fragment != "" {
		return errors.New("launch offer snapshot official source must be a credential-free HTTPS URL")
	}
	if err := validateSortedUniqueNonEmpty(value.EvidenceRefs, "launch offer evidence references"); err != nil {
		return err
	}
	accountBound := value.ProviderAccountRef != "" || value.ProviderAccountHash != ""
	if accountBound && (value.ProviderAccountRef == "" || !validLaunchSHA256(value.ProviderAccountHash)) {
		return errors.New("launch offer snapshot provider account binding is incomplete")
	}
	switch value.Status {
	case LaunchCreditVerified:
		if !accountBound || value.VerifiedCreditMinor <= 0 {
			return errors.New("verified active credit requires an exact provider account and positive balance")
		}
	case LaunchCreditAdvisory, LaunchCreditNone, LaunchCreditUnknown:
		if value.VerifiedCreditMinor != 0 {
			return errors.New("unverified offer status cannot carry verified credit")
		}
	default:
		return errors.New("launch offer snapshot status is invalid")
	}
	retrievedAt, err := time.Parse(time.RFC3339Nano, value.RetrievedAt)
	if err != nil {
		return errors.New("launch offer snapshot retrieval time is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, value.ExpiresAt)
	if err != nil || !retrievedAt.Before(expiresAt) {
		return errors.New("launch offer snapshot expiry is invalid")
	}
	return nil
}
