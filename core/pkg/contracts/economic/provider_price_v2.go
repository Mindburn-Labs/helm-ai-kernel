package economic

import (
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"time"
)

// quantum_posture: versioned classical SHA-256 price commitments; no signatures
// or provider billing authority are created by a price snapshot.

// ProviderPriceSchemaV2 represents a tariff in integer nano-cents per token.
// For example USD 0.042 per million tokens is exactly 4,200 nano-cents/token.
// The unversioned legacy representation and its digest remain unchanged.
const ProviderPriceSchemaV2 = "helm.provider-price-snapshot.v2"

const nanoCentsPerCent int64 = 1_000_000_000

func (s *ProviderPriceSnapshot) validatePriceRepresentation() error {
	if s.SchemaVersion == "" {
		if s.InputTokenNanoCents != 0 || s.OutputTokenNanoCents != 0 || s.RequestNanoCents != 0 {
			return errors.New("provider_price_snapshot: nano-cent prices require v2")
		}
		if s.InputTokenMicroCents < 0 || s.OutputTokenMicroCents < 0 || s.RequestCents < 0 {
			return errors.New("provider_price_snapshot: price fields cannot be negative")
		}
		if s.InputTokenMicroCents == 0 && s.OutputTokenMicroCents == 0 && s.RequestCents == 0 {
			return errors.New("provider_price_snapshot: at least one price field is required")
		}
		return nil
	}
	if s.SchemaVersion != ProviderPriceSchemaV2 {
		return errors.New("provider_price_snapshot: unsupported schema version")
	}
	if s.InputTokenMicroCents != 0 || s.OutputTokenMicroCents != 0 || s.RequestCents != 0 {
		return errors.New("provider_price_snapshot: v2 cannot mix legacy price units")
	}
	if s.InputTokenNanoCents < 0 || s.OutputTokenNanoCents < 0 || s.RequestNanoCents < 0 {
		return errors.New("provider_price_snapshot: price fields cannot be negative")
	}
	if s.InputTokenNanoCents == 0 && s.OutputTokenNanoCents == 0 && s.RequestNanoCents == 0 {
		return errors.New("provider_price_snapshot: at least one price field is required")
	}
	if s.CapturedAt.IsZero() || s.EffectiveAt.IsZero() {
		return errors.New("provider_price_snapshot: v2 capture and effective times are required")
	}
	if len(s.Currency) != 3 || strings.IndexFunc(s.Currency, func(r rune) bool { return r < 'A' || r > 'Z' }) >= 0 {
		return errors.New("provider_price_snapshot: v2 currency requires three uppercase letters")
	}
	if len(s.SourceHash) != 71 || !strings.HasPrefix(s.SourceHash, "sha256:") || strings.ToLower(s.SourceHash) != s.SourceHash {
		return errors.New("provider_price_snapshot: v2 source_hash requires a SHA-256 digest")
	}
	if _, err := hex.DecodeString(s.SourceHash[7:]); err != nil {
		return errors.New("provider_price_snapshot: v2 source_hash requires a SHA-256 digest")
	}
	return nil
}

// ExactCostNanoCents retains the unrounded tariff cost for v2. It is distinct
// from QuoteCents' conservative whole-cent reservation, and is not evidence of
// the provider's actual invoice. Billing adjustments need provider evidence.
func (s *ProviderPriceSnapshot) ExactCostNanoCents(inputTokens, outputTokens int64) (int64, error) {
	if err := s.Validate(); err != nil {
		return 0, err
	}
	if s.SchemaVersion != ProviderPriceSchemaV2 {
		return 0, errors.New("provider_price_snapshot: exact nano-cent cost requires v2")
	}
	a, okA := mulNonNegative(inputTokens, s.InputTokenNanoCents)
	b, okB := mulNonNegative(outputTokens, s.OutputTokenNanoCents)
	if !okA || !okB || b > math.MaxInt64-a || s.RequestNanoCents > math.MaxInt64-a-b {
		return 0, errors.New("provider_price_snapshot: token cost overflow")
	}
	return a + b + s.RequestNanoCents, nil
}

// Seal validates and commits the price fields. This is a digest, not a signature.
func (s *ProviderPriceSnapshot) Seal() error {
	if err := s.Validate(); err != nil {
		return err
	}
	s.ContentHash = s.computeHash()
	return nil
}

// CanonicalDigest lets consumers verify the source-owned representation without
// duplicating its field list. Validate must succeed before using a price.
func (s *ProviderPriceSnapshot) CanonicalDigest() string {
	if s == nil {
		return ""
	}
	return s.computeHash()
}

func (s *ProviderPriceSnapshot) exactPriceDigest() string {
	return hashSpendAuthorityCanonical(struct {
		SchemaVersion          string    `json:"schema_version"`
		ID                     string    `json:"id"`
		ProviderID             string    `json:"provider_id"`
		ModelID                string    `json:"model_id"`
		Currency               string    `json:"currency"`
		InputTokenNanoCents    int64     `json:"input_token_nano_cents"`
		OutputTokenNanoCents   int64     `json:"output_token_nano_cents"`
		RequestNanoCents       int64     `json:"request_nano_cents"`
		ProviderTermsProfileID string    `json:"provider_terms_profile_id"`
		SourceURI              string    `json:"source_uri"`
		SourceHash             string    `json:"source_hash"`
		CapturedAt             time.Time `json:"captured_at"`
		EffectiveAt            time.Time `json:"effective_at"`
		ExpiresAt              time.Time `json:"expires_at"`
	}{s.SchemaVersion, s.ID, s.ProviderID, s.ModelID, s.Currency,
		s.InputTokenNanoCents, s.OutputTokenNanoCents, s.RequestNanoCents,
		s.ProviderTermsProfileID, s.SourceURI, s.SourceHash,
		s.CapturedAt, s.EffectiveAt, s.ExpiresAt})
}
