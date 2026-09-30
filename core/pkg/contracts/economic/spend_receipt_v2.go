package economic

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"regexp"
	"strings"
	"time"
)

// quantum_posture: SHA-256 content commitments are not signatures. A receipt
// needs the existing authenticated evidence envelope to establish its issuer.
const UsageReceiptSchemaV2 = "helm.usage-receipt.v2"
const SettlementReceiptSchemaV2 = "helm.settlement-receipt.v2"
const TariffEstimateBasis = "TARIFF_ESTIMATE"

// UsageReceiptV2 records exact provider tariff accrual, not a verified invoice
// or a customer charge. No platform fee, tax or resale policy is inferred.
// All amounts are decimal strings on the wire to survive JavaScript clients.
// Settlement binds this receipt's hash in one direction; there is no hash cycle.
type UsageReceiptV2 struct {
	SchemaVersion             string    `json:"schema_version"`
	ID                        string    `json:"id"`
	TenantID                  string    `json:"tenant_id"`
	WorkspaceID               string    `json:"workspace_id"`
	RouteQuoteID              string    `json:"route_quote_id"`
	SpendIntentID             string    `json:"spend_intent_id"`
	EnvelopeID                string    `json:"envelope_id"`
	AgentID                   string    `json:"agent_id"`
	ProviderID                string    `json:"provider_id"`
	ModelID                   string    `json:"model_id"`
	ProviderRequestID         string    `json:"provider_request_id"`
	ProviderPriceSnapshotHash string    `json:"provider_price_snapshot_hash"`
	ObservationDigest         string    `json:"observation_digest"`
	ReservedNanoCents         int64     `json:"reserved_nano_cents,string"`
	AccruedNanoCents          int64     `json:"accrued_nano_cents,string"`
	Currency                  string    `json:"currency"`
	CostBasis                 string    `json:"cost_basis"`
	InputTokens               int64     `json:"input_tokens,string"`
	OutputTokens              int64     `json:"output_tokens,string"`
	PolicyHash                string    `json:"policy_hash"`
	EvidencePackRef           string    `json:"evidence_pack_ref"`
	CreatedAt                 time.Time `json:"created_at"`
	ContentHash               string    `json:"content_hash"`
}

func (r *UsageReceiptV2) Validate() error {
	if r == nil || r.SchemaVersion != UsageReceiptSchemaV2 || r.CostBasis != TariffEstimateBasis {
		return errors.New("usage receipt v2: unsupported version or cost basis")
	}
	if err := exactReceiptFields(r.Currency, r.CreatedAt, r.ID, r.TenantID, r.WorkspaceID, r.RouteQuoteID, r.SpendIntentID, r.EnvelopeID, r.AgentID, r.ProviderID, r.ModelID, r.ProviderRequestID, r.EvidencePackRef); err != nil {
		return err
	}
	if !exactDigest(r.ProviderPriceSnapshotHash) || !exactDigest(r.ObservationDigest) || !exactDigest(r.PolicyHash) {
		return errors.New("usage receipt v2: price, observation and policy digests required")
	}
	if r.ReservedNanoCents <= 0 || r.AccruedNanoCents < 0 || r.AccruedNanoCents > r.ReservedNanoCents || r.InputTokens < 0 || r.OutputTokens < 0 {
		return errors.New("usage receipt v2: invalid amounts or token counts")
	}
	return nil
}

// VerifyPrice recomputes the accrual from the immutable tariff and observation.
// This verifies arithmetic and binding, not the truth of the provider usage.
func (r *UsageReceiptV2) VerifyPrice(p *ProviderPriceSnapshot) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if p == nil || p.ContentHash != r.ProviderPriceSnapshotHash || p.CanonicalDigest() != p.ContentHash || p.ProviderID != r.ProviderID || p.ModelID != r.ModelID || p.Currency != r.Currency {
		return errors.New("usage receipt v2: tariff binding mismatch")
	}
	amount, err := p.ExactCostNanoCents(r.InputTokens, r.OutputTokens)
	if err != nil {
		return err
	}
	if amount != r.AccruedNanoCents {
		return errors.New("usage receipt v2: accrual differs from tariff")
	}
	return nil
}

func (r *UsageReceiptV2) CanonicalContentHash() string {
	if r == nil {
		return ""
	}
	body := *r
	body.ContentHash = ""
	return hashSpendAuthorityCanonical(body)
}
func (r *UsageReceiptV2) Seal() error {
	if err := r.Validate(); err != nil {
		return err
	}
	r.ContentHash = r.CanonicalContentHash()
	return nil
}
func (r *UsageReceiptV2) HasCanonicalContentHash() bool {
	return r != nil && r.Validate() == nil && r.ContentHash == r.CanonicalContentHash()
}

type SettlementLedgerEntryV2 struct {
	ID              string              `json:"id"`
	AccountID       string              `json:"account_id"`
	Direction       SettlementDirection `json:"direction"`
	AmountNanoCents int64               `json:"amount_nano_cents,string"`
}

// SettlementReceiptV2 commits the balanced accrual movements in the existing
// ledger. A zero-cost completion has an empty ledger and releases its hold.
type SettlementReceiptV2 struct {
	SchemaVersion          string                    `json:"schema_version"`
	ID                     string                    `json:"id"`
	TenantID               string                    `json:"tenant_id"`
	WorkspaceID            string                    `json:"workspace_id"`
	UsageReceiptID         string                    `json:"usage_receipt_id"`
	RouteQuoteID           string                    `json:"route_quote_id"`
	SourceUsageReceiptHash string                    `json:"source_usage_receipt_hash"`
	ReservedNanoCents      int64                     `json:"reserved_nano_cents,string"`
	AccruedNanoCents       int64                     `json:"accrued_nano_cents,string"`
	Currency               string                    `json:"currency"`
	CostBasis              string                    `json:"cost_basis"`
	LedgerEntries          []SettlementLedgerEntryV2 `json:"ledger_entries"`
	EvidencePackRef        string                    `json:"evidence_pack_ref"`
	CreatedAt              time.Time                 `json:"created_at"`
	ContentHash            string                    `json:"content_hash"`
}

func (s *SettlementReceiptV2) Validate() error {
	if s == nil || s.SchemaVersion != SettlementReceiptSchemaV2 || s.CostBasis != TariffEstimateBasis {
		return errors.New("settlement receipt v2: unsupported version or cost basis")
	}
	if err := exactReceiptFields(s.Currency, s.CreatedAt, s.ID, s.TenantID, s.WorkspaceID, s.UsageReceiptID, s.RouteQuoteID, s.EvidencePackRef); err != nil {
		return err
	}
	if !exactDigest(s.SourceUsageReceiptHash) || s.ReservedNanoCents <= 0 || s.AccruedNanoCents < 0 || s.AccruedNanoCents > s.ReservedNanoCents || s.LedgerEntries == nil {
		return errors.New("settlement receipt v2: invalid source, amounts or ledger")
	}
	ids := make(map[string]bool)
	accounts := make(map[string]SettlementDirection)
	var debit, credit int64
	for _, e := range s.LedgerEntries {
		if strings.TrimSpace(e.ID) == "" || strings.TrimSpace(e.AccountID) == "" || ids[e.ID] || e.AmountNanoCents <= 0 {
			return errors.New("settlement receipt v2: invalid or duplicate entry")
		}
		ids[e.ID] = true
		if prior, ok := accounts[e.AccountID]; ok && prior != e.Direction {
			return errors.New("settlement receipt v2: self-offsetting account")
		}
		accounts[e.AccountID] = e.Direction
		var sum *int64
		switch e.Direction {
		case SettlementDebit:
			sum = &debit
		case SettlementCredit:
			sum = &credit
		default:
			return errors.New("settlement receipt v2: unknown direction")
		}
		if e.AmountNanoCents > math.MaxInt64-*sum {
			return errors.New("settlement receipt v2: ledger overflow")
		}
		*sum += e.AmountNanoCents
	}
	if debit != s.AccruedNanoCents || credit != debit {
		return errors.New("settlement receipt v2: ledger differs from accrual")
	}
	return nil
}
func (s *SettlementReceiptV2) VerifyUsage(r *UsageReceiptV2) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if !r.HasCanonicalContentHash() || s.SourceUsageReceiptHash != r.ContentHash || s.UsageReceiptID != r.ID || s.TenantID != r.TenantID || s.WorkspaceID != r.WorkspaceID || s.RouteQuoteID != r.RouteQuoteID || s.Currency != r.Currency || s.ReservedNanoCents != r.ReservedNanoCents || s.AccruedNanoCents != r.AccruedNanoCents {
		return errors.New("settlement receipt v2: usage binding mismatch")
	}
	return nil
}
func (s *SettlementReceiptV2) CanonicalContentHash() string {
	if s == nil {
		return ""
	}
	body := *s
	body.ContentHash = ""
	return hashSpendAuthorityCanonical(body)
}
func (s *SettlementReceiptV2) Seal() error {
	if err := s.Validate(); err != nil {
		return err
	}
	s.ContentHash = s.CanonicalContentHash()
	return nil
}
func (s *SettlementReceiptV2) HasCanonicalContentHash() bool {
	return s != nil && s.Validate() == nil && s.ContentHash == s.CanonicalContentHash()
}

// Strict decoding prevents old cent fields or unknown extensions from being
// silently dropped before verification. Consumers must select by version.
func DecodeUsageReceiptV2(raw []byte) (*UsageReceiptV2, error) {
	r := new(UsageReceiptV2)
	if err := decodeExactReceipt(raw, r); err != nil {
		return nil, err
	}
	return r, r.Validate()
}
func DecodeSettlementReceiptV2(raw []byte) (*SettlementReceiptV2, error) {
	s := new(SettlementReceiptV2)
	if err := decodeExactReceipt(raw, s); err != nil {
		return nil, err
	}
	return s, s.Validate()
}
func decodeExactReceipt(raw []byte, into any) error {
	// Reject duplicate keys, including nested entry objects; encoding/json's
	// last-key-wins behavior is not suitable for financial evidence.
	check := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueJSONValue(check); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(into); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("exact receipt: trailing JSON")
	}
	return validateExactWire(raw, reflect.TypeOf(into).Elem())
}

func validateExactWire(raw []byte, value reflect.Type) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for i := 0; i < value.NumField(); i++ {
		tag := strings.Split(value.Field(i).Tag.Get("json"), ",")
		field, ok := fields[tag[0]]
		if !ok || bytes.Equal(bytes.TrimSpace(field), []byte("null")) {
			return errors.New("exact receipt: missing or null field")
		}
		if len(tag) == 2 && tag[1] == "string" {
			var n string
			if json.Unmarshal(field, &n) != nil || !exactUnsignedDecimal.MatchString(n) {
				return errors.New("exact receipt: noncanonical integer")
			}
		}
		ft := value.Field(i).Type
		if ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.Struct {
			var entries []json.RawMessage
			if err := json.Unmarshal(field, &entries); err != nil {
				return err
			}
			for _, entry := range entries {
				if err := validateExactWire(entry, ft.Elem()); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

var exactUnsignedDecimal = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

func uniqueJSONValue(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("exact receipt: duplicate JSON field")
			}
			seen[name] = true
			if err := uniqueJSONValue(d); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := uniqueJSONValue(d); err != nil {
				return err
			}
		}
	default:
		return errors.New("exact receipt: invalid JSON structure")
	}
	_, err = d.Token()
	return err
}
func exactReceiptFields(currency string, at time.Time, fields ...string) error {
	for _, field := range fields {
		if strings.TrimSpace(field) == "" {
			return errors.New("exact receipt: required field missing")
		}
	}
	if len(currency) != 3 || strings.IndexFunc(currency, func(r rune) bool { return r < 'A' || r > 'Z' }) >= 0 {
		return errors.New("exact receipt: invalid currency")
	}
	raw, err := at.MarshalJSON()
	var decoded time.Time
	if at.IsZero() || err != nil || decoded.UnmarshalJSON(raw) != nil || !at.Equal(decoded) {
		return errors.New("exact receipt: invalid timestamp")
	}
	return nil
}
func exactDigest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s[7:])
	return err == nil
}
