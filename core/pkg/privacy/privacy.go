package privacy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// DetectorVersion identifies the deterministic egress detector used by the
// shared privacy boundary. It is intentionally a version, not a description
// of any detected value.
const DetectorVersion = "helm-privacy-v1"

const (
	maxProtectDepth       = 32
	maxProtectNodes       = 10000
	maxProtectStringBytes = 1 << 20
	maxProtectTotalBytes  = 4 << 20
	maxUnicodeEscapeDepth = 4
)

var (
	// ErrDataEgressBlocked is the stable, value-free failure returned when a
	// value cannot be safely sent across a governed boundary.
	ErrDataEgressBlocked = errors.New("DATA_EGRESS_BLOCKED")

	// ErrDataEgressInvalid is kept distinct for callers that need to diagnose
	// malformed values locally. The MCP firewall maps both errors to the same
	// public data-egress denial.
	ErrDataEgressInvalid = errors.New("DATA_EGRESS_INVALID")

	phonePattern      = regexp.MustCompile(`(?:\+[1-9][0-9]{0,2}(?:[ .()-]*[0-9]){7,14}|(?:\([0-9]{2,4}\)|[0-9]{3,4})(?:[ .-]+[0-9]{2,4}){2,4})`)
	ssnPattern        = regexp.MustCompile(`\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`)
	cardPattern       = regexp.MustCompile(`(?:[0-9][ -]?){13,19}`)
	ibanPattern       = regexp.MustCompile(`(?i)\b[A-Z]{2}[0-9]{2}(?:[ -]?[A-Z0-9]){11,30}\b`)
	secretPattern     = regexp.MustCompile(`(?i)(?:\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd|secret|credential|token)\b\s*[:=]\s*(?:"[^"\r\n]{1,}"|'[^'\r\n]{1,}'|[^\s,;]+)|\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9_-]{4,}\b|\b(?:sk|rk)[_-](?:live|test)?[_-]?[A-Za-z0-9_-]{8,}\b|\b(?:ghp|github_pat|gho|ghs|glpat|xox[baprs])[-_][A-Za-z0-9_-]{12,}\b|\b(?:hf|npm|pypi)[_-][A-Za-z0-9_-]{12,}\b|\bAKIA[0-9A-Z]{16}\b|\bBearer\s+[A-Za-z0-9._~+/=-]{8,})`)
	privateKeyPattern = regexp.MustCompile(`(?i)-----begin [a-z0-9 ]*private key-----`)
)

var restrictedKeyMarkers = []string{
	"secret",
	"token",
	"password",
	"passwd",
	"authorization",
	"cookie",
	"credential",
	"private_key",
	"api_key",
	"apikey",
	"access_token",
	"client_secret",
	"ssn",
	"social_security",
	"tax_id",
	"credit_card",
	"payment_card",
	"card_number",
	"cc_number",
	"iban",
	"bank_account",
}

// PIIClassification defines the sensitivity level of data.
type PIIClassification string

const (
	PIINone      PIIClassification = "NONE"
	PIISensitive PIIClassification = "SENSITIVE" // Name, Email, IP, etc.
	PIICritical  PIIClassification = "CRITICAL"  // SSN, Credit Card, Health Data
)

// PrivacyManager defines the interface for privacy controls.
type PrivacyManager interface {
	// Scrub removes PII from the given text based on the classification.
	Scrub(ctx context.Context, text string, level PIIClassification) string
	// Validate verifies if the data complies with privacy policies.
	Validate(ctx context.Context, data map[string]interface{}) (bool, []string)
}

// StandardPrivacyManager implements the PrivacyManager interface.
type StandardPrivacyManager struct {
	emailRegex *regexp.Regexp
}

// NewPrivacyManager returns a new instance of StandardPrivacyManager.
func NewPrivacyManager() *StandardPrivacyManager {
	return &StandardPrivacyManager{
		emailRegex: regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
	}
}

// Scrub redacts PII from the text.
func (pm *StandardPrivacyManager) Scrub(ctx context.Context, text string, level PIIClassification) string {
	if level == PIINone {
		return text
	}

	// Simple redaction for emails as a proof of concept
	return pm.emailRegex.ReplaceAllString(text, "[REDACTED_EMAIL]")
}

// Validate checks for privacy compliance.
// For now, it just ensures no critical PII keys exist in the top level of the map.
func (pm *StandardPrivacyManager) Validate(ctx context.Context, data map[string]interface{}) (bool, []string) {
	var violations []string
	// Example rule: no key should contain "ssn" or "credit_card"
	restrictedKeys := []string{"ssn", "social_security", "credit_card", "cc_number"}

	for key := range data {
		for _, restricted := range restrictedKeys {
			if key == restricted {
				violations = append(violations, "found restricted key: "+key)
			}
		}
	}

	if len(violations) > 0 {
		return false, violations
	}
	return true, nil
}

// Protect returns a deep, non-mutating copy of value suitable for crossing a
// governed MCP boundary. Ordinary email and phone values are replaced with
// stable markers. Restricted credentials and financial/identity values fail
// closed. findings contains only unique detector labels and never a value.
//
// Protect deliberately accepts any so callers cannot accidentally protect only
// the top-level map while allowing a nested map, slice, or JSON raw value to
// cross the boundary unchanged.
func (pm *StandardPrivacyManager) Protect(ctx context.Context, value any) (protected any, findings []string, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	p := protector{
		ctx:      ctx,
		manager:  pm,
		findings: make(map[string]struct{}),
	}
	protected, err = p.value(value, 0)
	if err != nil {
		return nil, nil, err
	}
	findings = make([]string, 0, len(p.findings))
	for finding := range p.findings {
		findings = append(findings, finding)
	}
	sort.Strings(findings)
	return protected, findings, nil
}

type protector struct {
	ctx      context.Context
	manager  *StandardPrivacyManager
	findings map[string]struct{}
	nodes    int
	bytes    int
}

func (p *protector) value(value any, depth int) (any, error) {
	if err := p.ctx.Err(); err != nil {
		return nil, ErrDataEgressBlocked
	}
	if depth > maxProtectDepth {
		return nil, ErrDataEgressInvalid
	}
	p.nodes++
	if p.nodes > maxProtectNodes {
		return nil, ErrDataEgressInvalid
	}

	switch typed := value.(type) {
	case nil:
		return nil, nil
	case string:
		return p.text(typed)
	case json.Number:
		// A JSON number is not a string payload and must retain its exact
		// lexical representation for canonical downstream evaluation.
		if len(typed) > maxProtectStringBytes {
			return nil, ErrDataEgressInvalid
		}
		return p.numeric(string(typed), typed)
	case json.RawMessage:
		return p.rawJSON(typed, depth)
	case []byte:
		// Raw bytes have no trustworthy textual classification. Callers that
		// intentionally provide JSON must use json.RawMessage so it is parsed
		// and canonicalized exactly once before inspection.
		return nil, ErrDataEgressInvalid
	case map[string]any:
		return p.mapAny(typed, depth)
	case map[string]string:
		return p.mapString(typed)
	case []any:
		return p.sliceAny(typed, depth)
	case []string:
		return p.sliceString(typed)
	case []map[string]any:
		return p.sliceMapAny(typed, depth)
	case bool:
		return value, nil
	case int:
		return p.numeric(strconv.FormatInt(int64(typed), 10), value)
	case int8:
		return p.numeric(strconv.FormatInt(int64(typed), 10), value)
	case int16:
		return p.numeric(strconv.FormatInt(int64(typed), 10), value)
	case int32:
		return p.numeric(strconv.FormatInt(int64(typed), 10), value)
	case int64:
		return p.numeric(strconv.FormatInt(typed, 10), value)
	case uint:
		return p.numeric(strconv.FormatUint(uint64(typed), 10), value)
	case uint8:
		return p.numeric(strconv.FormatUint(uint64(typed), 10), value)
	case uint16:
		return p.numeric(strconv.FormatUint(uint64(typed), 10), value)
	case uint32:
		return p.numeric(strconv.FormatUint(uint64(typed), 10), value)
	case uint64:
		return p.numeric(strconv.FormatUint(typed, 10), value)
	case uintptr:
		return p.numeric(strconv.FormatUint(uint64(typed), 10), value)
	case float32, float64:
		if typed, ok := value.(float32); ok {
			return p.numeric(strconv.FormatFloat(float64(typed), 'f', -1, 32), value)
		}
		if typed, ok := value.(float64); ok {
			return p.numeric(strconv.FormatFloat(typed, 'f', -1, 64), value)
		}
		return value, nil
	}

	// Support typed map/slice values without turning arbitrary structs or
	// pointers into an accidental serialization surface. Pointer/interface
	// cycles terminate at the depth bound and fail closed.
	return p.reflectValue(reflect.ValueOf(value), depth)
}

func (p *protector) numeric(lexical string, value any) (any, error) {
	if err := p.accountBytes(len(lexical)); err != nil {
		return nil, err
	}
	if hasValidNumericCard(lexical) {
		return nil, ErrDataEgressBlocked
	}
	return value, nil
}

func (p *protector) text(value string) (string, error) {
	if err := p.ctx.Err(); err != nil {
		return "", ErrDataEgressBlocked
	}
	if !utf8.ValidString(value) {
		return "", ErrDataEgressInvalid
	}
	if len(value) > maxProtectStringBytes {
		return "", ErrDataEgressInvalid
	}
	if err := p.accountBytes(len(value)); err != nil {
		return "", err
	}
	protected, labels, err := sanitizeText(value, p.manager)
	if err != nil {
		return "", err
	}
	if len(protected) > maxProtectStringBytes {
		return "", ErrDataEgressInvalid
	}
	if len(protected) > len(value) {
		if err := p.accountBytes(len(protected) - len(value)); err != nil {
			return "", err
		}
	}
	for _, label := range labels {
		p.findings[label] = struct{}{}
	}
	return protected, nil
}

func (p *protector) mapAny(value map[string]any, depth int) (map[string]any, error) {
	if value == nil {
		return nil, nil
	}
	if len(value) > maxProtectNodes-p.nodes {
		return nil, ErrDataEgressInvalid
	}
	keys := sortedKeysAny(value)
	protected := make(map[string]any, len(value))
	for _, key := range keys {
		protectedKey, err := p.key(key)
		if err != nil {
			return nil, err
		}
		if _, exists := protected[protectedKey]; exists {
			return nil, ErrDataEgressInvalid
		}
		item, err := p.value(value[key], depth+1)
		if err != nil {
			return nil, err
		}
		protected[protectedKey] = item
	}
	return protected, nil
}

func (p *protector) mapString(value map[string]string) (map[string]string, error) {
	if value == nil {
		return nil, nil
	}
	if len(value) > maxProtectNodes-p.nodes {
		return nil, ErrDataEgressInvalid
	}
	p.nodes += len(value)
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	protected := make(map[string]string, len(value))
	for _, key := range keys {
		protectedKey, err := p.key(key)
		if err != nil {
			return nil, err
		}
		if _, exists := protected[protectedKey]; exists {
			return nil, ErrDataEgressInvalid
		}
		item, err := p.text(value[key])
		if err != nil {
			return nil, err
		}
		protected[protectedKey] = item
	}
	return protected, nil
}

func (p *protector) key(key string) (string, error) {
	if err := p.ctx.Err(); err != nil {
		return "", ErrDataEgressBlocked
	}
	if len(key) > maxProtectStringBytes {
		return "", ErrDataEgressInvalid
	}
	canonical, unresolved := canonicalizeUnicode(key)
	if unresolved || isRestrictedKey(canonical) {
		return "", ErrDataEgressBlocked
	}
	return p.text(key)
}

func (p *protector) sliceAny(value []any, depth int) ([]any, error) {
	if value == nil {
		return nil, nil
	}
	if len(value) > maxProtectNodes-p.nodes {
		return nil, ErrDataEgressInvalid
	}
	protected := make([]any, len(value))
	for i, item := range value {
		var err error
		protected[i], err = p.value(item, depth+1)
		if err != nil {
			return nil, err
		}
	}
	return protected, nil
}

func (p *protector) sliceString(value []string) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	if len(value) > maxProtectNodes-p.nodes {
		return nil, ErrDataEgressInvalid
	}
	p.nodes += len(value)
	protected := make([]string, len(value))
	for i, item := range value {
		var err error
		protected[i], err = p.text(item)
		if err != nil {
			return nil, err
		}
	}
	return protected, nil
}

func (p *protector) sliceMapAny(value []map[string]any, depth int) ([]map[string]any, error) {
	if value == nil {
		return nil, nil
	}
	if len(value) > maxProtectNodes-p.nodes {
		return nil, ErrDataEgressInvalid
	}
	protected := make([]map[string]any, len(value))
	for i, item := range value {
		var err error
		protected[i], err = p.mapAny(item, depth+1)
		if err != nil {
			return nil, err
		}
	}
	return protected, nil
}

func (p *protector) rawJSON(raw json.RawMessage, depth int) (json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > maxProtectStringBytes {
		return nil, ErrDataEgressInvalid
	}
	if err := p.accountBytes(len(raw)); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return nil, ErrDataEgressInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, ErrDataEgressInvalid
	}
	protected, err := p.value(decoded, depth+1)
	if err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(protected)
	if err != nil || len(canonical) > maxProtectStringBytes {
		return nil, ErrDataEgressInvalid
	}
	if len(canonical) > len(raw) {
		if err := p.accountBytes(len(canonical) - len(raw)); err != nil {
			return nil, err
		}
	}
	return json.RawMessage(canonical), nil
}

func (p *protector) accountBytes(size int) error {
	if size < 0 || size > maxProtectTotalBytes-p.bytes {
		return ErrDataEgressInvalid
	}
	p.bytes += size
	return nil
}

func (p *protector) reflectValue(value reflect.Value, depth int) (any, error) {
	if !value.IsValid() {
		return nil, nil
	}
	switch value.Kind() {
	case reflect.Interface, reflect.Pointer:
		if value.IsNil() {
			return nil, nil
		}
		return p.value(value.Elem().Interface(), depth+1)
	case reflect.Map:
		if value.IsNil() || value.Type().Key().Kind() != reflect.String {
			if value.IsNil() {
				return nil, nil
			}
			return nil, ErrDataEgressInvalid
		}
		if value.Len() > maxProtectNodes-p.nodes {
			return nil, ErrDataEgressInvalid
		}
		keys := value.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		protected := make(map[string]any, len(keys))
		for _, key := range keys {
			protectedKey, err := p.key(key.String())
			if err != nil {
				return nil, err
			}
			if _, exists := protected[protectedKey]; exists {
				return nil, ErrDataEgressInvalid
			}
			item, err := p.value(value.MapIndex(key).Interface(), depth+1)
			if err != nil {
				return nil, err
			}
			protected[protectedKey] = item
		}
		return protected, nil
	case reflect.Slice, reflect.Array:
		if value.Kind() == reflect.Slice && value.IsNil() {
			return nil, nil
		}
		if value.Type().Elem().Kind() == reflect.Uint8 {
			return nil, ErrDataEgressInvalid
		}
		if value.Len() > maxProtectNodes-p.nodes {
			return nil, ErrDataEgressInvalid
		}
		protected := make([]any, value.Len())
		for i := 0; i < value.Len(); i++ {
			var err error
			protected[i], err = p.value(value.Index(i).Interface(), depth+1)
			if err != nil {
				return nil, err
			}
		}
		return protected, nil
	default:
		return nil, ErrDataEgressInvalid
	}
}

func sortedKeysAny(value map[string]any) []string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func isRestrictedKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	normalized = strings.NewReplacer("-", "_", " ", "_", ".", "_").Replace(normalized)
	compact := strings.ReplaceAll(normalized, "_", "")
	for _, marker := range restrictedKeyMarkers {
		if strings.Contains(normalized, marker) || strings.Contains(compact, strings.ReplaceAll(marker, "_", "")) {
			return true
		}
	}
	return false
}

func sanitizeText(value string, manager *StandardPrivacyManager) (string, []string, error) {
	canonical, unresolved := canonicalizeUnicode(value)
	if unresolved {
		// An unresolved escape layer is not safe to forward. It may be an
		// encoded secret/PII value whose final representation is hidden by the
		// layer cap, so fail closed rather than guessing.
		return "", nil, ErrDataEgressBlocked
	}

	if restrictedText(canonical) {
		return "", nil, ErrDataEgressBlocked
	}
	labels := make([]string, 0, 2)
	protected := canonical
	emailRegex := defaultEmailRegex
	if manager != nil && manager.emailRegex != nil {
		emailRegex = manager.emailRegex
	}
	if emailRegex.MatchString(protected) {
		protected = emailRegex.ReplaceAllString(protected, "[REDACTED_EMAIL]")
		labels = append(labels, "email")
	}
	if redacted, changed := redactPhones(protected); changed {
		protected = redacted
		labels = append(labels, "phone")
	}
	if len(labels) == 0 {
		// Canonicalization is only a detection aid. Preserve a clean caller
		// value byte-for-byte, including literal escaped code text.
		return value, nil, nil
	}
	return protected, labels, nil
}

var defaultEmailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)

func restrictedText(value string) bool {
	if ssnPattern.MatchString(value) || secretPattern.MatchString(value) || privateKeyPattern.MatchString(value) {
		return true
	}
	if hasValidCard(value) || hasValidIBAN(value) {
		return true
	}
	return looksLikeJWTText(value)
}

func redactPhones(value string) (string, bool) {
	indices := phonePattern.FindAllStringIndex(value, -1)
	if len(indices) == 0 {
		return value, false
	}
	var builder strings.Builder
	last := 0
	changed := false
	for _, index := range indices {
		candidate := value[index[0]:index[1]]
		if (index[0] > 0 && isDigit(value[index[0]-1])) || (index[1] < len(value) && isDigit(value[index[1]])) {
			continue
		}
		if digitCount(candidate) < 10 || digitCount(candidate) > 15 || !plausiblePhone(candidate) {
			continue
		}
		builder.WriteString(value[last:index[0]])
		builder.WriteString("[REDACTED_PHONE]")
		last = index[1]
		changed = true
	}
	if !changed {
		return value, false
	}
	builder.WriteString(value[last:])
	return builder.String(), true
}

func digitCount(value string) int {
	count := 0
	for _, char := range value {
		if char >= '0' && char <= '9' {
			count++
		}
	}
	return count
}

func isDigit(value byte) bool {
	return value >= '0' && value <= '9'
}

func plausiblePhone(value string) bool {
	if strings.HasPrefix(value, "+") || strings.HasPrefix(value, "(") {
		return true
	}
	// A four-digit first group is common in dates and identifiers, but not in
	// the local phone formats this boundary recognizes.
	firstGroup := value
	if separator := strings.IndexAny(firstGroup, " .-"); separator >= 0 {
		firstGroup = firstGroup[:separator]
	}
	return len(firstGroup) <= 3
}

func hasValidCard(value string) bool {
	for _, index := range cardPattern.FindAllStringIndex(value, -1) {
		if (index[0] > 0 && isDigit(value[index[0]-1])) || (index[1] < len(value) && isDigit(value[index[1]])) {
			continue
		}
		match := value[index[0]:index[1]]
		digits := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, match)
		if len(digits) >= 13 && len(digits) <= 19 && luhnValid(digits) {
			return true
		}
	}
	return false
}

func hasValidNumericCard(value string) bool {
	if len(value) < 13 || len(value) > 19 {
		return false
	}
	for index := 0; index < len(value); index++ {
		if !isDigit(value[index]) {
			return false
		}
	}
	return luhnValid(value)
}

func luhnValid(value string) bool {
	if len(value) < 2 {
		return false
	}
	sum := 0
	double := false
	for i := len(value) - 1; i >= 0; i-- {
		digit := int(value[i] - '0')
		if double {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		double = !double
	}
	return sum%10 == 0
}

func hasValidIBAN(value string) bool {
	for _, match := range ibanPattern.FindAllString(value, -1) {
		compact := strings.Map(func(r rune) rune {
			switch {
			case r == ' ' || r == '-':
				return -1
			case r >= 'a' && r <= 'z':
				return r - ('a' - 'A')
			default:
				return r
			}
		}, match)
		if len(compact) < 15 || len(compact) > 34 || ibanMod97(compact) != 1 {
			continue
		}
		return true
	}
	return false
}

func ibanMod97(value string) int {
	if len(value) < 4 {
		return 0
	}
	reordered := value[4:] + value[:4]
	remainder := 0
	for _, char := range reordered {
		if char >= '0' && char <= '9' {
			remainder = (remainder*10 + int(char-'0')) % 97
			continue
		}
		if char < 'A' || char > 'Z' {
			return 0
		}
		for _, digit := range strconv.Itoa(int(char-'A') + 10) {
			remainder = (remainder*10 + int(digit-'0')) % 97
		}
	}
	return remainder
}

func looksLikeJWTText(value string) bool {
	for _, field := range strings.Fields(value) {
		trimmed := strings.Trim(field, "\"'`,;()[]{}")
		parts := strings.Split(trimmed, ".")
		if len(parts) != 3 {
			continue
		}
		valid := true
		for _, part := range parts {
			if len(part) < 8 {
				valid = false
				break
			}
			for _, char := range part {
				if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' && char != '_' {
					valid = false
					break
				}
			}
			if !valid {
				break
			}
		}
		if valid {
			return true
		}
	}
	return false
}

func canonicalizeUnicode(value string) (string, bool) {
	canonical := value
	for depth := 0; depth < maxUnicodeEscapeDepth; depth++ {
		if next, changed := collapseUnicodeLayer(canonical); changed {
			canonical = next
			continue
		}
		if next, changed := decodeUnicodeLayer(canonical); changed {
			canonical = next
			continue
		}
		return canonical, false
	}
	_, collapsed := collapseUnicodeLayer(canonical)
	_, decoded := decodeUnicodeLayer(canonical)
	return canonical, collapsed || decoded
}

func collapseUnicodeLayer(value string) (string, bool) {
	var builder strings.Builder
	changed := false
	for i := 0; i < len(value); {
		if value[i] != '\\' {
			builder.WriteByte(value[i])
			i++
			continue
		}
		start := i
		for i < len(value) && value[i] == '\\' {
			i++
		}
		run := i - start
		if i+4 < len(value) && value[i] == 'u' && isHex4(value[i+1:i+5]) && run >= 2 {
			builder.WriteString(strings.Repeat("\\", run-1))
			builder.WriteString(value[i : i+5])
			i += 5
			changed = true
			continue
		}
		builder.WriteString(value[start:i])
	}
	return builder.String(), changed
}

func decodeUnicodeLayer(value string) (string, bool) {
	var builder strings.Builder
	changed := false
	for i := 0; i < len(value); {
		if i+5 >= len(value) || value[i] != '\\' || value[i+1] != 'u' || !isHex4(value[i+2:i+6]) {
			_, size := utf8.DecodeRuneInString(value[i:])
			if size == 0 {
				size = 1
			}
			builder.WriteString(value[i : i+size])
			i += size
			continue
		}
		code, _ := strconv.ParseUint(value[i+2:i+6], 16, 16)
		runeValue := rune(code)
		consumed := 6
		if utf16.IsSurrogate(runeValue) && runeValue >= 0xD800 && runeValue <= 0xDBFF && i+11 < len(value) && value[i+6] == '\\' && value[i+7] == 'u' && isHex4(value[i+8:i+12]) {
			low, _ := strconv.ParseUint(value[i+8:i+12], 16, 16)
			if low >= 0xDC00 && low <= 0xDFFF {
				runeValue = utf16.DecodeRune(runeValue, rune(low))
				consumed = 12
			}
		}
		if !utf8.ValidRune(runeValue) || (runeValue >= 0xD800 && runeValue <= 0xDFFF) {
			builder.WriteString(value[i : i+consumed])
			i += consumed
			continue
		}
		builder.WriteRune(runeValue)
		i += consumed
		changed = true
	}
	return builder.String(), changed
}

func isHex4(value string) bool {
	if len(value) != 4 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') && (char < 'A' || char > 'F') {
			return false
		}
	}
	return true
}
