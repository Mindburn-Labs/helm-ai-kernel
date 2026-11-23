package privacy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// DetectorVersion identifies the deterministic egress detector used by the
// shared privacy boundary. It is intentionally a version, not a description
// of any detected value.
const DetectorVersion = "helm-privacy-v5"

const (
	// MaxPayloadBytes is the largest complete JSON document accepted by the
	// canonical privacy boundary. Individual text values remain more tightly
	// bounded so one field cannot monopolize the full payload budget.
	MaxPayloadBytes       = 4 << 20
	maxProtectDepth       = 32
	maxProtectNodes       = 10000
	maxJSONProtectNodes   = 1 << 18
	maxProtectStringBytes = 1 << 20
	maxProtectTotalBytes  = MaxPayloadBytes
	maxUnicodeEscapeDepth = 4
	maxExactFloat32Int    = 1<<24 - 1
	maxExactFloat64Int    = 1<<53 - 1
	modelLogprobTokenKey  = "helm_logprob_lexeme"
	modelEmbeddedJSONKey  = "helm_model_embedded_json"
	modelSchemaKeyPrefix  = "helm_model_schema_name_"
)

type modelPayloadKind uint8

const (
	modelPayloadGeneric modelPayloadKind = iota
	modelPayloadRequest
	modelPayloadResponse
)

var (
	// ErrDataEgressBlocked is the stable, value-free failure returned when a
	// value cannot be safely sent across a governed boundary.
	ErrDataEgressBlocked = errors.New("DATA_EGRESS_BLOCKED")

	// ErrDataEgressInvalid is kept distinct for callers that need to diagnose
	// malformed values locally. The MCP firewall maps both errors to the same
	// public data-egress denial.
	ErrDataEgressInvalid = errors.New("DATA_EGRESS_INVALID")

	phonePattern        = regexp.MustCompile(`(?:(?:\+|00)[1-9][0-9]{0,2}(?:[ .()-]*[0-9]){7,14}|(?:\([0-9]{2,4}\)|[0-9]{3,4})(?:[ .-]+[0-9]{2,4}){2,4}|\b[0-9]{10,15}\b)`)
	ssnPattern          = regexp.MustCompile(`\b[0-9]{3}[ -][0-9]{2}[ -][0-9]{4}\b`)
	compactSSNPattern   = regexp.MustCompile(`(?i)\b(?:ssn|social[ _-]*security(?:[ _-]*(?:number|no))?)\b["']?\s*[:=#-]?\s*["']?[0-9]{9}\b`)
	cardPattern         = regexp.MustCompile(`(?:[0-9][ .-]?){12,19}`)
	ibanPattern         = regexp.MustCompile(`(?i)\b[A-Z]{2}[0-9]{2}(?:[ -]?[A-Z0-9]){11,30}\b`)
	assignmentPattern   = regexp.MustCompile(`(?i)(?:"([^"\r\n]{1,128})"|'([^'\r\n]{1,128})'|([a-z][a-z0-9_.-]{0,127}))\s*[:=]`)
	secretPattern       = regexp.MustCompile(`(?i)(?:\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd|secret|credential|token)\b["']?\s*[:=]\s*(?:"[^"\r\n]{1,}"|'[^'\r\n]{1,}'|[^\s,;]+)|\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9_-]{4,}\b|\b(?:sk|rk)[_-](?:live|test)?[_-]?[A-Za-z0-9_-]{8,}\b|\b(?:ghp|github_pat|gho|ghs|glpat|xox[baprs])[-_][A-Za-z0-9_-]{12,}\b|\b(?:hf|npm|pypi)[_-][A-Za-z0-9_-]{12,}\b|\bAKIA[0-9A-Z]{16}\b|\bBearer\s+[A-Za-z0-9._~+/=-]{8,})`)
	googleAPIKeyPattern = regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])AIza[A-Za-z0-9_-]{35}(?:$|[^A-Za-z0-9_-])`)
	credentialURI       = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^/\s@]*:[^/\s@]+@`)
	privateKeyPattern   = regexp.MustCompile(`(?i)-----begin [a-z0-9 ]*private key(?: block)?-----`)
	jwtPattern          = regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]*)(?:$|[^A-Za-z0-9_-])`)
	paymentContext      = regexp.MustCompile(`(?i)\b(?:card|credit|debit|payment|pan|cc[ _-]*(?:number|no))\b`)
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
	"secret_access_key",
	"ssn",
	"social_security",
	"tax_id",
	"credit_card",
	"payment_card",
	"card_number",
	"cc_number",
	"iban",
	"bank_account",
	"authorization_header",
	"cookie_header",
	"set_cookie",
	"private_key_pem",
	"password_hash",
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
		emailRegex: defaultEmailRegex,
	}
}

// Scrub redacts PII from the text.
func (pm *StandardPrivacyManager) Scrub(ctx context.Context, text string, level PIIClassification) string {
	if level == PIINone {
		return text
	}

	protected, _ := redactCanonicalMatches(text, findEmailMatches(text, pm.emailRegex), "[REDACTED_EMAIL]")
	return protected
}

// Validate reports top-level keys that exactly match a restricted PII label.
func (pm *StandardPrivacyManager) Validate(ctx context.Context, data map[string]interface{}) (bool, []string) {
	var violations []string
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
		maxNodes: maxProtectNodes,
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

// ProtectJSON applies the canonical privacy boundary to one complete JSON
// payload and returns a bounded, canonical copy safe for egress.
func ProtectJSON(ctx context.Context, raw json.RawMessage) (json.RawMessage, []string, error) {
	return protectJSON(ctx, raw, modelPayloadGeneric)
}

// ProtectModelRequestJSON protects a model request while preserving restricted-
// looking identifiers only where the protocol declares JSON Schema names.
func ProtectModelRequestJSON(ctx context.Context, raw json.RawMessage) (json.RawMessage, []string, error) {
	return protectJSON(ctx, raw, modelPayloadRequest)
}

// ProtectModelResponseJSON protects a provider response while preserving the
// protocol-owned token fields in OpenAI log-probability entries. The exception
// is path-scoped; ordinary token keys remain restricted.
func ProtectModelResponseJSON(ctx context.Context, raw json.RawMessage) (json.RawMessage, []string, error) {
	return protectJSON(ctx, raw, modelPayloadResponse)
}

func protectJSON(ctx context.Context, raw json.RawMessage, kind modelPayloadKind) (json.RawMessage, []string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	p := protector{
		ctx:      ctx,
		manager:  NewPrivacyManager(),
		findings: make(map[string]struct{}),
		maxNodes: maxJSONProtectNodes,
	}
	protected, err := p.protectJSON(raw, 0, kind)
	if err != nil {
		return nil, nil, err
	}
	findings := make([]string, 0, len(p.findings))
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
	maxNodes int
}

func (p *protector) value(value any, depth int) (any, error) {
	if err := p.ctx.Err(); err != nil {
		return nil, ErrDataEgressBlocked
	}
	if depth > maxProtectDepth {
		return nil, ErrDataEgressInvalid
	}
	p.nodes++
	if p.nodes > p.maxNodes {
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
	case float32:
		numeric := float64(typed)
		if unsafeJSONFloat(numeric, maxExactFloat32Int) {
			return nil, ErrDataEgressInvalid
		}
		return p.numeric(strconv.FormatFloat(numeric, 'f', -1, 32), value)
	case float64:
		if unsafeJSONFloat(typed, maxExactFloat64Int) {
			return nil, ErrDataEgressInvalid
		}
		return p.numeric(strconv.FormatFloat(typed, 'f', -1, 64), value)
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
	classified := lexical
	if exact := exactIntegerDigits(lexical); exact != "" {
		classified = exact
	}
	if hasValidNumericCard(classified) {
		return nil, ErrDataEgressBlocked
	}
	return value, nil
}

func exactIntegerDigits(value string) string {
	if value == "" || value[0] == '-' {
		return ""
	}
	mantissa := value
	var exponent int64
	if index := strings.IndexAny(value, "eE"); index >= 0 {
		parsed, err := strconv.ParseInt(value[index+1:], 10, 32)
		if err != nil {
			return ""
		}
		exponent = parsed
		mantissa = value[:index]
	}
	integerDigits := len(mantissa)
	if point := strings.IndexByte(mantissa, '.'); point >= 0 {
		if strings.Contains(mantissa[point+1:], ".") {
			return ""
		}
		integerDigits = point
		mantissa = mantissa[:point] + mantissa[point+1:]
	}
	if mantissa == "" {
		return ""
	}
	firstNonZero := -1
	for index := range mantissa {
		if !isDigit(mantissa[index]) {
			return ""
		}
		if firstNonZero < 0 && mantissa[index] != '0' {
			firstNonZero = index
		}
	}
	if firstNonZero < 0 {
		return "0"
	}
	decimalPosition := int64(integerDigits) + exponent
	if decimalPosition <= 0 {
		return ""
	}
	if decimalPosition < int64(len(mantissa)) {
		for _, digit := range mantissa[decimalPosition:] {
			if digit != '0' {
				return ""
			}
		}
	}
	end := min(decimalPosition, int64(len(mantissa)))
	digits := strings.TrimLeft(mantissa[:end], "0")
	trailingZeros := max(decimalPosition-int64(len(mantissa)), 0)
	if int64(len(digits))+trailingZeros > 19 {
		return ""
	}
	return digits + strings.Repeat("0", int(trailingZeros))
}

func unsafeJSONFloat(value, maxExactInteger float64) bool {
	return math.IsNaN(value) || math.IsInf(value, 0) ||
		(math.Trunc(value) == value && math.Abs(value) > maxExactInteger)
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
	if len(value) > p.maxNodes-p.nodes {
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
		item, err = p.redactNumericPhone(key, item)
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
	if len(value) > p.maxNodes-p.nodes {
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
	canonical, unresolved := canonicalizeTextEncodings(key)
	if unresolved || !utf8.ValidString(canonical) || isRestrictedKey(canonical) {
		return "", ErrDataEgressBlocked
	}
	return p.text(key)
}

func (p *protector) sliceAny(value []any, depth int) ([]any, error) {
	if value == nil {
		return nil, nil
	}
	if len(value) > p.maxNodes-p.nodes {
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
	if len(value) > p.maxNodes-p.nodes {
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
	if len(value) > p.maxNodes-p.nodes {
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
	return p.protectJSON(raw, depth, modelPayloadGeneric)
}

func (p *protector) protectJSON(raw json.RawMessage, depth int, kind modelPayloadKind) (json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > MaxPayloadBytes {
		return nil, ErrDataEgressInvalid
	}
	if err := validateJSONShape(raw); err != nil {
		return nil, err
	}
	decoded, err := decodeJSONValue(raw)
	if err != nil {
		return nil, err
	}
	schemaNames := make(map[string]string)
	if kind == modelPayloadRequest {
		if err := rewriteModelRequestEmbeddedJSON(decoded, false); err != nil {
			return nil, err
		}
		if err := rewriteModelRequestSchemaKeys(decoded, false, schemaNames); err != nil {
			return nil, err
		}
	}
	var originalLogprobTokens []string
	if kind == modelPayloadResponse {
		if err := rewriteModelResponseEmbeddedJSON(decoded, false); err != nil {
			return nil, err
		}
		if err := rewriteModelResponseLogprobTokenKeys(p, decoded, false, &originalLogprobTokens); err != nil {
			return nil, err
		}
	}
	protected, err := p.value(decoded, depth+1)
	if err != nil {
		return nil, err
	}
	if kind == modelPayloadResponse {
		if err := rewriteModelResponseLogprobTokenKeys(p, protected, true, &originalLogprobTokens); err != nil {
			return nil, err
		}
		if len(originalLogprobTokens) != 0 {
			return nil, ErrDataEgressInvalid
		}
		if err := rewriteModelResponseEmbeddedJSON(protected, true); err != nil {
			return nil, err
		}
	}
	if kind == modelPayloadRequest {
		if err := rewriteModelRequestSchemaKeys(protected, true, schemaNames); err != nil {
			return nil, err
		}
		if len(schemaNames) != 0 {
			return nil, ErrDataEgressInvalid
		}
		if err := rewriteModelRequestEmbeddedJSON(protected, true); err != nil {
			return nil, err
		}
	}
	canonical, err := json.Marshal(protected)
	if err != nil || len(canonical) > MaxPayloadBytes {
		return nil, ErrDataEgressInvalid
	}
	if len(canonical) > len(raw) {
		if err := p.accountBytes(len(canonical) - len(raw)); err != nil {
			return nil, err
		}
	}
	return json.RawMessage(canonical), nil
}

func validateJSONShape(raw json.RawMessage) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	depth, nodes, roots := 0, 0, 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ErrDataEgressInvalid
		}
		nodes++
		if nodes > maxJSONProtectNodes {
			return ErrDataEgressInvalid
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{', '[':
				if depth == 0 {
					roots++
				}
				depth++
				if depth > maxProtectDepth {
					return ErrDataEgressInvalid
				}
			case '}', ']':
				depth--
				if depth < 0 {
					return ErrDataEgressInvalid
				}
			}
		} else if depth == 0 {
			roots++
		}
	}
	if roots != 1 || depth != 0 {
		return ErrDataEgressInvalid
	}
	return nil
}

func decodeJSONValue(raw json.RawMessage) (any, error) {
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
	return decoded, nil
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
		if value.Len() > p.maxNodes-p.nodes {
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
			rawItem := value.MapIndex(key).Interface()
			item, err := p.value(rawItem, depth+1)
			if err != nil {
				return nil, err
			}
			item, err = p.redactNumericPhone(key.String(), item)
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
		if value.Len() > p.maxNodes-p.nodes {
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
	case reflect.String:
		protected, err := p.text(value.String())
		if err != nil {
			return nil, err
		}
		result := reflect.New(value.Type()).Elem()
		result.SetString(protected)
		return result.Interface(), nil
	case reflect.Bool:
		return value.Interface(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return p.numeric(strconv.FormatInt(value.Int(), 10), value.Interface())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return p.numeric(strconv.FormatUint(value.Uint(), 10), value.Interface())
	case reflect.Float32, reflect.Float64:
		bits := value.Type().Bits()
		numeric := value.Float()
		maxExact := float64(maxExactFloat64Int)
		if bits == 32 {
			maxExact = maxExactFloat32Int
		}
		if unsafeJSONFloat(numeric, maxExact) {
			return nil, ErrDataEgressInvalid
		}
		return p.numeric(strconv.FormatFloat(numeric, 'f', -1, bits), value.Interface())
	default:
		return nil, ErrDataEgressInvalid
	}
}

func (p *protector) redactNumericPhone(key string, protected any) (any, error) {
	if !isPhoneKey(key) {
		return protected, nil
	}
	return p.redactNumericPhoneValue(protected, true)
}

func (p *protector) redactNumericPhoneValue(value any, accountGrowth bool) (any, error) {
	digits := exactNumericDigits(value)
	if digits == "" || !plausibleCompactPhoneDigits(digits) {
		switch typed := value.(type) {
		case []any:
			for index := range typed {
				redacted, err := p.redactNumericPhoneValue(typed[index], accountGrowth)
				if err != nil {
					return nil, err
				}
				typed[index] = redacted
			}
		case []map[string]any:
			for index := range typed {
				redacted, err := p.redactNumericPhoneValue(typed[index], accountGrowth)
				if err != nil {
					return nil, err
				}
				typed[index] = redacted.(map[string]any)
			}
		case map[string]any:
			for _, key := range sortedKeysAny(typed) {
				redacted, err := p.redactNumericPhoneValue(typed[key], accountGrowth)
				if err != nil {
					return nil, err
				}
				typed[key] = redacted
			}
		case json.RawMessage:
			decoded, err := decodeJSONValue(typed)
			if err != nil {
				return nil, err
			}
			redacted, err := p.redactNumericPhoneValue(decoded, false)
			if err != nil {
				return nil, err
			}
			canonical, err := json.Marshal(redacted)
			if err != nil || len(canonical) > maxProtectStringBytes {
				return nil, ErrDataEgressInvalid
			}
			if accountGrowth && len(canonical) > len(typed) {
				if err := p.accountBytes(len(canonical) - len(typed)); err != nil {
					return nil, err
				}
			}
			return json.RawMessage(canonical), nil
		}
		return value, nil
	}
	const marker = "[REDACTED_PHONE]"
	if accountGrowth && len(marker) > len(digits) {
		if err := p.accountBytes(len(marker) - len(digits)); err != nil {
			return nil, err
		}
	}
	p.findings["phone"] = struct{}{}
	return marker, nil
}

func exactNumericDigits(value any) string {
	if number, ok := value.(json.Number); ok {
		return exactIntegerDigits(string(number))
	}
	rv := reflect.ValueOf(value)
	if !rv.IsValid() {
		return ""
	}
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return exactIntegerDigits(strconv.FormatInt(rv.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return exactIntegerDigits(strconv.FormatUint(rv.Uint(), 10))
	case reflect.Float32, reflect.Float64:
		return exactIntegerDigits(strconv.FormatFloat(rv.Float(), 'f', -1, rv.Type().Bits()))
	default:
		return ""
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
