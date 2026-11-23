package privacy

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

func isRestrictedKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	normalized = strings.NewReplacer("-", "_", " ", "_", ".", "_").Replace(normalized)
	compact := strings.ReplaceAll(normalized, "_", "")
	baseNormalized := normalized
	for _, suffix := range []string{"_value", "_data"} {
		if strings.HasSuffix(baseNormalized, suffix) {
			baseNormalized = strings.TrimSuffix(baseNormalized, suffix)
			break
		}
	}
	baseCompact := compact
	for _, suffix := range []string{"value", "data"} {
		if strings.HasSuffix(baseCompact, suffix) {
			baseCompact = strings.TrimSuffix(baseCompact, suffix)
			break
		}
	}
	for _, marker := range restrictedKeyMarkers {
		if marker == "token" {
			if isRestrictedTokenKey(normalized) || isRestrictedTokenKey(baseNormalized) {
				return true
			}
			continue
		}
		markerCompact := strings.ReplaceAll(marker, "_", "")
		if matchesRestrictedKeyMarker(normalized, compact, marker, markerCompact) ||
			matchesRestrictedKeyMarker(baseNormalized, baseCompact, marker, markerCompact) {
			return true
		}
	}
	return false
}

func matchesRestrictedKeyMarker(normalized, compact, marker, markerCompact string) bool {
	return normalized == marker || strings.HasSuffix(normalized, "_"+marker) ||
		compact == markerCompact || strings.HasSuffix(compact, markerCompact)
}

func isRestrictedTokenKey(normalized string) bool {
	compact := strings.ReplaceAll(normalized, "_", "")
	if normalized == "token" || strings.HasSuffix(normalized, "_token") || strings.HasSuffix(compact, "token") {
		return true
	}
	switch compact {
	case "tokenvalue", "tokensecret", "tokendata", "tokencredential":
		return true
	default:
		return false
	}
}

func sanitizeText(value string, manager *StandardPrivacyManager) (string, []string, error) {
	canonical, unresolved := canonicalizeTextEncodings(value)
	if unresolved || !utf8.ValidString(canonical) || restrictedText(canonical) {
		return "", nil, ErrDataEgressBlocked
	}
	labels := make([]string, 0, 2)
	protected := value
	emailRegex := defaultEmailRegex
	if manager != nil && manager.emailRegex != nil {
		emailRegex = manager.emailRegex
	}
	emailMatches := findEmailMatches(canonical, emailRegex)
	if len(emailMatches) > 0 {
		var replaced bool
		protected, replaced = redactCanonicalMatches(protected, emailMatches, "[REDACTED_EMAIL]")
		if !replaced {
			return "", nil, ErrDataEgressBlocked
		}
		labels = append(labels, "email")
	}
	phoneMatches := findPhoneMatches(canonical)
	if len(phoneMatches) > 0 {
		var replaced bool
		protected, replaced = redactCanonicalMatches(protected, phoneMatches, "[REDACTED_PHONE]")
		if !replaced {
			return "", nil, ErrDataEgressBlocked
		}
		labels = append(labels, "phone")
	}
	if len(labels) == 0 {
		// Canonicalization is only a detection aid. Preserve a clean caller
		// value byte-for-byte, including literal escaped code text.
		return value, nil, nil
	}
	remaining, unresolved := canonicalizeTextEncodings(protected)
	if unresolved || restrictedText(remaining) ||
		len(findEmailMatches(remaining, emailRegex)) > 0 || len(findPhoneMatches(remaining)) > 0 {
		return "", nil, ErrDataEgressBlocked
	}
	return protected, labels, nil
}

var defaultEmailRegex = regexp.MustCompile(`[\p{L}\p{N}\p{M}\p{So}._%+-]+@[\p{L}\p{N}\p{M}-]+(?:[.。．｡][\p{L}\p{N}\p{M}-]+)+`)

func findEmailMatches(value string, pattern *regexp.Regexp) []string {
	if pattern == nil {
		pattern = defaultEmailRegex
	}
	candidates := pattern.FindAllString(value, -1)
	matches := candidates[:0]
	for _, candidate := range candidates {
		at := strings.LastIndexByte(candidate, '@')
		if at <= 0 || at == len(candidate)-1 {
			continue
		}
		local := candidate[:at]
		if len(local) > 64 || strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
			continue
		}
		domain, err := idna.Lookup.ToASCII(candidate[at+1:])
		if err != nil || !validEmailDomain(domain) {
			continue
		}
		matches = append(matches, candidate)
	}
	return matches
}

func validEmailDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 || !strings.Contains(domain, ".") {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

func restrictedText(value string) bool {
	if ssnPattern.MatchString(value) || compactSSNPattern.MatchString(value) ||
		secretPattern.MatchString(value) || googleAPIKeyPattern.MatchString(value) || credentialURI.MatchString(value) ||
		hasRestrictedAssignment(value) || privateKeyPattern.MatchString(value) {
		return true
	}
	if hasValidCard(value) || hasValidIBAN(value) {
		return true
	}
	return looksLikeJWTText(value)
}

func hasRestrictedAssignment(value string) bool {
	if !strings.ContainsAny(value, ":=") {
		return false
	}
	for len(value) > 0 {
		indices := assignmentPattern.FindStringSubmatchIndex(value)
		if indices == nil {
			return false
		}
		for group := 2; group < len(indices); group += 2 {
			if indices[group] >= 0 && isRestrictedKey(value[indices[group]:indices[group+1]]) {
				return true
			}
		}
		value = value[indices[1]:]
	}
	return false
}

func findPhoneMatches(value string) []string {
	indices := phonePattern.FindAllStringIndex(value, -1)
	if len(indices) == 0 {
		return nil
	}
	matches := make([]string, 0, len(indices))
	for _, index := range indices {
		candidate := value[index[0]:index[1]]
		if (index[0] > 0 && isDigit(value[index[0]-1])) || (index[1] < len(value) && isDigit(value[index[1]])) {
			continue
		}
		if addr, err := netip.ParseAddr(candidate); err == nil && addr.Is4() {
			continue
		}
		if digitCount(candidate) < 10 || digitCount(candidate) > 15 || !plausiblePhone(candidate) {
			continue
		}
		if digitCount(candidate) == len(candidate) {
			if key, ok := precedingAssignmentKey(value, index[0]); ok && !isPhoneKey(key) {
				continue
			}
		}
		matches = append(matches, candidate)
	}
	return matches
}

func redactCanonicalMatches(original string, matches []string, marker string) (string, bool) {
	seen := make(map[string]struct{}, len(matches))
	variants := make(map[string]struct{}, len(matches)*(maxUnicodeEscapeDepth+1))
	replacements := make([]string, 0, len(matches)*(maxUnicodeEscapeDepth+1)*2)
	hasUnicodeEscapes := strings.Contains(original, `\u`)
	hasPercentEscapes := strings.Contains(original, "%")
	for _, match := range matches {
		if _, ok := seen[match]; ok {
			continue
		}
		seen[match] = struct{}{}
		if hasUnicodeEscapes {
			for slashCount := maxUnicodeEscapeDepth; slashCount >= 1; slashCount-- {
				candidate := unicodeEscapeVariant(match, slashCount)
				if candidate != "" {
					if _, ok := variants[candidate]; !ok {
						variants[candidate] = struct{}{}
						replacements = append(replacements, candidate, marker)
					}
				}
			}
		}
		if hasPercentEscapes {
			for _, candidate := range percentEscapeVariants(match) {
				if _, ok := variants[candidate]; !ok {
					variants[candidate] = struct{}{}
					replacements = append(replacements, candidate, marker)
				}
			}
		}
		if _, ok := variants[match]; !ok {
			variants[match] = struct{}{}
			replacements = append(replacements, match, marker)
		}
	}
	if len(replacements) == 0 {
		return original, false
	}
	protected := strings.NewReplacer(replacements...).Replace(original)
	return protected, protected != original
}
func precedingAssignmentKey(value string, start int) (string, bool) {
	if start <= 0 {
		return "", false
	}
	windowStart := max(0, start-160)
	prefix := strings.TrimRight(value[windowStart:start], " \t")
	indices := assignmentPattern.FindAllStringSubmatchIndex(prefix, -1)
	if len(indices) == 0 || indices[len(indices)-1][1] != len(prefix) {
		return "", false
	}
	last := indices[len(indices)-1]
	for group := 2; group < len(last); group += 2 {
		if last[group] >= 0 {
			return prefix[last[group]:last[group+1]], true
		}
	}
	return "", false
}

func isPhoneKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	normalized = strings.NewReplacer("-", "_", " ", "_", ".", "_").Replace(normalized)
	compact := strings.ReplaceAll(normalized, "_", "")
	switch compact {
	case "phone", "phonenumber", "mobile", "mobilephone", "telephone", "tel", "contactphone":
		return true
	default:
		return strings.HasSuffix(normalized, "_phone") || strings.HasSuffix(normalized, "_phone_number")
	}
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
	if strings.HasPrefix(value, "+") || strings.HasPrefix(value, "00") || strings.HasPrefix(value, "(") {
		return true
	}
	if digitCount(value) == len(value) {
		return plausibleCompactPhoneDigits(value)
	}
	// A four-digit first group is common in dates and identifiers, but not in
	// the local phone formats this boundary recognizes.
	firstGroup := value
	if separator := strings.IndexAny(firstGroup, " .-"); separator >= 0 {
		firstGroup = firstGroup[:separator]
	}
	return len(firstGroup) <= 3
}

func plausibleCompactPhoneDigits(value string) bool {
	for index := range value {
		if !isDigit(value[index]) {
			return false
		}
	}
	if len(value) == 10 {
		return value[0] >= '2' && value[0] <= '9' && value[3] >= '2' && value[3] <= '9'
	}
	if len(value) == 11 && value[0] == '1' {
		return value[1] >= '2' && value[1] <= '9' && value[4] >= '2' && value[4] <= '9'
	}
	if len(value) < 11 || len(value) > 15 || value[0] == '0' || looksLikeDateIdentifier(value) {
		return false
	}
	if gtin13Valid(value) {
		return false
	}
	// A 15-digit Luhn-valid value is much more likely to be the IMEI-like
	// identifier covered by this package's existing non-payment control.
	return len(value) != 15 || !luhnValid(value)
}

func gtin13Valid(value string) bool {
	if len(value) != 13 {
		return false
	}
	sum := 0
	for index := 0; index < 12; index++ {
		if !isDigit(value[index]) {
			return false
		}
		weight := 1
		if index%2 == 1 {
			weight = 3
		}
		sum += int(value[index]-'0') * weight
	}
	return isDigit(value[12]) && int(value[12]-'0') == (10-sum%10)%10
}

func looksLikeDateIdentifier(value string) bool {
	if len(value) < len("20060102") {
		return false
	}
	date, err := time.Parse("20060102", value[:8])
	return err == nil && date.Year() >= 1900 && date.Year() <= 2100
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
		if len(digits) >= 12 && len(digits) <= 19 && luhnValid(digits) &&
			(isKnownPaymentCardNumber(digits) || paymentContext.MatchString(value)) {
			return true
		}
	}
	return false
}

func hasValidNumericCard(value string) bool {
	if len(value) < 12 || len(value) > 19 {
		return false
	}
	for index := 0; index < len(value); index++ {
		if !isDigit(value[index]) {
			return false
		}
	}
	return luhnValid(value) && isKnownPaymentCardNumber(value)
}

func isKnownPaymentCardNumber(value string) bool {
	length := len(value)
	switch {
	case value[0] == '4' && (length == 13 || length == 16 || length == 19):
		return true
	case length == 15 && (strings.HasPrefix(value, "34") || strings.HasPrefix(value, "37")):
		return true
	case length == 16 && (prefixBetween(value, 2, 51, 55) || prefixBetween(value, 4, 2221, 2720)):
		return true
	case length == 14 && (prefixBetween(value, 3, 300, 305) || strings.HasPrefix(value, "36") ||
		strings.HasPrefix(value, "38") || strings.HasPrefix(value, "39")):
		return true
	case (length == 16 || length == 19) && (strings.HasPrefix(value, "6011") ||
		strings.HasPrefix(value, "65") || prefixBetween(value, 3, 644, 649) ||
		prefixBetween(value, 6, 622126, 622925)):
		return true
	case length >= 16 && length <= 19 && (prefixBetween(value, 4, 3528, 3589) ||
		strings.HasPrefix(value, "62")):
		return true
	case length >= 12 && length <= 19 && (prefixBetween(value, 8, 63900000, 63909999) ||
		prefixBetween(value, 8, 67000000, 67999999)):
		return true
	default:
		return false
	}
}

func prefixBetween(value string, digits, minimum, maximum int) bool {
	if len(value) < digits {
		return false
	}
	prefix, err := strconv.Atoi(value[:digits])
	return err == nil && prefix >= minimum && prefix <= maximum
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
		if !validIBANCountryLength(compact) || ibanMod97(compact) != 1 {
			continue
		}
		return true
	}
	return false
}

// validIBANCountryLength reflects SWIFT IBAN Registry Release 102 (June 2026).
func validIBANCountryLength(value string) bool {
	if len(value) < 2 {
		return false
	}
	expected := 0
	switch value[:2] {
	case "NO":
		expected = 15
	case "BE":
		expected = 16
	case "DK", "FI", "FK", "FO", "GL", "NL", "SD":
		expected = 18
	case "MK", "SI":
		expected = 19
	case "AT", "BA", "EE", "KZ", "LT", "LU", "MN", "XK":
		expected = 20
	case "CH", "HR", "LI", "LV":
		expected = 21
	case "BG", "BH", "CR", "DE", "GB", "GE", "IE", "ME", "RS", "VA":
		expected = 22
	case "AE", "GI", "IL", "IQ", "OM", "SO", "TL":
		expected = 23
	case "AD", "CZ", "ES", "MD", "PK", "RO", "SA", "SE", "SK", "TN", "VG":
		expected = 24
	case "LY", "PT", "ST":
		expected = 25
	case "IS", "TR":
		expected = 26
	case "BI", "DJ", "FR", "GR", "IT", "MC", "MR", "SM":
		expected = 27
	case "AL", "AZ", "BY", "CY", "DO", "GT", "HN", "HU", "LB", "NI", "PL", "SV":
		expected = 28
	case "BR", "EG", "PS", "QA", "UA":
		expected = 29
	case "JO", "KW", "MU", "YE":
		expected = 30
	case "MT", "SC":
		expected = 31
	case "LC":
		expected = 32
	case "RU":
		expected = 33
	default:
		return false
	}
	return len(value) == expected
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
	for _, match := range jwtPattern.FindAllStringSubmatch(value, -1) {
		if jwtJSONSegment(match[1]) && jwtJSONSegment(match[2]) {
			return true
		}
	}
	return false
}

func jwtJSONSegment(segment string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return false
	}
	var object map[string]json.RawMessage
	return json.Unmarshal(decoded, &object) == nil && object != nil
}
