package acton

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

var mnemonicPattern = regexp.MustCompile(`(?i)\b(mnemonic|seed phrase|private[_ -]?key|secret[_ -]?key)\b`)
var walletRefPattern = regexp.MustCompile(`^wallet:[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,120}$`)

func ValidateWalletPolicy(env *ActonCommandEnvelope) error {
	spec := commandSpecs[env.ActionURN]
	if !spec.RequiresWallet {
		return nil
	}
	if env.WalletRef == "" {
		return fmt.Errorf("%s", ReasonWalletRefRequired)
	}
	if !strings.HasPrefix(env.WalletRef, "wallet:") {
		return fmt.Errorf("%s: wallet ref must be opaque", ReasonWalletRefRequired)
	}
	if !walletRefPattern.MatchString(env.WalletRef) {
		return fmt.Errorf("%s: wallet ref must be a single opaque identifier", ReasonWalletRefRequired)
	}
	if mnemonicPattern.MatchString(env.WalletRef) || containsLikelySeedPhrase(env.WalletRef) {
		return fmt.Errorf("%s", ReasonPlaintextMnemonicForbidden)
	}
	return nil
}

func HasPlaintextSecretRisk(env *ActonCommandEnvelope) bool {
	if env == nil {
		return false
	}
	values := append([]string{}, env.Argv...)
	values = append(values, env.WalletRef)
	for _, value := range values {
		if mnemonicPattern.MatchString(value) || containsLikelySeedPhrase(value) {
			return true
		}
	}
	if env.Metadata != nil {
		for key, raw := range env.Metadata {
			value := fmt.Sprint(raw)
			if mnemonicPattern.MatchString(key) || mnemonicPattern.MatchString(value) || containsLikelySeedPhrase(value) {
				return true
			}
		}
	}
	return false
}

func RedactWalletRef(ref string) string {
	if ref == "" {
		return ""
	}
	if len(ref) <= len("wallet:")+6 {
		return "wallet:REDACTED"
	}
	return ref[:len("wallet:")+3] + "...REDACTED"
}

func containsLikelySeedPhrase(value string) bool {
	words := seedPhraseCandidateWords(value)
	if len(words) < 12 {
		return false
	}
	for _, n := range []int{12, 24} {
		if len(words) >= n {
			return true
		}
	}
	return false
}

func seedPhraseCandidateWords(value string) []string {
	fields := strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return !unicode.IsLetter(r)
	})
	words := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if len(field) < 2 || len(field) > 16 {
			return nil
		}
		words = append(words, field)
	}
	return words
}
