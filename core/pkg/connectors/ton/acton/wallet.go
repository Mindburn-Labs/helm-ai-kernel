package acton

import (
	"fmt"
	"regexp"
	"strings"
)

var mnemonicPattern = regexp.MustCompile(`(?i)\b(mnemonic|seed phrase|private[_ -]?key|secret[_ -]?key)\b`)

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
	if mnemonicPattern.MatchString(env.WalletRef) {
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
		if mnemonicPattern.MatchString(value) {
			return true
		}
	}
	if env.Metadata != nil {
		for key, raw := range env.Metadata {
			if mnemonicPattern.MatchString(key) || mnemonicPattern.MatchString(fmt.Sprint(raw)) {
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
