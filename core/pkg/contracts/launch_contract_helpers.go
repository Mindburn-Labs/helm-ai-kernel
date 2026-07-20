package contracts

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

// launchConstantEqual compares authority-relevant identifiers without leaking
// which byte differed. Route validation and dispatch authorization share this
// primitive so the provider-neutral layer does not depend on executable
// effect-envelope implementation files.
func launchConstantEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func validLaunchSHA256(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 {
		return false
	}
	digest := strings.TrimPrefix(value, "sha256:")
	if digest != strings.ToLower(digest) {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}

// launchTupleKey hex-encodes each authority-relevant component before adding a
// sentinel. The encoded values cannot contain the sentinel, so arbitrary input
// remains unambiguous while component-wise lexical ordering is preserved.
func launchTupleKey(values ...string) string {
	var key strings.Builder
	for _, value := range values {
		key.WriteString(hex.EncodeToString([]byte(value)))
		key.WriteByte(0)
	}
	return key.String()
}

func launchEffectIsProviderMutation(effectID string) bool {
	switch effectID {
	case EffectTypeProviderProvision, EffectTypeDeployProductionActivate, EffectTypeProviderRollback, EffectTypeProviderTeardown:
		return true
	default:
		return false
	}
}
