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

func launchEffectIsProviderMutation(effectID string) bool {
	switch effectID {
	case EffectTypeProviderProvision, EffectTypeDeployProductionActivate, EffectTypeProviderRollback, EffectTypeProviderTeardown:
		return true
	default:
		return false
	}
}
