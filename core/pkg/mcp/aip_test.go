package mcp

import (
	"fmt"
	"time"
)

func aipFixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func aipTestSignatureVerifier(claim DelegationClaim) error {
	if claim.Signature == "sig-fixture" {
		return nil
	}
	return fmt.Errorf("unexpected test signature %q", claim.Signature)
}
