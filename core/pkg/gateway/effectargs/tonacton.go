package effectargs

import "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"

// The TON Acton effect types (helm-tracker#266). The gateway performs local,
// fork and testnet Acton operations. The effect types below are refused at
// admission, whatever adapters are configured.

// TONActonPrefix starts every Acton effect type.
const TONActonPrefix = "ton.acton."

// tonActonMainnet lists the Acton effect types that operate on TON mainnet.
var tonActonMainnet = map[string]struct{}{
	TONActonPrefix + "library.publish_mainnet": {},
	TONActonPrefix + "library.topup_mainnet":   {},
	TONActonPrefix + "script.mainnet":          {},
	TONActonPrefix + "source.verify_mainnet":   {},
}

// tonActonKeyWithTenantCode lists the effect types that would execute
// tenant-authored Tolk (a script) in a process that holds a signing key. Acton
// scripts can read the environment and files, so no key may share a process
// with one until a signer keeps the key out of the tenant process.
var tonActonKeyWithTenantCode = map[string]struct{}{
	TONActonPrefix + "script.testnet": {},
}

// IsTONActonMainnet reports whether effectType is a TON Acton operation on
// mainnet.
func IsTONActonMainnet(effectType string) bool {
	_, ok := tonActonMainnet[effectType]
	return ok
}

// IsTONActonKeyWithTenantCode reports whether effectType is refused because it
// runs tenant code next to a signing key.
func IsTONActonKeyWithTenantCode(effectType string) bool {
	_, ok := tonActonKeyWithTenantCode[effectType]
	return ok
}

// TONActonRefusal returns the reason an Acton effect type is refused before
// any mandate, adapter or database is consulted, and false for every other
// effect type.
func TONActonRefusal(effectType string) (contracts.ReasonCode, string, bool) {
	switch {
	case IsTONActonMainnet(effectType):
		return contracts.ReasonTONMainnetRefused,
			effectType + " operates on TON mainnet, which spends real TON; this gateway performs local, fork and testnet Acton operations only", true
	case IsTONActonKeyWithTenantCode(effectType):
		return contracts.ReasonTONTenantCodeWithKeyRefused,
			effectType + " would run tenant-authored code in a process that holds a signing key; it is refused until a signer keeps the key out of that process", true
	}
	return "", "", false
}
