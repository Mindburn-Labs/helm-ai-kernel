package effectargs

// The TON Acton effect types (helm-tracker#266). The gateway performs local,
// fork and testnet Acton operations only; the effect types below spend real TON
// and are refused at admission, whatever adapters are configured.

// TONActonPrefix starts every Acton effect type.
const TONActonPrefix = "ton.acton."

// tonActonMainnet lists the Acton effect types that operate on TON mainnet.
var tonActonMainnet = map[string]struct{}{
	TONActonPrefix + "library.publish_mainnet": {},
	TONActonPrefix + "library.topup_mainnet":   {},
	TONActonPrefix + "script.mainnet":          {},
	TONActonPrefix + "source.verify_mainnet":   {},
}

// IsTONActonMainnet reports whether effectType is a TON Acton operation on
// mainnet. Admission refuses it with contracts.ReasonTONMainnetRefused before it
// reads a mandate or an adapter: mainnet spends real TON.
func IsTONActonMainnet(effectType string) bool {
	_, ok := tonActonMainnet[effectType]
	return ok
}
