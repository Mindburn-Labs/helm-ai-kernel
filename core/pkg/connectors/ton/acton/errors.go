package acton

import "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"

// ReasonCode is the stable reason code carried by ActonReceipt. Every code
// except OK takes its wire value from the one registry in contracts/verdict.go
// (R4), so the connector and the gateway cannot disagree on a code.
type ReasonCode string

const (
	ReasonOK                             ReasonCode = "OK"
	ReasonUnknownCommand                 ReasonCode = ReasonCode(contracts.ReasonTONActonUnknownCommand)
	ReasonUnsupportedVersion             ReasonCode = ReasonCode(contracts.ReasonTONActonUnsupportedVersion)
	ReasonCompilerUnpinned               ReasonCode = ReasonCode(contracts.ReasonTONTolkCompilerUnpinned)
	ReasonCompilerMismatch               ReasonCode = ReasonCode(contracts.ReasonTONTolkCompilerMismatch)
	ReasonArgvRejected                   ReasonCode = ReasonCode(contracts.ReasonTONActonArgvRejected)
	ReasonRawShellForbidden              ReasonCode = ReasonCode(contracts.ReasonTONActonRawShellForbidden)
	ReasonGenericMainnetScriptDenied     ReasonCode = ReasonCode(contracts.ReasonTONActonGenericMainnetScriptDenied)
	ReasonScriptManifestRequired         ReasonCode = ReasonCode(contracts.ReasonTONScriptManifestRequired)
	ReasonScriptManifestHashMismatch     ReasonCode = ReasonCode(contracts.ReasonTONScriptManifestHashMismatch)
	ReasonExpectedEffectMismatch         ReasonCode = ReasonCode(contracts.ReasonTONExpectedEffectMismatch)
	ReasonSpendCeilingExceeded           ReasonCode = ReasonCode(contracts.ReasonTONSpendCeilingExceeded)
	ReasonMainnetRequiresApproval        ReasonCode = ReasonCode(contracts.ReasonTONMainnetRequiresApproval)
	ReasonApprovalCeremonyRequired       ReasonCode = ReasonCode(contracts.ReasonTONApprovalCeremonyRequired)
	ReasonWalletRefRequired              ReasonCode = ReasonCode(contracts.ReasonTONWalletRefRequired)
	ReasonPlaintextMnemonicForbidden     ReasonCode = ReasonCode(contracts.ReasonTONPlaintextMnemonicForbidden)
	ReasonNetworkGrantRequired           ReasonCode = ReasonCode(contracts.ReasonTONNetworkGrantRequired)
	ReasonSandboxGrantRequired           ReasonCode = ReasonCode(contracts.ReasonTONSandboxGrantRequired)
	ReasonSourceVerificationRequired     ReasonCode = ReasonCode(contracts.ReasonTONSourceVerificationRequired)
	ReasonVerifyDryRunRequired           ReasonCode = ReasonCode(contracts.ReasonTONVerifyDryRunRequired)
	ReasonVerifyBytecodeMismatch         ReasonCode = ReasonCode(contracts.ReasonTONVerifyBytecodeMismatch)
	ReasonCoverageThresholdFailed        ReasonCode = ReasonCode(contracts.ReasonTONCoverageThresholdFailed)
	ReasonMutationThresholdFailed        ReasonCode = ReasonCode(contracts.ReasonTONMutationThresholdFailed)
	ReasonLibraryMainnetRequiresApproval ReasonCode = ReasonCode(contracts.ReasonTONLibraryMainnetRequiresApproval)
	ReasonLibrarySpendCeilingExceeded    ReasonCode = ReasonCode(contracts.ReasonTONLibrarySpendCeilingExceeded)
	ReasonConnectorContractDrift         ReasonCode = ReasonCode(contracts.ReasonConnectorContractDrift)
	ReasonComputeGasExhausted            ReasonCode = ReasonCode(contracts.ReasonComputeGasExhausted)
	ReasonComputeTimeExhausted           ReasonCode = ReasonCode(contracts.ReasonComputeTimeExhausted)
)

func (r ReasonCode) String() string {
	return string(r)
}

func allReasonCodes() []ReasonCode {
	return []ReasonCode{
		ReasonOK,
		ReasonUnknownCommand,
		ReasonUnsupportedVersion,
		ReasonCompilerUnpinned,
		ReasonCompilerMismatch,
		ReasonArgvRejected,
		ReasonRawShellForbidden,
		ReasonGenericMainnetScriptDenied,
		ReasonScriptManifestRequired,
		ReasonScriptManifestHashMismatch,
		ReasonExpectedEffectMismatch,
		ReasonSpendCeilingExceeded,
		ReasonMainnetRequiresApproval,
		ReasonApprovalCeremonyRequired,
		ReasonWalletRefRequired,
		ReasonPlaintextMnemonicForbidden,
		ReasonNetworkGrantRequired,
		ReasonSandboxGrantRequired,
		ReasonSourceVerificationRequired,
		ReasonVerifyDryRunRequired,
		ReasonVerifyBytecodeMismatch,
		ReasonCoverageThresholdFailed,
		ReasonMutationThresholdFailed,
		ReasonLibraryMainnetRequiresApproval,
		ReasonLibrarySpendCeilingExceeded,
		ReasonConnectorContractDrift,
		ReasonComputeGasExhausted,
		ReasonComputeTimeExhausted,
	}
}
