package hostaction

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

type Options struct {
	Clock      func() time.Time
	TimeWindow time.Duration
}

func Correlate(helmReceipts []contracts.Receipt, chain *contracts.ExternalReceiptChain, opts Options) []contracts.HostCorrelationResult {
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.TimeWindow == 0 {
		opts.TimeWindow = 5 * time.Minute
	}
	if chain == nil || len(chain.Receipts) == 0 {
		return missingHostReceiptResults(helmReceipts, opts)
	}

	var results []contracts.HostCorrelationResult
	matchedHELM := map[string]bool{}
	for _, hostReceipt := range chain.Receipts {
		result := correlateOne(helmReceipts, hostReceipt, opts)
		if result.HELMReceiptID != "" {
			matchedHELM[result.HELMReceiptID] = true
		}
		results = append(results, result)
	}
	for _, receipt := range helmReceipts {
		if isNetworkReceipt(receipt) && !matchedHELM[receipt.ReceiptID] {
			results = append(results, contracts.HostCorrelationResult{
				SchemaVersion:    contracts.HostCorrelationResultVersion,
				Status:           contracts.HostCorrelationMissingHostReceipt,
				ReasonCode:       string(contracts.ReasonHostReceiptMissing),
				HELMReceiptID:    receipt.ReceiptID,
				HELMDecisionID:   receipt.DecisionID,
				HELMSandboxLease: receipt.SandboxLeaseID,
				Details:          "HELM network-authority receipt has no corresponding host evidence",
				CorrelatedAt:     opts.Clock().UTC(),
			})
		}
	}
	return results
}

func correlateOne(helmReceipts []contracts.Receipt, host contracts.ExternalHostReceipt, opts Options) contracts.HostCorrelationResult {
	result := contracts.HostCorrelationResult{
		SchemaVersion:   contracts.HostCorrelationResultVersion,
		HostReceiptID:   host.ReceiptID,
		HostReceiptHash: host.ReceiptHash,
		ObservedEvent:   &host.Event,
		CorrelatedAt:    opts.Clock().UTC(),
	}

	match, method, confidence := findBestMatch(helmReceipts, host, opts.TimeWindow)
	if match == nil {
		result.Status = contracts.HostCorrelationUncorrelatedHostEgress
		result.ReasonCode = string(contracts.ReasonHostEgressWithoutIntent)
		result.CorrelationMethod = "none"
		result.Details = "host egress has no matching HELM intent or receipt"
		result.BoundaryDrift = buildBoundaryDrift(result, nil, string(contracts.ReasonHostEgressWithoutIntent), opts.Clock)
		return result
	}

	result.HELMReceiptID = match.ReceiptID
	result.HELMDecisionID = match.DecisionID
	result.HELMSandboxLease = match.SandboxLeaseID
	result.CorrelationMethod = method
	result.Confidence = confidence

	if deniedReceipt(*match) {
		result.Status = contracts.HostCorrelationPolicyDeniedHostEgress
		result.ReasonCode = string(contracts.ReasonHostEgressAfterDeny)
		result.Details = "host egress was observed after HELM denied the corresponding action"
		result.BoundaryDrift = buildBoundaryDrift(result, match, string(contracts.ReasonHostEgressAfterDeny), opts.Clock)
		return result
	}

	if destinationMismatch(*match, host) {
		result.Status = contracts.HostCorrelationPartiallyCorrelated
		result.ReasonCode = string(contracts.ReasonHostDestinationMismatch)
		result.Details = "host destination differs from HELM receipt destination metadata"
		result.BoundaryDrift = buildBoundaryDrift(result, match, string(contracts.ReasonHostDestinationMismatch), opts.Clock)
		return result
	}

	if volumeExceeded(*match, host) {
		result.Status = contracts.HostCorrelationPartiallyCorrelated
		result.ReasonCode = string(contracts.ReasonHostVolumeExceeded)
		result.Details = "host egress byte volume exceeds HELM receipt metadata ceiling"
		result.BoundaryDrift = buildBoundaryDrift(result, match, string(contracts.ReasonHostVolumeExceeded), opts.Clock)
		return result
	}

	result.Status = contracts.HostCorrelationCorrelated
	result.Details = "host evidence correlates with HELM authority receipt"
	return result
}

func findBestMatch(receipts []contracts.Receipt, host contracts.ExternalHostReceipt, window time.Duration) (*contracts.Receipt, string, float64) {
	for i := range receipts {
		if exactIdentityMatch(receipts[i], host) {
			return &receipts[i], "identity", 1.0
		}
	}
	for i := range receipts {
		if processMatch(receipts[i], host) {
			return &receipts[i], "process", 0.85
		}
	}
	for i := range receipts {
		if destinationTimeMatch(receipts[i], host, window) {
			return &receipts[i], "destination_time", 0.65
		}
	}
	return nil, "", 0
}

func exactIdentityMatch(receipt contracts.Receipt, host contracts.ExternalHostReceipt) bool {
	if host.WorkloadID != "" && metadataString(receipt, "workload_id") == host.WorkloadID {
		return true
	}
	if host.SandboxLeaseID != "" && (receipt.SandboxLeaseID == host.SandboxLeaseID || metadataString(receipt, "sandbox_lease_id") == host.SandboxLeaseID) {
		return true
	}
	if host.AgentID != "" && (receipt.ExecutorID == host.AgentID || metadataString(receipt, "agent_id") == host.AgentID) {
		return true
	}
	return false
}

func processMatch(receipt contracts.Receipt, host contracts.ExternalHostReceipt) bool {
	if explicitIdentityConflict(receipt, host) {
		return false
	}
	process := metadataString(receipt, "process_identity")
	if process == "" {
		return false
	}
	if host.ProcessIdentity == process {
		return true
	}
	for _, ancestor := range host.ProcessAncestry {
		if ancestor == process {
			return true
		}
	}
	return false
}

func destinationTimeMatch(receipt contracts.Receipt, host contracts.ExternalHostReceipt, window time.Duration) bool {
	if !isNetworkReceipt(receipt) {
		return false
	}
	if explicitIdentityConflict(receipt, host) {
		return false
	}
	if !receipt.Timestamp.IsZero() {
		delta := receipt.Timestamp.Sub(host.Event.Timestamp)
		if delta < 0 {
			delta = -delta
		}
		if delta > window {
			return false
		}
	}
	return destinationFieldsMatch(receipt, host)
}

func destinationFieldsMatch(receipt contracts.Receipt, host contracts.ExternalHostReceipt) bool {
	ip := metadataString(receipt, "destination_ip")
	hostName := metadataString(receipt, "destination_host")
	port := metadataString(receipt, "destination_port")
	protocol := metadataString(receipt, "protocol")
	if ip != "" && host.Event.DestinationIP != "" && ip != host.Event.DestinationIP {
		return false
	}
	if hostName != "" && host.Event.DestinationHost != "" && !strings.EqualFold(hostName, host.Event.DestinationHost) {
		return false
	}
	if port != "" && port != strconv.Itoa(host.Event.DestinationPort) {
		return false
	}
	if protocol != "" && !strings.EqualFold(protocol, host.Event.Protocol) {
		return false
	}
	return ip != "" || hostName != "" || port != "" || protocol != ""
}

func explicitIdentityConflict(receipt contracts.Receipt, host contracts.ExternalHostReceipt) bool {
	if host.WorkloadID != "" {
		if receiptWorkload := metadataString(receipt, "workload_id"); receiptWorkload != "" && receiptWorkload != host.WorkloadID {
			return true
		}
	}
	if host.SandboxLeaseID != "" {
		receiptLease := receipt.SandboxLeaseID
		if receiptLease == "" {
			receiptLease = metadataString(receipt, "sandbox_lease_id")
		}
		if receiptLease != "" && receiptLease != host.SandboxLeaseID {
			return true
		}
	}
	if host.AgentID != "" {
		receiptAgent := receipt.ExecutorID
		if receiptAgent == "" {
			receiptAgent = metadataString(receipt, "agent_id")
		}
		if receiptAgent != "" && receiptAgent != host.AgentID {
			return true
		}
	}
	return false
}

func destinationMismatch(receipt contracts.Receipt, host contracts.ExternalHostReceipt) bool {
	ip := metadataString(receipt, "destination_ip")
	hostName := metadataString(receipt, "destination_host")
	port := metadataString(receipt, "destination_port")
	protocol := metadataString(receipt, "protocol")
	return (ip != "" && host.Event.DestinationIP != "" && ip != host.Event.DestinationIP) ||
		(hostName != "" && host.Event.DestinationHost != "" && !strings.EqualFold(hostName, host.Event.DestinationHost)) ||
		(port != "" && port != strconv.Itoa(host.Event.DestinationPort)) ||
		(protocol != "" && !strings.EqualFold(protocol, host.Event.Protocol))
}

func volumeExceeded(receipt contracts.Receipt, host contracts.ExternalHostReceipt) bool {
	limitText := metadataString(receipt, "max_egress_bytes")
	if limitText == "" {
		return false
	}
	limit, err := strconv.ParseInt(limitText, 10, 64)
	if err != nil || limit <= 0 {
		return false
	}
	return host.Event.BytesSent+host.Event.BytesReceived > limit
}

func deniedReceipt(receipt contracts.Receipt) bool {
	return strings.EqualFold(receipt.Verdict, string(contracts.VerdictDeny)) ||
		strings.EqualFold(receipt.Status, string(contracts.VerdictDeny)) ||
		strings.EqualFold(receipt.Status, "DENIED") ||
		strings.EqualFold(receipt.ReasonCode, string(contracts.ReasonDataEgressBlocked))
}

func isNetworkReceipt(receipt contracts.Receipt) bool {
	switch receipt.Type {
	case contracts.ReceiptTypeNetworkEgressAttempt, contracts.ReceiptTypeNetworkEgressAllowed,
		contracts.ReceiptTypeNetworkEgressDenied, contracts.ReceiptTypeNetworkEgressUncorr:
		return true
	}
	return receipt.EffectType == contracts.EffectTypeWorkstationNetworkEgress ||
		strings.Contains(strings.ToUpper(receipt.EffectID), "NETWORK") ||
		strings.Contains(strings.ToUpper(receipt.EffectID), "EGRESS") ||
		strings.EqualFold(metadataString(receipt, "effect_type"), contracts.EffectTypeWorkstationNetworkEgress)
}

func metadataString(receipt contracts.Receipt, key string) string {
	if receipt.Metadata == nil {
		return ""
	}
	value, ok := receipt.Metadata[key]
	if !ok || value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatInt(int64(v), 10)
	default:
		return fmt.Sprint(v)
	}
}

func missingHostReceiptResults(receipts []contracts.Receipt, opts Options) []contracts.HostCorrelationResult {
	var out []contracts.HostCorrelationResult
	for _, receipt := range receipts {
		if !isNetworkReceipt(receipt) {
			continue
		}
		out = append(out, contracts.HostCorrelationResult{
			SchemaVersion:  contracts.HostCorrelationResultVersion,
			Status:         contracts.HostCorrelationMissingHostReceipt,
			ReasonCode:     string(contracts.ReasonHostReceiptMissing),
			HELMReceiptID:  receipt.ReceiptID,
			HELMDecisionID: receipt.DecisionID,
			Details:        "HELM network-authority receipt has no host evidence chain to verify",
			CorrelatedAt:   opts.Clock().UTC(),
		})
	}
	return out
}

func buildBoundaryDrift(result contracts.HostCorrelationResult, helm *contracts.Receipt, reasonCode string, clock func() time.Time) *contracts.BoundaryDriftReceipt {
	receipt := contracts.BoundaryDriftReceipt{
		ReceiptVersion:  contracts.BoundaryDriftReceiptVersion,
		Type:            contracts.ReceiptTypeBoundaryDrift,
		ReasonCode:      reasonCode,
		Severity:        "high",
		HostReceiptID:   result.HostReceiptID,
		HostReceiptHash: result.HostReceiptHash,
		HELMReceiptID:   result.HELMReceiptID,
		HELMDecisionID:  result.HELMDecisionID,
		CreatedAt:       clock().UTC(),
	}
	if helm != nil {
		receipt.PolicyHash = helm.PolicyHash
	}
	receipt.ReceiptID = "boundary_drift:" + shortHash(result.HostReceiptHash+result.HELMReceiptID+reasonCode)
	hashable := receipt
	hashable.ReceiptHash = ""
	hash, err := canonicalize.CanonicalHash(hashable)
	if err == nil {
		receipt.ReceiptHash = "sha256:" + hash
	}
	return &receipt
}

func shortHash(input string) string {
	if input == "" {
		input = time.Now().UTC().Format(time.RFC3339Nano)
	}
	return canonicalize.HashBytes([]byte(input))[:16]
}
