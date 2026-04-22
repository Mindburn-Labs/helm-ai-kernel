package serving

import "errors"

// KVCachePolicy defines the quantization and allocation strategy for the underlying inference engine.
type KVCachePolicy string

const (
	// KVPolicyFP16 represents the canonical unquantized baseline.
	// Used for high-precision analytical steps like Critic review.
	KVPolicyFP16 KVCachePolicy = "fp16"

	// KVPolicyFP8 represents standard weight/activation compression.
	KVPolicyFP8 KVCachePolicy = "fp8"

	// KVPolicyQJLLike represents 1-bit JL transform bias-correcting layer compression.
	// Used for long-horizon planning with minimal degradation.
	KVPolicyQJLLike KVCachePolicy = "qjl_like"

	// KVPolicyTurboQuant represents extreme online vector compression applied
	// to the KV-cache. Permitted only for trace generation or replay logs where 
	// >4x sizing constraints dominate marginal accuracy shifts.
	KVPolicyTurboQuant KVCachePolicy = "turboquant_candidate"
)

var ErrUnsupportedPolicy = errors.New("serving: unsupported kv cache policy requested")

// ValidatePolicy checks if the engine can satisfy the requested kv-cache behavior.
func ValidatePolicy(policy KVCachePolicy) error {
	switch policy {
	case KVPolicyFP16, KVPolicyFP8, KVPolicyQJLLike, KVPolicyTurboQuant:
		return nil
	default:
		return ErrUnsupportedPolicy
	}
}
