package admission

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/gateway/effectargs"
)

var (
	effectTypePattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	unitPattern       = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)
)

const (
	maxTargetBytes  = 512
	maxWorkRefBytes = 255
)

// validateProposal refuses a malformed request before anything is written,
// and returns the parsed arguments.
func validateProposal(in ProposeInput) (map[string]any, error) {
	bad := func(format string, args ...any) error {
		return refuse(CodeInvalidArgument, contracts.ReasonSchemaViolation, format, args...)
	}
	if n := len(in.IdempotencyKey); n < 1 || n > 255 || !utf8.ValidString(in.IdempotencyKey) {
		return nil, bad("idempotency_key must be 1 to 255 bytes of UTF-8")
	}
	if in.MandateID != "" {
		if _, err := uuid.Parse(in.MandateID); err != nil || strings.ToLower(in.MandateID) != in.MandateID {
			return nil, bad("mandate_id must be a lowercase UUID")
		}
	}
	if !effectTypePattern.MatchString(in.EffectType) {
		return nil, bad("effect.effect_type %q is not an effect type", in.EffectType)
	}
	if in.Target == "" || len(in.Target) > maxTargetBytes || !utf8.ValidString(in.Target) ||
		strings.IndexFunc(in.Target, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return nil, bad("effect.target must be 1 to %d bytes of UTF-8 without control characters", maxTargetBytes)
	}
	authorityChange := strings.HasPrefix(in.EffectType, "helm.authority.")
	switch {
	case in.CommitmentID != "" && in.CaseID != "":
		return nil, bad("set one of commitment_id and case_id")
	case in.CommitmentID == "" && in.CaseID == "" && !authorityChange:
		return nil, bad("commitment_id or case_id is required")
	case len(in.CommitmentID) > maxWorkRefBytes || len(in.CaseID) > maxWorkRefBytes:
		return nil, bad("commitment_id and case_id are at most %d bytes", maxWorkRefBytes)
	}
	units := map[string]struct{}{}
	for _, q := range in.Quote {
		if !unitPattern.MatchString(q.Unit) {
			return nil, bad("quote unit %q is not a unit", q.Unit)
		}
		if _, dup := units[q.Unit]; dup {
			return nil, bad("quote unit %q repeats", q.Unit)
		}
		units[q.Unit] = struct{}{}
		if q.Amount < 0 {
			return nil, bad("quote amount for %q is negative", q.Unit)
		}
	}
	distinct := map[string]struct{}{}
	for _, d := range in.Distinct {
		if !unitPattern.MatchString(d.Unit) {
			return nil, bad("distinct value unit %q is not a unit", d.Unit)
		}
		if _, dup := distinct[d.Unit]; dup {
			return nil, bad("distinct value unit %q repeats", d.Unit)
		}
		distinct[d.Unit] = struct{}{}
		if len(d.Digest) != 32 {
			return nil, bad("distinct value for %q must be a 32-byte SHA-256 digest", d.Unit)
		}
	}
	args, err := effectargs.Validate(in.EffectType, in.Target, in.Arguments)
	if err != nil {
		return nil, bad("effect.arguments: %v", err)
	}
	return args, nil
}
