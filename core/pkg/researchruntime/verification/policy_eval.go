package verification

// evalPolicy is a placeholder for future typed policy evaluation against a
// PolicyBundle loaded via policyloader. When implemented it will evaluate CEL
// rules from the bundle against the VerifyInput and return machine-readable
// reason codes for any BLOCK-action rules that fire.
func (s *Service) evalPolicy(_ *VerifyInput) []string {
	// Future: evaluate against PolicyBundle
	return nil
}
