package actioninbox

// ApprovalRouter determines the approval route based on risk classification.
type ApprovalRouter struct{}

// NewApprovalRouter creates a new ApprovalRouter.
func NewApprovalRouter() *ApprovalRouter {
	return &ApprovalRouter{}
}

// RouteForRiskClass returns the appropriate approval route for the given
// risk class. Lower risk items are auto-approved; higher risk items
// require progressively more human oversight.
//
//   - R0, R1 -> auto (no human needed)
//   - R2     -> single_human
//   - R3+    -> dual_control
func (r *ApprovalRouter) RouteForRiskClass(riskClass string) ApprovalRoute {
	switch riskClass {
	case "R0", "R1":
		return ApprovalRoute{
			RouteType:   "auto",
			TimeoutSecs: 0,
			OnTimeout:   "deny",
		}
	case "R2":
		return ApprovalRoute{
			RouteType:   "single_human",
			Quorum:      1,
			TimeoutSecs: 3600, // 1 hour
			OnTimeout:   "deny",
		}
	default:
		// R3 and above require dual control
		return ApprovalRoute{
			RouteType:   "dual_control",
			Quorum:      2,
			TimeoutSecs: 7200, // 2 hours
			OnTimeout:   "escalate",
		}
	}
}
