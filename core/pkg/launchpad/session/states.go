package session

func ValidState(state State) bool {
	switch state {
	case StatePlanned, StateValidated, StateEscalated, StateDenied, StateProvisioning, StateInstalling, StateStarting, StateHealthchecking, StateRunning, StateRepairRequired, StateTearingDown, StateDeleted, StateFailed:
		return true
	default:
		return false
	}
}
