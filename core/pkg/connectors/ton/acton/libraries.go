package acton

func IsLibraryAction(action ActionURN) bool {
	switch action {
	case ActionLibraryInfo, ActionLibraryFetch, ActionLibraryPublishTN, ActionLibraryPublishMN, ActionLibraryTopupTN, ActionLibraryTopupMN:
		return true
	default:
		return false
	}
}

func LibraryActionIsReadOnly(action ActionURN) bool {
	return action == ActionLibraryInfo || action == ActionLibraryFetch
}
