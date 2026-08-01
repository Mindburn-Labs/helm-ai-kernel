package receipts

// NewReceiptForSession builds an unchained genesis receipt under an explicit
// session key.
//
// Use it when an operation legitimately starts its own chain — teardown, for
// example, happens after the launch has completed and its chain head is not
// persisted. Giving it a distinct session key states that separation, instead
// of leaving a second genesis inside the launch's chain where a verifier reads
// it as a fork.
func NewReceiptForSession(receiptType, sessionID, launchID, verdict string, subject map[string]any) Receipt {
	return newLinkedReceipt(receiptType, launchID, verdict, subject, "", 1, sessionID)
}
