package receipts

type TeardownReceipt struct {
	LaunchID string `json:"launch_id"`
	Status   string `json:"status"`
	Cascade  bool   `json:"cascade"`
}
