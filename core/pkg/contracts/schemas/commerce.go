package schemas

// Canonical Data Models for US Ecommerce
// These match the 'us-ecom' environment profile.

// CommerceOrder represents an e-commerce order.
type CommerceOrder struct {
	CanonicalID string             `json:"canonical_id"`
	ExternalID  string             `json:"external_id"`
	Source      string             `json:"source"`
	Status      string             `json:"status"`
	TotalAmount int64              `json:"total_amount_cents"`
	Currency    string             `json:"currency"`
	LineItems   []CommerceLineItem `json:"line_items"`
	Customer    CommerceCustomer   `json:"customer"`
	Metadata    map[string]string  `json:"metadata,omitempty"`
}

// CommerceLineItem represents a line item in an order.
type CommerceLineItem struct {
	SKU      string `json:"sku"`
	Quantity int    `json:"quantity"`
	Price    int64  `json:"price_cents"`
}

// CommerceCustomer represents a customer in an order.
type CommerceCustomer struct {
	Email string `json:"email"`
	ID    string `json:"id"`
}

// CommerceDispute represents a customer dispute.
type CommerceDispute struct {
	ID          string `json:"id"`
	OrderID     string `json:"order_id"`
	Reason      string `json:"reason"`
	Status      string `json:"status"` // OPEN, WON, LOST
	AmountCents int64  `json:"amount_cents"`
}

// MarketingCampaign represents a marketing campaign.
type MarketingCampaign struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	BudgetLimit int64  `json:"budget_limit_cents"`
	Status      string `json:"status"`
}

// CommerceProcess acts as the intermediate representation for the Miner.
type CommerceProcess struct {
	Name       string         `json:"name"`
	Trigger    string         `json:"trigger"` // Event Type
	Steps      []CommerceStep `json:"steps"`
	Invariants []string       `json:"invariants"`
}

// CommerceStep represents a step in a commerce process.
type CommerceStep struct {
	ActionType string `json:"action_type"`
	Condition  string `json:"condition,omitempty"` // CEL
}
