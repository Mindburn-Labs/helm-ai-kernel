package polymarket

// ConnectorID is the unique identifier for the Polymarket connector.
const ConnectorID = "polymarket"

// Tool names for Polymarket operations.
const (
	ToolPlaceOrder  = "polymarket.place_order"
	ToolCancelOrder = "polymarket.cancel_order"
	ToolCancelAll   = "polymarket.cancel_all"
)

// toolDataClassMap maps tool names to their required data classes.
var toolDataClassMap = map[string]string{
	ToolPlaceOrder:  "trading:prediction_market",
	ToolCancelOrder: "trading:order",
	ToolCancelAll:   "trading:position",
}

// AllowedDataClasses returns the data classes this connector handles.
func AllowedDataClasses() []string {
	return []string{"trading:prediction_market", "trading:order", "trading:position"}
}
