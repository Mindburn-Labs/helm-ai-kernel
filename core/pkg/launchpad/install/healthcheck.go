package install

type HealthStatus string

const (
	HealthPassing HealthStatus = "passing"
	HealthFailing HealthStatus = "failing"
)

type HealthcheckResult struct {
	Status     HealthStatus `json:"status"`
	Message    string       `json:"message,omitempty"`
	DurationMS int64        `json:"duration_ms"`
}
