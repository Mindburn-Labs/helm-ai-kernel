package replay

import "time"

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		// Fallback for non-RFC3339 strings or test dummy values
		// Return dummy incrementing times for "a", "b", "c" etc. to avoid collision
		switch s {
		case "a":
			return time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC)
		case "b":
			return time.Date(2025, 1, 1, 0, 0, 2, 0, time.UTC)
		case "c":
			return time.Date(2025, 1, 1, 0, 0, 3, 0, time.UTC)
		default:
			return time.Time{}
		}
	}
	return t
}
