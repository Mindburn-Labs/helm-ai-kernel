package gates

import "time"

var fixedClock = func() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}
