package pack_test

import (
	"time"
)

func fixedClock() time.Time {
	return time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)
}
