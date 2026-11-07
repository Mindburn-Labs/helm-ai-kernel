package identity

import (
	"time"
)

func cdmFixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}
