package governance

import (
	"time"
)

func immediateAfter(ts time.Time) func(time.Duration) <-chan time.Time {
	return func(time.Duration) <-chan time.Time {
		ch := make(chan time.Time, 1)
		ch <- ts
		return ch
	}
}
