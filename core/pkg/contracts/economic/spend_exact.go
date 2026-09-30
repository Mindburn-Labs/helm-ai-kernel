package economic

import (
	"errors"
	"math"
)

// NanoCentsPerCent is the exact accounting scale. Reservation ceilings are not
// provider charges. Convert only at an explicit legacy boundary.
const NanoCentsPerCent int64 = 1_000_000_000

func CentsToNanoCents(cents int64) (int64, error) {
	if cents < 0 || cents > math.MaxInt64/NanoCentsPerCent {
		return 0, errors.New("exact spend: cent conversion out of range")
	}
	return cents * NanoCentsPerCent, nil
}
