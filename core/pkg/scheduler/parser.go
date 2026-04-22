package scheduler

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrRRULENotImplemented is returned by ParseRRULE; RRULE support is reserved for a future release.
var ErrRRULENotImplemented = errors.New("RRULE parsing is not yet implemented")

// CronSchedule holds the parsed, expanded field sets of a 5-field cron expression.
// Each slice contains all matching values for that field in ascending order.
type CronSchedule struct {
	// Minutes contains the matching minute values [0, 59].
	Minutes []int
	// Hours contains the matching hour values [0, 23].
	Hours []int
	// DaysOfMonth contains the matching day-of-month values [1, 31].
	DaysOfMonth []int
	// Months contains the matching month values [1, 12].
	Months []int
	// DaysOfWeek contains the matching day-of-week values [0, 6] (0 = Sunday).
	DaysOfWeek []int
}

// fieldSpec describes the legal range and optional name aliases for a single cron field.
type fieldSpec struct {
	min     int
	max     int
	aliases map[string]int // lower-case name → numeric value
}

var (
	minuteField = fieldSpec{min: 0, max: 59, aliases: nil}
	hourField   = fieldSpec{min: 0, max: 23, aliases: nil}
	domField    = fieldSpec{min: 1, max: 31, aliases: nil}
	monthField  = fieldSpec{
		min: 1, max: 12,
		aliases: map[string]int{
			"jan": 1, "feb": 2, "mar": 3, "apr": 4,
			"may": 5, "jun": 6, "jul": 7, "aug": 8,
			"sep": 9, "oct": 10, "nov": 11, "dec": 12,
		},
	}
	dowField = fieldSpec{
		min: 0, max: 6,
		aliases: map[string]int{
			"sun": 0, "mon": 1, "tue": 2, "wed": 3,
			"thu": 4, "fri": 5, "sat": 6,
		},
	}
)

// ParseCron parses a standard 5-field cron expression and returns a CronSchedule.
//
// Supported syntax per field:
//   - Wildcard:  *
//   - Literal:   5
//   - List:      1,3,5
//   - Range:     1-5
//   - Step:      */5  or  1-5/2
//   - Named day: MON-SUN (day-of-week), JAN-DEC (month)
//
// Field order: minute  hour  day-of-month  month  day-of-week
func ParseCron(expression string) (*CronSchedule, error) {
	expression = strings.TrimSpace(expression)
	parts := strings.Fields(expression)
	if len(parts) != 5 {
		return nil, fmt.Errorf("cron expression must have exactly 5 fields, got %d: %q", len(parts), expression)
	}

	minutes, err := parseField(parts[0], minuteField)
	if err != nil {
		return nil, fmt.Errorf("minute field %q: %w", parts[0], err)
	}
	hours, err := parseField(parts[1], hourField)
	if err != nil {
		return nil, fmt.Errorf("hour field %q: %w", parts[1], err)
	}
	dom, err := parseField(parts[2], domField)
	if err != nil {
		return nil, fmt.Errorf("day-of-month field %q: %w", parts[2], err)
	}
	months, err := parseField(parts[3], monthField)
	if err != nil {
		return nil, fmt.Errorf("month field %q: %w", parts[3], err)
	}
	dow, err := parseField(parts[4], dowField)
	if err != nil {
		return nil, fmt.Errorf("day-of-week field %q: %w", parts[4], err)
	}

	return &CronSchedule{
		Minutes:     minutes,
		Hours:       hours,
		DaysOfMonth: dom,
		Months:      months,
		DaysOfWeek:  dow,
	}, nil
}

// ParseRRULE is a placeholder for future RRULE (iCalendar) support.
// It always returns ErrRRULENotImplemented.
func ParseRRULE(_ string) error {
	return ErrRRULENotImplemented
}

// parseField expands a single cron field token into a sorted, deduplicated slice of ints.
func parseField(token string, fs fieldSpec) ([]int, error) {
	set := make(map[int]struct{})

	// Comma-separated list of terms.
	terms := strings.Split(token, ",")
	for _, term := range terms {
		values, err := parseTerm(term, fs)
		if err != nil {
			return nil, err
		}
		for _, v := range values {
			set[v] = struct{}{}
		}
	}

	result := make([]int, 0, len(set))
	for v := range set {
		result = append(result, v)
	}
	sortInts(result)
	return result, nil
}

// parseTerm handles a single cron field term: wildcard, step, range, or literal.
func parseTerm(term string, fs fieldSpec) ([]int, error) {
	// Step: expr/step
	var baseExpr string
	var step int = 1

	if idx := strings.Index(term, "/"); idx >= 0 {
		stepStr := term[idx+1:]
		baseExpr = term[:idx]
		var err error
		step, err = strconv.Atoi(stepStr)
		if err != nil || step <= 0 {
			return nil, fmt.Errorf("invalid step value %q", stepStr)
		}
	} else {
		baseExpr = term
	}

	// Determine base range.
	var rangeMin, rangeMax int

	switch {
	case baseExpr == "*":
		rangeMin = fs.min
		rangeMax = fs.max
	case strings.Contains(baseExpr, "-"):
		parts := strings.SplitN(baseExpr, "-", 2)
		var err error
		rangeMin, err = resolveValue(parts[0], fs)
		if err != nil {
			return nil, fmt.Errorf("invalid range start %q: %w", parts[0], err)
		}
		rangeMax, err = resolveValue(parts[1], fs)
		if err != nil {
			return nil, fmt.Errorf("invalid range end %q: %w", parts[1], err)
		}
		if rangeMin > rangeMax {
			return nil, fmt.Errorf("range start %d > end %d", rangeMin, rangeMax)
		}
	default:
		// Literal value (step remains 1, so only this single value is produced).
		v, err := resolveValue(baseExpr, fs)
		if err != nil {
			return nil, err
		}
		if step != 1 {
			// e.g. "5/2" means: starting at 5, every 2nd value up to max.
			rangeMin = v
			rangeMax = fs.max
		} else {
			return []int{v}, nil
		}
	}

	// Validate bounds.
	if rangeMin < fs.min || rangeMax > fs.max {
		return nil, fmt.Errorf("value out of range [%d, %d]", fs.min, fs.max)
	}

	// Expand.
	var result []int
	for v := rangeMin; v <= rangeMax; v += step {
		result = append(result, v)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("empty expansion for term %q", term)
	}
	return result, nil
}

// resolveValue converts a cron value token (number or named alias) to an int.
func resolveValue(s string, fs fieldSpec) (int, error) {
	lower := strings.ToLower(s)
	if fs.aliases != nil {
		if v, ok := fs.aliases[lower]; ok {
			return v, nil
		}
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("unrecognized value %q", s)
	}
	if v < fs.min || v > fs.max {
		return 0, fmt.Errorf("value %d is out of range [%d, %d]", v, fs.min, fs.max)
	}
	return v, nil
}

// sortInts sorts a slice of ints in-place using a simple insertion sort.
// The slices are small (at most 60 elements), so insertion sort is adequate.
func sortInts(s []int) {
	for i := 1; i < len(s); i++ {
		key := s[i]
		j := i - 1
		for j >= 0 && s[j] > key {
			s[j+1] = s[j]
			j--
		}
		s[j+1] = key
	}
}
