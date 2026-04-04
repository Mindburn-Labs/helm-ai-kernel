package scheduler

import (
	"fmt"
	"math/rand"
	"time"
)

// NextFireTime computes the next fire time strictly after `after` for the given schedule.
// It returns an error if the spec is for an unsupported kind or the expression is invalid.
//
// The returned time is in the schedule's configured timezone (or UTC if empty).
func NextFireTime(spec ScheduleSpec, after time.Time) (time.Time, error) {
	switch spec.Kind {
	case ScheduleCron:
		return nextCronFire(spec, after)
	case ScheduleRRULE:
		return time.Time{}, fmt.Errorf("RRULE scheduling is not yet implemented")
	default:
		return time.Time{}, fmt.Errorf("unknown schedule kind: %q", spec.Kind)
	}
}

// ApplyJitter adds a uniformly distributed random offset within [0, jitterWindowMs) milliseconds
// to fireTime. If jitterWindowMs is <= 0 the original time is returned unchanged.
func ApplyJitter(fireTime time.Time, jitterWindowMs int) time.Time {
	if jitterWindowMs <= 0 {
		return fireTime
	}
	jitterNs := rand.Int63n(int64(jitterWindowMs) * int64(time.Millisecond))
	return fireTime.Add(time.Duration(jitterNs))
}

// nextCronFire iterates forward from `after` (truncated to the next full minute) and finds
// the first (minute, hour, dom, month, dow) tuple that satisfies the parsed cron schedule.
//
// The search is bounded to 4 years (roughly 2,102,400 minutes) to prevent infinite loops
// against pathological expressions.
func nextCronFire(spec ScheduleSpec, after time.Time) (time.Time, error) {
	cs, err := ParseCron(spec.Expression)
	if err != nil {
		return time.Time{}, fmt.Errorf("nextCronFire: %w", err)
	}

	loc, err := loadLocation(spec.Timezone)
	if err != nil {
		return time.Time{}, fmt.Errorf("nextCronFire: %w", err)
	}

	// Work in the schedule's timezone.
	t := after.In(loc)
	// Advance to the start of the next minute.
	t = t.Truncate(time.Minute).Add(time.Minute)

	const maxIterations = 2_102_400 // 4 years of minutes
	for i := 0; i < maxIterations; i++ {
		// Check month first — skip whole month if no match.
		if !contains(cs.Months, int(t.Month())) {
			// Advance to the 1st of the next month, 00:00.
			t = firstOfNextMonth(t)
			continue
		}

		// Day matching: cron uses OR semantics when both dom and dow fields are
		// not wildcards; otherwise AND semantics would make many expressions useless.
		// Standard cron: if both are restricted (non-*), a day matches if dom OR dow matches.
		domWild := isWildcardField(spec, cs, "dom")
		dowWild := isWildcardField(spec, cs, "dow")

		var dayMatch bool
		switch {
		case domWild && dowWild:
			dayMatch = true
		case domWild:
			dayMatch = contains(cs.DaysOfWeek, int(t.Weekday()))
		case dowWild:
			dayMatch = contains(cs.DaysOfMonth, t.Day())
		default:
			// Both restricted — OR semantics.
			dayMatch = contains(cs.DaysOfMonth, t.Day()) || contains(cs.DaysOfWeek, int(t.Weekday()))
		}

		if !dayMatch {
			// Advance to midnight of the next day.
			t = midnightNextDay(t)
			continue
		}

		if !contains(cs.Hours, t.Hour()) {
			// Advance to the next matching hour, at :00 minutes.
			next := nextValue(cs.Hours, t.Hour())
			if next < 0 {
				// No more matching hours today; go to midnight tomorrow.
				t = midnightNextDay(t)
				continue
			}
			t = time.Date(t.Year(), t.Month(), t.Day(), next, cs.Minutes[0], 0, 0, loc)
			continue
		}

		if !contains(cs.Minutes, t.Minute()) {
			next := nextValue(cs.Minutes, t.Minute())
			if next < 0 {
				// Advance to the next matching hour.
				nextHour := nextValue(cs.Hours, t.Hour()+1)
				if nextHour < 0 {
					t = midnightNextDay(t)
				} else {
					t = time.Date(t.Year(), t.Month(), t.Day(), nextHour, cs.Minutes[0], 0, 0, loc)
				}
				continue
			}
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), next, 0, 0, loc)
			continue
		}

		// All fields match.
		return t, nil
	}

	return time.Time{}, fmt.Errorf("nextCronFire: no fire time found within search window for expression %q", spec.Expression)
}

// isWildcardField returns true when a field was derived from a pure "*" (i.e. contains
// all values in its range).  This is a heuristic used for dom/dow OR semantics.
func isWildcardField(spec ScheduleSpec, cs *CronSchedule, field string) bool {
	parts := splitCronFields(spec.Expression)
	if len(parts) != 5 {
		return false
	}
	switch field {
	case "dom":
		return parts[2] == "*"
	case "dow":
		return parts[4] == "*"
	}
	return false
}

// splitCronFields splits a cron expression into its 5 constituent fields.
func splitCronFields(expression string) []string {
	fields := []string{}
	for _, f := range splitWhitespace(expression) {
		fields = append(fields, f)
		if len(fields) == 5 {
			break
		}
	}
	return fields
}

// splitWhitespace returns whitespace-delimited tokens from s (no stdlib strings import needed).
func splitWhitespace(s string) []string {
	var tokens []string
	start := -1
	for i, ch := range s {
		isSpace := ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
		if !isSpace && start == -1 {
			start = i
		} else if isSpace && start >= 0 {
			tokens = append(tokens, s[start:i])
			start = -1
		}
	}
	if start >= 0 {
		tokens = append(tokens, s[start:])
	}
	return tokens
}

// loadLocation loads a time.Location from an IANA timezone name.
// An empty name resolves to UTC.
func loadLocation(tz string) (*time.Location, error) {
	if tz == "" {
		return time.UTC, nil
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return nil, fmt.Errorf("unknown timezone %q: %w", tz, err)
	}
	return loc, nil
}

// contains reports whether val is present in the sorted slice s.
func contains(s []int, val int) bool {
	for _, v := range s {
		if v == val {
			return true
		}
	}
	return false
}

// nextValue returns the smallest value in the sorted slice s that is >= val.
// Returns -1 if no such value exists.
func nextValue(s []int, val int) int {
	for _, v := range s {
		if v >= val {
			return v
		}
	}
	return -1
}

// midnightNextDay returns midnight of the day following t.
func midnightNextDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, t.Location())
}

// firstOfNextMonth returns midnight on the 1st of the month following t.
func firstOfNextMonth(t time.Time) time.Time {
	y, m, _ := t.Date()
	if m == time.December {
		return time.Date(y+1, time.January, 1, 0, 0, 0, 0, t.Location())
	}
	return time.Date(y, m+1, 1, 0, 0, 0, 0, t.Location())
}
