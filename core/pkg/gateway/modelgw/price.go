package modelgw

import (
	"errors"
	"math"
)

const microsPerMillion int64 = 1_000_000

// errOverflow: a price computation that does not fit an int64 is refused,
// never wrapped (ARITHMETIC_OVERFLOW at the gateway's edge).
var errOverflow = errors.New("the price of the call overflows")

// Usage is what a provider reported for one call, normalized: InputTokens are
// the tokens billed at the input price (cached and cache-written tokens are
// counted separately), OutputTokens include reasoning and thinking tokens.
type Usage struct {
	InputTokens        int64
	CacheReadTokens    int64
	CacheWrite5mTokens int64
	CacheWrite1hTokens int64
	OutputTokens       int64
}

func (u Usage) valid() bool {
	return u.InputTokens >= 0 && u.CacheReadTokens >= 0 && u.CacheWrite5mTokens >= 0 && u.CacheWrite1hTokens >= 0 && u.OutputTokens >= 0
}

// Quote prices an assumed input-token bound and the whole maximum output in
// usd_micros. Input uses the dearer of the input and cache-read prices; a
// cache-writing request also includes both cache-write prices in that maximum.
// The sum is rounded up once, to whole micros. This arithmetic bound does not
// establish that request bytes bound provider tokens (for example, for remote
// media or retained history), or that a provider enforces its output cap.
func (r *Route) Quote(inputBytes, maxOutputTokens int64, mayWriteCache bool) (int64, error) {
	if inputBytes < 0 || maxOutputTokens < 0 {
		return 0, errors.New("a call cannot have a negative size")
	}
	rates := r.rates()
	in := max(rates.input, rates.cacheRead)
	if mayWriteCache {
		in = max(in, rates.cacheWrite5m, rates.cacheWrite1h)
	}
	a, err := mulChecked(inputBytes, in)
	if err != nil {
		return 0, err
	}
	b, err := mulChecked(maxOutputTokens, rates.output)
	if err != nil {
		return 0, err
	}
	total, err := addChecked(a, b)
	if err != nil {
		return 0, err
	}
	return ceilMicros(total)
}

// Cost prices a provider-reported usage at the route's tariff, in usd_micros,
// rounded up once. The tariff is the configured price, not the provider's
// invoice.
func (r *Route) Cost(u Usage) (int64, error) {
	if !u.valid() {
		return 0, errors.New("a usage report cannot hold a negative count")
	}
	rates := r.rates()
	var total int64
	for _, term := range []struct{ tokens, rate int64 }{
		{u.InputTokens, rates.input}, {u.CacheReadTokens, rates.cacheRead},
		{u.CacheWrite5mTokens, rates.cacheWrite5m}, {u.CacheWrite1hTokens, rates.cacheWrite1h},
		{u.OutputTokens, rates.output},
	} {
		part, err := mulChecked(term.tokens, term.rate)
		if err != nil {
			return 0, err
		}
		if total, err = addChecked(total, part); err != nil {
			return 0, err
		}
	}
	return ceilMicros(total)
}

type rates struct{ input, output, cacheRead, cacheWrite5m, cacheWrite1h int64 }

// rates is the route's tariff with the optional cache prices defaulted to the
// input price. Validation guarantees Input and Output are set.
func (r *Route) rates() rates {
	p := r.Price
	out := rates{input: *p.Input, output: *p.Output}
	out.cacheRead, out.cacheWrite5m, out.cacheWrite1h = out.input, out.input, out.input
	if p.CacheRead != nil {
		out.cacheRead = *p.CacheRead
	}
	if p.CacheWrite5m != nil {
		out.cacheWrite5m = *p.CacheWrite5m
	}
	if p.CacheWrite1h != nil {
		out.cacheWrite1h = *p.CacheWrite1h
	}
	return out
}

func mulChecked(a, b int64) (int64, error) {
	if a < 0 || b < 0 {
		return 0, errors.New("a price term cannot be negative")
	}
	if a != 0 && b > math.MaxInt64/a {
		return 0, errOverflow
	}
	return a * b, nil
}

func addChecked(a, b int64) (int64, error) {
	if a > math.MaxInt64-b {
		return 0, errOverflow
	}
	return a + b, nil
}

// ceilMicros converts a sum of token-times-rate terms (usd_micros times
// tokens per million) to usd_micros, rounding up.
func ceilMicros(total int64) (int64, error) {
	q, r := total/microsPerMillion, total%microsPerMillion
	if r == 0 {
		return q, nil
	}
	return addChecked(q, 1)
}
