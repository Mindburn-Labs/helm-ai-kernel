package privacy

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

func rewriteModelResponseLogprobTokenKeys(p *protector, value any, restore bool, originalTokens *[]string) error {
	root, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	if choices, ok := root["choices"].([]any); ok {
		for _, choiceValue := range choices {
			choice, ok := choiceValue.(map[string]any)
			if !ok {
				continue
			}
			logprobs, ok := choice["logprobs"].(map[string]any)
			if !ok {
				continue
			}
			for _, field := range []string{"content", "refusal"} {
				if err := rewriteLogprobEntries(p, logprobs[field], restore, originalTokens); err != nil {
					return err
				}
			}
		}
	}
	if outputs, ok := root["output"].([]any); ok {
		for _, outputValue := range outputs {
			output, ok := outputValue.(map[string]any)
			if !ok {
				continue
			}
			contents, ok := output["content"].([]any)
			if !ok {
				continue
			}
			for _, contentValue := range contents {
				content, ok := contentValue.(map[string]any)
				if !ok {
					continue
				}
				if err := rewriteLogprobEntries(p, content["logprobs"], restore, originalTokens); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func rewriteLogprobEntries(p *protector, value any, restore bool, originalTokens *[]string) error {
	entries, ok := value.([]any)
	if !ok {
		return nil
	}
	if !restore {
		if err := p.validateLogprobEntryStreams(entries); err != nil {
			return err
		}
	}
	for _, entry := range entries {
		if err := rewriteLogprobTokenEntry(p, entry, restore, originalTokens); err != nil {
			return err
		}
	}
	return nil
}

func (p *protector) validateLogprobEntryStreams(entries []any) error {
	var tokenStream strings.Builder
	var byteStream []byte
	tokenEntries := 0
	byteEntries := 0
	flushTokens := func() error {
		var err error
		if tokenEntries > 1 {
			err = p.validateLogprobStreamText(tokenStream.String())
		}
		tokenStream.Reset()
		tokenEntries = 0
		return err
	}
	flushBytes := func() error {
		var err error
		if byteEntries > 1 {
			err = p.validateLogprobByteStream(byteStream)
		}
		byteStream = byteStream[:0]
		byteEntries = 0
		return err
	}
	for _, value := range entries {
		entry, ok := value.(map[string]any)
		if !ok {
			if err := flushTokens(); err != nil {
				return err
			}
			if err := flushBytes(); err != nil {
				return err
			}
			continue
		}
		token, ok := entry["token"].(string)
		if !ok {
			if err := flushTokens(); err != nil {
				return err
			}
			if err := flushBytes(); err != nil {
				return err
			}
			continue
		}
		clean, err := p.logprobTextClean(token)
		if err != nil {
			return err
		}
		if !clean {
			if err := flushTokens(); err != nil {
				return err
			}
			if err := flushBytes(); err != nil {
				return err
			}
			continue
		}
		if tokenStream.Len() > maxProtectStringBytes-len(token) {
			return ErrDataEgressInvalid
		}
		tokenStream.WriteString(token)
		tokenEntries++
		rawValue, present := entry["bytes"]
		if !present || rawValue == nil {
			if err := flushBytes(); err != nil {
				return err
			}
			continue
		}
		raw, err := decodeLogprobBytes(rawValue)
		if err != nil {
			return err
		}
		if len(byteStream) > maxProtectStringBytes-len(raw) {
			return ErrDataEgressInvalid
		}
		byteStream = append(byteStream, raw...)
		byteEntries++
	}
	if err := flushTokens(); err != nil {
		return err
	}
	return flushBytes()
}

func (p *protector) validateLogprobStreamText(value string) error {
	clean, err := p.logprobTextClean(value)
	if err != nil {
		return err
	}
	if !clean {
		return ErrDataEgressBlocked
	}
	return nil
}

func (p *protector) logprobTextClean(value string) (bool, error) {
	if value == "" {
		return true, nil
	}
	if err := p.ctx.Err(); err != nil {
		return false, ErrDataEgressBlocked
	}
	if !utf8.ValidString(value) || len(value) > maxProtectStringBytes {
		return false, ErrDataEgressInvalid
	}
	protected, _, err := sanitizeText(value, p.manager)
	if err != nil {
		return false, err
	}
	return protected == value, nil
}

func (p *protector) validateLogprobByteStream(raw []byte) error {
	if len(raw) == 0 {
		return nil
	}
	if utf8.Valid(raw) {
		return p.validateLogprobStreamText(string(raw))
	}
	validPrefix := 0
	for validPrefix < len(raw) {
		r, size := utf8.DecodeRune(raw[validPrefix:])
		if r == utf8.RuneError && size == 1 {
			break
		}
		validPrefix += size
	}
	if validPrefix > 0 {
		if err := p.validateLogprobStreamText(string(raw[:validPrefix])); err != nil {
			return err
		}
	}
	fragment := raw[validPrefix:]
	if len(fragment) == 0 || len(fragment) >= utf8.UTFMax {
		return ErrDataEgressInvalid
	}
	if utf8.RuneStart(fragment[0]) && !utf8.FullRune(fragment) {
		return nil
	}
	if validPrefix == 0 {
		for _, item := range fragment {
			if item&0xc0 != 0x80 {
				return ErrDataEgressInvalid
			}
		}
		return nil
	}
	return ErrDataEgressInvalid
}

func rewriteLogprobTokenEntry(p *protector, value any, restore bool, originalTokens *[]string) error {
	entry, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	from, to := "token", modelLogprobTokenKey
	if restore {
		from, to = to, from
	} else if _, reserved := entry[to]; reserved {
		return ErrDataEgressInvalid
	}
	tokenValue, exists := entry[from]
	if !exists {
		if rawBytes, present := entry["bytes"]; present && rawBytes != nil {
			return ErrDataEgressInvalid
		}
	}
	if exists {
		if !restore {
			token, ok := tokenValue.(string)
			if !ok {
				return ErrDataEgressInvalid
			}
			if rawBytes, present := entry["bytes"]; present && rawBytes != nil {
				if err := p.validateLogprobBytes(rawBytes, token); err != nil {
					return err
				}
			}
			*originalTokens = append(*originalTokens, token)
		}
		if _, collision := entry[to]; collision {
			return ErrDataEgressInvalid
		}
		entry[to] = tokenValue
		delete(entry, from)
		if restore {
			token, ok := tokenValue.(string)
			if !ok || len(*originalTokens) == 0 {
				return ErrDataEgressInvalid
			}
			originalToken := (*originalTokens)[0]
			*originalTokens = (*originalTokens)[1:]
			if rawBytes, present := entry["bytes"]; present && rawBytes != nil && token != originalToken {
				encoded := []byte(token)
				byteValues := make([]int, len(encoded))
				for index, item := range encoded {
					byteValues[index] = int(item)
				}
				entry["bytes"] = byteValues
			}
		}
	}
	if top, ok := entry["top_logprobs"].([]any); ok {
		for _, candidate := range top {
			if err := rewriteLogprobTokenEntry(p, candidate, restore, originalTokens); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *protector) validateLogprobBytes(value any, token string) error {
	raw, err := decodeLogprobBytes(value)
	if err != nil {
		return err
	}
	if utf8.Valid(raw) {
		if string(raw) == token {
			return nil
		}
		return p.validateLogprobStreamText(string(raw))
	}
	return p.validateLogprobByteStream(raw)
}

func decodeLogprobBytes(value any) ([]byte, error) {
	items, ok := value.([]any)
	if !ok {
		return nil, ErrDataEgressInvalid
	}
	raw := make([]byte, len(items))
	for index, item := range items {
		digits := exactNumericDigits(item)
		parsed, err := strconv.ParseUint(digits, 10, 8)
		if digits == "" || err != nil {
			return nil, ErrDataEgressInvalid
		}
		raw[index] = byte(parsed)
	}
	return raw, nil
}
