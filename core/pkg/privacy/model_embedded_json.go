package privacy

import (
	"encoding/json"
	"strings"
)

func rewriteModelResponseEmbeddedJSON(value any, restore bool) error {
	root, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	if err := rewriteModelMessageEmbeddedJSON(root, restore); err != nil {
		return err
	}
	if choices, ok := root["choices"].([]any); ok {
		for _, choiceValue := range choices {
			choice, ok := choiceValue.(map[string]any)
			if !ok {
				continue
			}
			message, ok := choice["message"].(map[string]any)
			if !ok {
				continue
			}
			if err := rewriteModelMessageEmbeddedJSON(message, restore); err != nil {
				return err
			}
		}
	}
	if candidates, ok := root["candidates"].([]any); ok {
		for _, candidateValue := range candidates {
			candidate, ok := candidateValue.(map[string]any)
			if !ok {
				continue
			}
			content, ok := candidate["content"].(map[string]any)
			if ok {
				if err := rewriteModelMessageEmbeddedJSON(content, restore); err != nil {
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
			if err := rewriteEmbeddedJSONField(output, "arguments", restore, true); err != nil {
				return err
			}
			if err := rewriteModelMessageEmbeddedJSON(output, restore); err != nil {
				return err
			}
		}
	}
	return nil
}

func rewriteModelRequestEmbeddedJSON(value any, restore bool) error {
	root, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	if err := rewriteEmbeddedJSONField(root, "input", restore, false); err != nil {
		return err
	}
	for _, field := range []string{"messages", "input", "contents"} {
		messages, ok := root[field].([]any)
		if !ok {
			continue
		}
		for _, messageValue := range messages {
			message, ok := messageValue.(map[string]any)
			if ok {
				if err := rewriteModelMessageEmbeddedJSON(message, restore); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func rewriteModelMessageEmbeddedJSON(message map[string]any, restore bool) error {
	if err := rewriteModelContentBlockEmbeddedJSON(message, restore, 0); err != nil {
		return err
	}
	if functionCall, ok := message["function_call"].(map[string]any); ok {
		if err := rewriteEmbeddedJSONField(functionCall, "arguments", restore, true); err != nil {
			return err
		}
	}
	if toolCalls, ok := message["tool_calls"].([]any); ok {
		for _, toolCallValue := range toolCalls {
			toolCall, ok := toolCallValue.(map[string]any)
			if !ok {
				continue
			}
			if function, ok := toolCall["function"].(map[string]any); ok {
				if err := rewriteEmbeddedJSONField(function, "arguments", restore, true); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func rewriteModelContentBlockEmbeddedJSON(block map[string]any, restore bool, depth int) error {
	if depth > maxProtectDepth {
		return ErrDataEgressInvalid
	}
	for _, field := range []string{"text", "content"} {
		if err := rewriteEmbeddedJSONField(block, field, restore, false); err != nil {
			return err
		}
	}
	for _, field := range []string{"content", "parts"} {
		parts, ok := block[field].([]any)
		if !ok {
			continue
		}
		for _, partValue := range parts {
			part, ok := partValue.(map[string]any)
			if !ok {
				continue
			}
			if err := rewriteModelContentBlockEmbeddedJSON(part, restore, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func rewriteEmbeddedJSONField(container map[string]any, field string, restore, required bool) error {
	value, exists := container[field]
	if !exists {
		return nil
	}
	if restore {
		wrapper, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		rawValue, marked := wrapper[modelEmbeddedJSONKey]
		if !marked {
			return nil
		}
		raw, ok := rawValue.(json.RawMessage)
		if !ok || len(wrapper) != 1 {
			return ErrDataEgressInvalid
		}
		container[field] = string(raw)
		return nil
	}
	text, ok := value.(string)
	if !ok || text == "" {
		return nil
	}
	if len(text) > maxProtectStringBytes {
		return ErrDataEgressInvalid
	}
	raw := json.RawMessage(strings.TrimSpace(text))
	decoded, err := decodeJSONValue(raw)
	if err != nil {
		if required {
			return ErrDataEgressInvalid
		}
		return nil
	}
	switch decoded.(type) {
	case map[string]any, []any:
		container[field] = map[string]any{modelEmbeddedJSONKey: raw}
	default:
		if required {
			return ErrDataEgressInvalid
		}
	}
	return nil
}
