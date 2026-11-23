package privacy

import (
	"strconv"
	"strings"
)

func rewriteModelRequestSchemaKeys(value any, restore bool, names map[string]string) error {
	root, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	visit := func(schema any) error {
		return rewriteModelSchema(schema, restore, names)
	}
	if tools, ok := root["tools"].([]any); ok {
		for _, toolValue := range tools {
			tool, ok := toolValue.(map[string]any)
			if !ok {
				continue
			}
			if function, ok := tool["function"].(map[string]any); ok {
				if err := visit(function["parameters"]); err != nil {
					return err
				}
			}
			for _, field := range []string{"parameters", "input_schema"} {
				if err := visit(tool[field]); err != nil {
					return err
				}
			}
			if declarations, ok := tool["functionDeclarations"].([]any); ok {
				for _, declarationValue := range declarations {
					declaration, ok := declarationValue.(map[string]any)
					if ok {
						if err := visit(declaration["parameters"]); err != nil {
							return err
						}
					}
				}
			}
		}
	}
	if functions, ok := root["functions"].([]any); ok {
		for _, functionValue := range functions {
			function, ok := functionValue.(map[string]any)
			if ok {
				if err := visit(function["parameters"]); err != nil {
					return err
				}
			}
		}
	}
	if responseFormat, ok := root["response_format"].(map[string]any); ok {
		if jsonSchema, ok := responseFormat["json_schema"].(map[string]any); ok {
			if err := visit(jsonSchema["schema"]); err != nil {
				return err
			}
		}
	}
	if text, ok := root["text"].(map[string]any); ok {
		if format, ok := text["format"].(map[string]any); ok {
			if err := visit(format["schema"]); err != nil {
				return err
			}
		}
	}
	if generation, ok := root["generationConfig"].(map[string]any); ok {
		for _, field := range []string{"responseSchema", "response_schema"} {
			if err := visit(generation[field]); err != nil {
				return err
			}
		}
	}
	return nil
}

func rewriteModelSchema(value any, restore bool, names map[string]string) error {
	schema, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	for _, keyword := range []string{"properties", "$defs", "definitions", "patternProperties", "dependentSchemas", "dependentRequired"} {
		declarations, ok := schema[keyword].(map[string]any)
		if !ok {
			continue
		}
		if err := rewriteModelSchemaNames(declarations, restore, names); err != nil {
			return err
		}
		if keyword != "dependentRequired" {
			for _, name := range sortedKeysAny(declarations) {
				if err := rewriteModelSchema(declarations[name], restore, names); err != nil {
					return err
				}
			}
		}
	}
	for _, keyword := range []string{"items", "additionalProperties", "not", "if", "then", "else", "contains", "propertyNames"} {
		if err := rewriteModelSchema(schema[keyword], restore, names); err != nil {
			return err
		}
	}
	for _, keyword := range []string{"allOf", "anyOf", "oneOf", "prefixItems"} {
		items, ok := schema[keyword].([]any)
		if !ok {
			continue
		}
		for _, item := range items {
			if err := rewriteModelSchema(item, restore, names); err != nil {
				return err
			}
		}
	}
	return nil
}

func rewriteModelSchemaNames(declarations map[string]any, restore bool, names map[string]string) error {
	for _, name := range sortedKeysAny(declarations) {
		if restore {
			original, exists := names[name]
			if !exists {
				if strings.HasPrefix(name, modelSchemaKeyPrefix) {
					return ErrDataEgressInvalid
				}
				continue
			}
			if _, collision := declarations[original]; collision {
				return ErrDataEgressInvalid
			}
			declarations[original] = declarations[name]
			delete(declarations, name)
			delete(names, name)
			continue
		}
		if strings.HasPrefix(name, modelSchemaKeyPrefix) {
			return ErrDataEgressInvalid
		}
		if !isRestrictedKey(name) {
			continue
		}
		if schema, ok := declarations[name].(map[string]any); ok && schemaContainsExampleValue(schema) {
			return ErrDataEgressBlocked
		}
		marker := modelSchemaKeyPrefix + strconv.Itoa(len(names))
		if _, collision := declarations[marker]; collision {
			return ErrDataEgressInvalid
		}
		names[marker] = name
		declarations[marker] = declarations[name]
		delete(declarations, name)
	}
	return nil
}

func schemaContainsExampleValue(schema map[string]any) bool {
	for _, field := range []string{"default", "const", "enum", "example", "examples"} {
		if value, exists := schema[field]; exists && value != nil {
			return true
		}
	}
	for _, keyword := range []string{"properties", "$defs", "definitions", "patternProperties", "dependentSchemas"} {
		declarations, ok := schema[keyword].(map[string]any)
		if !ok {
			continue
		}
		for _, nested := range declarations {
			if child, ok := nested.(map[string]any); ok && schemaContainsExampleValue(child) {
				return true
			}
		}
	}
	for _, keyword := range []string{"items", "additionalProperties", "unevaluatedProperties", "unevaluatedItems", "not", "if", "then", "else", "contains", "propertyNames"} {
		if child, ok := schema[keyword].(map[string]any); ok && schemaContainsExampleValue(child) {
			return true
		}
	}
	for _, keyword := range []string{"allOf", "anyOf", "oneOf", "prefixItems"} {
		items, ok := schema[keyword].([]any)
		if !ok {
			continue
		}
		for _, nested := range items {
			if child, ok := nested.(map[string]any); ok && schemaContainsExampleValue(child) {
				return true
			}
		}
	}
	return false
}
