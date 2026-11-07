package governance

import (
	"errors"
)

// MockFactOracle for testing
type MockFactOracle struct {
	Facts map[string]interface{}
}

func (m *MockFactOracle) GetFact(subject, predicate string) (interface{}, error) {
	key := subject + "|" + predicate
	if val, ok := m.Facts[key]; ok {
		return val, nil
	}
	return nil, errors.New("fact not found")
}
