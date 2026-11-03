package executor

import ()

type invalidJSONBytes struct{}

func (invalidJSONBytes) MarshalJSON() ([]byte, error) {
	return []byte("{"), nil
}
