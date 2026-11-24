package executor

type invalidJSONBytes struct{}

func (invalidJSONBytes) MarshalJSON() ([]byte, error) {
	return []byte("{"), nil
}
